// Package backup keeps copies of the SQLite database in a directory: on a
// schedule, on demand (Admin → Backups) and before an upgrade changes the
// schema (db.OpenWithBackup). A copy is a complete database: it holds every
// stored credential, and without an external encryption key also the key
// that decrypts them.
package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"k8s-dashboard/backend/internal/db"
)

// Info is one copy.
type Info struct {
	Name      string    `json:"name"`
	SizeBytes int64     `json:"sizeBytes"`
	CreatedAt time.Time `json:"createdAt"`
}

// ErrNotFound: no copy of that name.
var ErrNotFound = errors.New("backup not found")

var nameRe = regexp.MustCompile(`^app-\d{8}-\d{6}(-[a-z-]+)?\.db$`)

// Manager makes, lists, opens and prunes copies.
type Manager struct {
	db   *db.DB
	dir  string
	keep int
	mu   sync.Mutex // one copy at a time
}

func New(d *db.DB, dir string, keep int) *Manager {
	return &Manager{db: d, dir: dir, keep: keep}
}

func (m *Manager) Dir() string { return m.dir }
func (m *Manager) Keep() int   { return m.keep }

// Create writes a new copy (tag: "" for a scheduled one, "manual", …) and
// deletes the oldest beyond Keep.
func (m *Manager) Create(ctx context.Context, tag string) (Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return Info{}, fmt.Errorf("create backup dir: %w", err)
	}
	name := db.BackupName(time.Now(), tag)
	path := filepath.Join(m.dir, name)
	if _, err := os.Stat(path); err == nil {
		return Info{}, errors.New("a backup was made this second; try again")
	}
	tmp := path + ".tmp"
	os.Remove(tmp)
	if err := m.db.BackupInto(ctx, tmp); err != nil {
		return Info{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return Info{}, err
	}
	m.prune()
	st, err := os.Stat(path)
	if err != nil {
		return Info{}, err
	}
	return Info{Name: name, SizeBytes: st.Size(), CreatedAt: st.ModTime().UTC()}, nil
}

// List returns the copies, newest first.
func (m *Manager) List() ([]Info, error) {
	entries, err := os.ReadDir(m.dir)
	if errors.Is(err, os.ErrNotExist) {
		return []Info{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Info{}
	for _, e := range entries {
		if e.IsDir() || !nameRe.MatchString(e.Name()) {
			continue
		}
		st, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Info{Name: e.Name(), SizeBytes: st.Size(), CreatedAt: st.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Open opens a copy for download.
func (m *Manager) Open(name string) (*os.File, Info, error) {
	if !nameRe.MatchString(name) {
		return nil, Info{}, ErrNotFound
	}
	f, err := os.Open(filepath.Join(m.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, Info{}, ErrNotFound
	}
	if err != nil {
		return nil, Info{}, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, Info{}, err
	}
	return f, Info{Name: name, SizeBytes: st.Size(), CreatedAt: st.ModTime().UTC()}, nil
}

func (m *Manager) prune() {
	list, err := m.List()
	if err != nil {
		return
	}
	for _, b := range list[min(len(list), m.keep):] {
		if err := os.Remove(filepath.Join(m.dir, b.Name)); err != nil {
			slog.Warn("backup prune failed", slog.String("file", b.Name), slog.Any("error", err))
		}
	}
}

// Run makes a copy every interval (0 = never), counted from the newest copy,
// so restarts don't skip or repeat one. onDone reports each scheduled copy.
func (m *Manager) Run(ctx context.Context, interval time.Duration, onDone func(Info, error)) {
	if interval <= 0 {
		return
	}
	go func() {
		for {
			wait := interval
			if list, err := m.List(); err == nil && len(list) > 0 {
				wait = time.Until(list[0].CreatedAt.Add(interval))
			}
			if wait > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
			info, err := m.Create(ctx, "")
			if onDone != nil {
				onDone(info, err)
			}
			if err != nil {
				slog.Error("scheduled backup failed", slog.Any("error", err))
				// Don't retry in a tight loop; try again in an hour.
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Hour):
				}
			}
		}
	}()
}
