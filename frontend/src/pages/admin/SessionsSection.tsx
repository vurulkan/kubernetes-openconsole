import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react';
import { Alert, Badge, Button, Toggle } from '../../components/ui';
import { Column, DataTable, IconButton } from '../../components/DataTable';
import { confirm } from '../../components/ConfirmDialog';
import {
  listSessions,
  revokeAllSessionsForUser,
  revokeSession,
  SessionRow,
} from '../../services/api';
import { ageShort } from '../../utils/age';

type Props = {
  // Who is viewing the page — so we can mark the current session row.
  currentUserId: number;
};

export const SessionsSection: React.FC<Props> = ({ currentUserId }) => {
  const [rows, setRows] = useState<SessionRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeOnly, setActiveOnly] = useState(true);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { items } = await listSessions(activeOnly);
      setRows(items ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load sessions');
    } finally {
      setLoading(false);
    }
  }, [activeOnly]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleRevoke = async (row: SessionRow) => {
    const ok = await confirm({
      title: 'Revoke session?',
      message: `This immediately signs ${row.username || 'this user'} out of the browser that holds this token. They will need to log in again.`,
      confirmText: 'Revoke',
      variant: 'danger',
    });
    if (!ok) return;
    try {
      await revokeSession(row.id);
      setNotice(`Session ${row.id} revoked.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke');
    }
  };

  const handleRevokeAll = async (userId: number, username: string) => {
    const ok = await confirm({
      title: 'Revoke every session for this user?',
      message: `All active sessions for ${username} will be killed, including any tabs this user has open right now.`,
      confirmText: 'Revoke all',
      variant: 'danger',
    });
    if (!ok) return;
    try {
      await revokeAllSessionsForUser(userId);
      setNotice(`All active sessions for ${username} revoked.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke');
    }
  };

  const columns: Column<SessionRow>[] = [
    {
      key: 'user',
      header: 'User',
      cell: (row) => (
        <div className="flex items-center gap-1.5">
          <span className="font-mono text-[13px] font-medium text-slate-900 dark:text-slate-100">
            {row.username || `user#${row.userId}`}
          </span>
          {row.userId === currentUserId && (
            <Badge variant="info" className="h-5 px-1.5 text-[10px]">this is you</Badge>
          )}
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      align: 'center',
      cell: (row) => {
        if (row.revokedAt) return <Badge variant="warning">Revoked</Badge>;
        if (new Date(row.expiresAt).getTime() < Date.now())
          return <Badge variant="default">Expired</Badge>;
        return <Badge variant="success">Active</Badge>;
      },
    },
    {
      key: 'ip',
      header: 'IP / UA',
      cell: (row) => (
        <div className="flex flex-col text-[11px] leading-tight">
          <span className="font-mono text-slate-700 dark:text-slate-200">{row.ip || '—'}</span>
          <span className="truncate text-slate-500 dark:text-slate-400" title={row.userAgent}>
            {shortenUA(row.userAgent)}
          </span>
        </div>
      ),
    },
    {
      key: 'issued',
      header: 'Issued',
      align: 'right',
      cell: (row) => <TimeCell iso={row.issuedAt} />,
    },
    {
      key: 'lastused',
      header: 'Last used',
      align: 'right',
      cell: (row) => <TimeCell iso={row.lastUsedAt} />,
    },
    {
      key: 'expires',
      header: 'Expires',
      align: 'right',
      cell: (row) => <TimeCell iso={row.expiresAt} />,
    },
    {
      key: 'actions',
      header: '',
      align: 'right',
      width: '96px',
      cell: (row) => {
        const live = !row.revokedAt && new Date(row.expiresAt).getTime() >= Date.now();
        if (!live)
          return <span className="text-xs text-slate-300 dark:text-slate-600">—</span>;
        return (
          <div className="flex justify-end gap-1">
            <IconButton
              label="Revoke this session"
              variant="danger"
              onClick={() => handleRevoke(row)}
            >
              <Trash2 size={14} />
            </IconButton>
            <IconButton
              label={`Revoke every session for ${row.username || 'this user'}`}
              variant="danger"
              onClick={() => handleRevokeAll(row.userId, row.username || `user#${row.userId}`)}
            >
              <ShieldAlert size={14} />
            </IconButton>
          </div>
        );
      },
    },
  ];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Toggle
            checked={activeOnly}
            onChange={setActiveOnly}
            label="Only active sessions"
          />
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {rows.length} shown
          </span>
        </div>
        <Button variant="outline" size="sm" onClick={refresh} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          Refresh
        </Button>
      </div>

      {error && (
        <Alert severity="error">
          <AlertTriangle size={14} className="mr-1 inline" />
          {error}
        </Alert>
      )}
      {notice && <Alert severity="success">{notice}</Alert>}

      <DataTable
        rows={rows}
        columns={columns}
        rowKey={(r) => r.id}
        emptyMessage={activeOnly ? 'No active sessions.' : 'No sessions on file.'}
      />
    </div>
  );
};

const TimeCell: React.FC<{ iso: string }> = ({ iso }) => {
  if (!iso) return <span className="text-xs text-slate-400 dark:text-slate-500">—</span>;
  return (
    <span className="font-mono text-[11px] text-slate-600 dark:text-slate-300" title={iso}>
      {ageShort(iso)}
    </span>
  );
};

// Browser UAs are long and the full string hurts the layout. Keep the first
// recognisable product token so an operator can still tell Chrome from
// kubectl-proxy at a glance.
function shortenUA(ua: string): string {
  if (!ua) return '—';
  const match = ua.match(/(Chrome|Firefox|Safari|Edg|curl|Go-http-client|kubectl|Postman)[\/\s][\d.]*/i);
  return match ? match[0] : ua.slice(0, 40);
}

export default SessionsSection;
