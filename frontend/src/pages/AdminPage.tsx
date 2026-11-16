import React, { useEffect, useState } from 'react';
import Layout from '../components/Layout';
import { Alert } from '../components/ui';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useScopedShortcuts } from '../hooks/useScopedShortcuts';
import { User, getFeatures } from '../services/api';
import { SectionCard } from './admin/SectionCard';
import { UsersTab } from './admin/UsersTab';
import { GroupsTab } from './admin/GroupsTab';
import { RolesTab } from './admin/RolesTab';
import { LdapSection, AzureAdSection } from './admin/IdentitySection';
import { SessionSettingsSection } from './admin/SessionSettingsSection';
import { ClustersSection } from './admin/ClustersSection';
import { CustomizationSection } from './admin/CustomizationSection';
import { AuditSection, emptyAuditFilters, type AuditFilters } from './admin/AuditSection';
import { SessionsSection } from './admin/SessionsSection';
import { ApiKeysSection } from './admin/ApiKeysSection';
import { RecordingSettingsPanel, RecordingsSection } from './admin/RecordingsSection';
import { BackupsSection } from './admin/BackupsSection';
import { useDirectory, type DirectoryKind } from './admin/useDirectory';
import {
  Boxes,
  Clock,
  FileText,
  Image as ImageIcon,
  KeyRound,
  Layers,
  Settings,
  ShieldCheck,
  UserPlus,
  Users as UsersIcon,
  Video,
  DatabaseBackup,
} from 'lucide-react';

// ─── Tab definitions ──────────────────────────────────────────────────────────

const ADMIN_TABS: Array<{
  value: string;
  icon: React.ComponentType<{ size?: number | string; className?: string }>;
}> = [
  { value: 'users', icon: UsersIcon },
  { value: 'groups', icon: Layers },
  { value: 'roles', icon: ShieldCheck },
  { value: 'ldap', icon: UserPlus },
  { value: 'azure-ad', icon: KeyRound },
  { value: 'session', icon: Clock },
  { value: 'clusters', icon: Boxes },
  { value: 'customization', icon: ImageIcon },
  { value: 'audit', icon: FileText },
  { value: 'sessions', icon: KeyRound },
  { value: 'api-keys', icon: KeyRound },
  { value: 'recordings', icon: Video },
  { value: 'backups', icon: DatabaseBackup },
];

// Map tab slugs to admin.tabs.* i18n keys; a few older slugs don't line up
// 1:1 so a tiny lookup keeps the dictionary tidy.
const TAB_I18N_KEY: Record<string, string> = {
  users: 'users', groups: 'groups', roles: 'roles',
  ldap: 'ldap', 'azure-ad': 'azure', session: 'session',
  clusters: 'clusters', customization: 'customization',
  audit: 'audit', sessions: 'sessions', recordings: 'recordings', 'api-keys': 'apiKeys',
  backups: 'backups',
};

const USERS: DirectoryKind[] = ['users'];

// API keys: the owner filter also offers users without a key.
const ApiKeysTab: React.FC<{ onError: (msg: string | null) => void }> = ({ onError }) => {
  const { users } = useDirectory(USERS, onError);
  return <ApiKeysSection users={users} />;
};

// ─── AdminPage ────────────────────────────────────────────────────────────────
//
// The admin shell: the tab list, the page header and error, and the state
// that outlives a tab switch (list filters, audit filters, users just added).
// Each tab's section loads what it shows when it opens.

const AdminPage: React.FC<{ user: User }> = ({ user }) => {
  const navigate = useNavigate();
  const { t: tr } = useTranslation();
  const [tab, setTab] = useState(() => localStorage.getItem('adminActiveTab') || 'users');
  const [error, setError] = useState<string | null>(null);
  const [apiKeysOn, setApiKeysOn] = useState(true);
  const [usersFilter, setUsersFilter] = useState('');
  const [groupsFilter, setGroupsFilter] = useState('');
  const [rolesFilter, setRolesFilter] = useState('');
  const [auditFilters, setAuditFilters] = useState<AuditFilters>(emptyAuditFilters);
  // Users just added (created or imported): listed first and highlighted
  // for a while so the admin sees where they landed.
  const [newUsernames, setNewUsernames] = useState<string[]>([]);

  // Admin page shortcuts: [ / ] cycle sub-sections (physical key — works on
  // Turkish Q where the same keys produce ğ / ü).
  useScopedShortcuts(
    [
      {
        code: 'BracketLeft',
        handler: () => {
          const idx = ADMIN_TABS.findIndex((t) => t.value === tab);
          const next = ADMIN_TABS[(idx - 1 + ADMIN_TABS.length) % ADMIN_TABS.length];
          setTab(next.value);
        },
      },
      {
        code: 'BracketRight',
        handler: () => {
          const idx = ADMIN_TABS.findIndex((t) => t.value === tab);
          const next = ADMIN_TABS[(idx + 1) % ADMIN_TABS.length];
          setTab(next.value);
        },
      },
    ],
    true
  );

  useEffect(() => {
    void getFeatures().then((f) => setApiKeysOn(f.api_keys !== false));
  }, []);

  useEffect(() => {
    if (newUsernames.length === 0) return;
    const timer = window.setTimeout(() => setNewUsernames([]), 15000);
    return () => window.clearTimeout(timer);
  }, [newUsernames]);

  useEffect(() => {
    if (!user.isAdmin) navigate('/');
  }, [user, navigate]);

  useEffect(() => {
    localStorage.setItem('adminActiveTab', tab);
  }, [tab]);

  return (
    <Layout
      user={user}
      panelTitle={tr('nav.admin')}
      panel={
        <nav aria-label={tr('nav.admin')} className="flex flex-col gap-0.5 p-2">
          {ADMIN_TABS.filter((entry) => apiKeysOn || entry.value !== 'api-keys').map((entry) => {
            const Icon = entry.icon;
            const active = tab === entry.value;
            const label = tr(`admin.tabs.${TAB_I18N_KEY[entry.value] ?? entry.value}`);
            return (
              <button
                key={entry.value}
                onClick={() => setTab(entry.value)}
                className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm transition-colors ${
                  active
                    ? 'bg-brand-50 dark:bg-brand-500/15 font-medium text-brand-700 dark:text-brand-200 ring-1 ring-inset ring-brand-200 dark:ring-brand-500/30'
                    : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 dark:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100 dark:text-slate-100'
                }`}
              >
                <Icon
                  size={15}
                  className={active ? 'text-brand-600 dark:text-brand-300' : 'text-slate-500 dark:text-slate-400'}
                />
                {label}
              </button>
            );
          })}
        </nav>
      }
    >
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500 dark:text-slate-400">
            <Settings size={14} className="text-brand-600 dark:text-brand-300" />
            <span className="uppercase tracking-wider">{tr("common.administration")}</span>
          </div>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">
            {(() => {
              const entry = ADMIN_TABS.find((t) => t.value === tab);
              if (!entry) return tr('nav.admin');
              return tr(`admin.tabs.${TAB_I18N_KEY[entry.value] ?? entry.value}`);
            })()}
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {tr('admin.cards.subtitle')}
          </p>
        </div>
      </div>

      {error && (
        <Alert severity="error" className="mt-4">
          {error}
        </Alert>
      )}

      <div className="card-surface mt-6 overflow-hidden">
        <div className="p-5">
          {tab === 'users' && (
            <UsersTab
              filter={usersFilter}
              onFilter={setUsersFilter}
              newUsernames={newUsernames}
              onUsersAdded={setNewUsernames}
              apiKeysOn={apiKeysOn}
              onError={setError}
            />
          )}

          {tab === 'groups' && <GroupsTab filter={groupsFilter} onFilter={setGroupsFilter} onError={setError} />}

          {tab === 'roles' && <RolesTab filter={rolesFilter} onFilter={setRolesFilter} onError={setError} />}

          {tab === 'ldap' && <LdapSection onUsersAdded={setNewUsernames} onError={setError} />}

          {tab === 'azure-ad' && <AzureAdSection />}

          {tab === 'session' && <SessionSettingsSection apiKeysOn={apiKeysOn} />}

          {tab === 'clusters' && <ClustersSection />}

          {tab === 'customization' && <CustomizationSection />}

          {tab === 'audit' && (
            <SectionCard title={tr('admin.sections.audit')}>
              <AuditSection filters={auditFilters} onChange={setAuditFilters} />
            </SectionCard>
          )}

          {tab === 'api-keys' && (
            <SectionCard title={tr('admin.sections.apiKeys')} description={tr('admin.cards.apiKeysDesc')}>
              <ApiKeysTab onError={setError} />
            </SectionCard>
          )}

          {tab === 'backups' && (
            <SectionCard title={tr('admin.sections.backups')} description={tr('admin.cards.backupsDesc')}>
              <BackupsSection />
            </SectionCard>
          )}

          {tab === 'sessions' && (
            <SectionCard
              title={tr('admin.sections.sessions')}
              description={tr('admin.cards.sessionsDesc')}
            >
              <SessionsSection currentUserId={user.id} />
            </SectionCard>
          )}

          {tab === 'recordings' && (
            <div className="flex flex-col gap-5">
              <SectionCard
                title={tr('admin.sections.recordingSettings')}
                description={tr('recordings.settingsDescription')}
              >
                <RecordingSettingsPanel />
              </SectionCard>
              <SectionCard
                title={tr('admin.sections.recordings')}
                description={tr('recordings.listDescription')}
              >
                <RecordingsSection />
              </SectionCard>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
};

export default AdminPage;
