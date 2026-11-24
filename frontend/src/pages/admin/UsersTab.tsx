import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Input, Modal, MultiSelect, MultiSelectOption } from '../../components/ui';
import { AzureImport, LdapImport } from '../../components/DirectoryImportPanel';
import { confirm } from '../../components/ConfirmDialog';
import {
  createUser,
  deleteUser,
  getAzureAD,
  getLDAP,
  setUserGroups,
  updateUser,
  type ApiAccessOverride,
} from '../../services/api';
import { UsersSection } from './UsersSection';
import { UserApiAccessField } from './ApiAccessParts';
import { useDirectory, type DirectoryKind } from './useDirectory';

const KINDS: DirectoryKind[] = ['users', 'groups'];

type NewUser = { username: string; password: string; isAdmin: boolean; source: 'local' | 'azure'; groupIds: number[] };
const emptyUser = (source: 'local' | 'azure' = 'local'): NewUser => ({ username: '', password: '', isAdmin: false, source, groupIds: [] });

/**
 * Admin → Users: the user list with its create (local / Azure AD), LDAP
 * import, edit and delete dialogs. Loads users, groups and whether LDAP /
 * Azure AD are on (for the "New user" menu).
 */
export const UsersTab: React.FC<{
  filter: string;
  onFilter: (v: string) => void;
  /** Just created or imported; kept by AdminPage so an LDAP-tab import shows here too. */
  newUsernames: string[];
  onUsersAdded: (names: string[]) => void;
  apiKeysOn: boolean;
  onError: (msg: string | null) => void;
}> = ({ filter, onFilter, newUsernames, onUsersAdded, apiKeysOn, onError }) => {
  const { t: tr } = useTranslation();
  const { users, groups, userGroups, refresh, loaded } = useDirectory(KINDS, onError);
  const [ldapEnabled, setLdapEnabled] = useState(false);
  const [azureEnabled, setAzureEnabled] = useState(false);
  const [azureSearch, setAzureSearch] = useState(false);
  const [showAzureImport, setShowAzureImport] = useState(false);
  const [newUser, setNewUser] = useState<NewUser>(emptyUser());
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [createUserError, setCreateUserError] = useState<string | null>(null);
  const [showLdapImport, setShowLdapImport] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editingUser, setEditingUser] = useState<null | {
    id: number;
    username: string;
    isActive: boolean;
    isAdmin: boolean;
    groupIds: number[];
    apiAccessOverride: ApiAccessOverride;
  }>(null);

  useEffect(() => {
    getLDAP()
      .then((c) => setLdapEnabled(c.enabled ?? false))
      .catch(() => {});
    getAzureAD()
      .then((c) => {
        setAzureEnabled(c.enabled ?? false);
        setAzureSearch((c.enabled ?? false) && (c.graphSearch ?? false));
      })
      .catch(() => {});
  }, []);

  const afterUsersAdded = async (names: string[]) => {
    await refresh();
    if (names.length > 0) onUsersAdded(names);
  };

  if (!loaded) return null;
  return (
    <>
      <UsersSection
        users={users}
        groups={groups}
        userGroups={userGroups}
        filter={filter}
        onFilter={onFilter}
        onNew={(source) => {
          if (source === 'azure' && azureSearch) {
            setShowAzureImport(true);
            return;
          }
          setNewUser(emptyUser(source));
          setCreateUserError(null);
          setShowCreateUser(true);
        }}
        onImportLdap={ldapEnabled ? () => setShowLdapImport(true) : undefined}
        newUsernames={newUsernames}
        azureEnabled={azureEnabled}
        azureSearch={azureSearch}
        onReload={() => void refresh()}
        onEdit={(u) =>
          setEditingUser({
            id: u.id,
            username: u.username,
            isActive: u.isActive,
            isAdmin: u.isAdmin,
            groupIds: (userGroups[u.id] ?? []).map((g) => g.id),
            apiAccessOverride: u.apiAccessOverride ?? '',
          })
        }
        onDelete={async (u) => {
          const ok = await confirm({
            title: tr('common.deleteUser', { name: u.username }),
            message: tr('admin.users.deleteConfirm'),
            confirmText: tr('actions.delete'),
            variant: 'danger',
          });
          if (!ok) return;
          onError(null);
          try {
            await deleteUser(u.id);
            await refresh();
          } catch (err) {
            onError((err as Error).message || tr('common.deleteFailed'));
          }
        }}
      />

      {/* ── Create User modal (local or pre-created Azure AD) ─────── */}
      {(() => {
        const azure = newUser.source === 'azure';
        const ready = !!newUser.username.trim() && (azure || !!newUser.password);
        const submit = async () => {
          if (!ready) return;
          setSaving(true);
          setCreateUserError(null);
          try {
            const created = await createUser(azure ? { ...newUser, password: undefined } : newUser);
            setNewUser(emptyUser());
            await afterUsersAdded([created.username]);
            setShowCreateUser(false);
          } catch (err) {
            setCreateUserError((err as Error).message || tr('admin.newUserMenu.createFailed'));
          } finally {
            setSaving(false);
          }
        };
        const groupOption = (g: { id: number; name: string }) => ({ id: g.id, label: g.name });
        return (
          <Modal
            open={showCreateUser}
            onClose={() => setShowCreateUser(false)}
            title={azure ? tr('admin.newUserMenu.azureTitle') : tr('admin.newUserMenu.localTitle')}
            size="sm"
            footer={
              <>
                <Button variant="outline" size="sm" onClick={() => setShowCreateUser(false)}>
                  {tr('actions.cancel')}
                </Button>
                <Button type="submit" form="create-user-form" variant="primary" size="sm" disabled={saving || !ready}>
                  {saving ? tr('admin.newUserMenu.creating') : tr('admin.newUserMenu.create')}
                </Button>
              </>
            }
          >
            <form
              id="create-user-form"
              className="flex flex-col gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                void submit();
              }}
            >
              {azure && <p className="text-xs text-slate-500 dark:text-slate-400">{tr('admin.newUserMenu.azureHelp')}</p>}
              <Input
                label={azure ? tr('admin.newUserMenu.upn') : tr('common.username')}
                placeholder={azure ? 'jane@example.com' : undefined}
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                autoFocus
              />
              {!azure && (
                <Input
                  label={tr('common.password')}
                  type="password"
                  autoComplete="new-password"
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                />
              )}
              <MultiSelect
                label={tr('admin.newUserMenu.groups')}
                options={groups.map(groupOption)}
                value={groups.filter((g) => newUser.groupIds.includes(g.id)).map(groupOption)}
                onChange={(value: MultiSelectOption[]) => setNewUser({ ...newUser, groupIds: value.map((v) => Number(v.id)) })}
                noOptionsText={tr('ldapImport.noGroups')}
                placeholder={tr('ldapImport.groupsPlaceholder')}
              />
              <Checkbox
                checked={newUser.isAdmin}
                onChange={(v) => setNewUser({ ...newUser, isAdmin: v })}
                label={tr('common.grantAdmin')}
              />
              {createUserError && <Alert severity="error">{createUserError}</Alert>}
            </form>
          </Modal>
        );
      })()}

      {/* ── Import from LDAP ──────────────────────────────────────── */}
      <Modal
        open={showLdapImport}
        onClose={() => setShowLdapImport(false)}
        title={tr('admin.newUserMenu.ldapTitle')}
        size="md"
        footer={
          <Button variant="outline" size="sm" onClick={() => setShowLdapImport(false)}>
            {tr('actions.close')}
          </Button>
        }
      >
        {showLdapImport && <LdapImport groups={groups} onImported={afterUsersAdded} />}
      </Modal>

      {/* ── Azure AD: search Entra ID (directory search on) ───────────── */}
      <Modal
        open={showAzureImport}
        onClose={() => setShowAzureImport(false)}
        title={tr('admin.newUserMenu.azureTitle')}
        size="md"
        footer={
          <Button variant="outline" size="sm" onClick={() => setShowAzureImport(false)}>
            {tr('actions.close')}
          </Button>
        }
      >
        {showAzureImport && (
          <AzureImport
            groups={groups}
            onImported={afterUsersAdded}
            onManual={() => {
              setShowAzureImport(false);
              setNewUser(emptyUser('azure'));
              setCreateUserError(null);
              setShowCreateUser(true);
            }}
          />
        )}
      </Modal>

      {/* ── Edit User modal ───────────────────────────────────────── */}
      {editingUser &&
        (() => {
          const submit = async () => {
            if (!editingUser) return;
            setSaving(true);
            onError(null);
            try {
              await updateUser(editingUser.id, {
                username: editingUser.username,
                isActive: editingUser.isActive,
                isAdmin: editingUser.isAdmin,
                apiAccessOverride: editingUser.apiAccessOverride,
              });
              await setUserGroups(editingUser.id, editingUser.groupIds);
              await refresh();
              setEditingUser(null);
            } catch (err) {
              onError((err as Error).message || tr('common.saveFailed'));
            } finally {
              setSaving(false);
            }
          };
          return (
            <Modal
              open={editingUser !== null}
              onClose={() => setEditingUser(null)}
              title={`Edit · ${editingUser.username}`}
              size="md"
              footer={
                <>
                  <Button variant="outline" size="sm" onClick={() => setEditingUser(null)}>
                    {tr('actions.cancel')}
                  </Button>
                  <Button variant="primary" size="sm" disabled={saving} onClick={submit}>
                    {saving ? tr('yamlEditor.saving') : tr('actions.save')}
                  </Button>
                </>
              }
            >
              <form
                className="flex flex-col gap-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  void submit();
                }}
              >
                <Input
                  label={tr('common.username')}
                  value={editingUser.username}
                  onChange={(e) => setEditingUser({ ...editingUser, username: e.target.value })}
                  autoFocus
                />
                <div className="flex items-center gap-5">
                  <Checkbox
                    checked={editingUser.isActive}
                    onChange={(v) => setEditingUser({ ...editingUser, isActive: v })}
                    label={tr('common.active')}
                  />
                  <Checkbox
                    checked={editingUser.isAdmin}
                    onChange={(v) => setEditingUser({ ...editingUser, isAdmin: v })}
                    label={tr('common.admin')}
                  />
                </div>
                <MultiSelect
                  label={tr('common.groups')}
                  options={groups.map((g) => ({ id: g.id, label: g.name }))}
                  value={editingUser.groupIds.map((id) => {
                    const g = groups.find((grp) => grp.id === id);
                    return { id, label: g?.name ?? `Group ${id}` };
                  })}
                  onChange={(value: MultiSelectOption[]) =>
                    setEditingUser({ ...editingUser, groupIds: value.map((v) => Number(v.id)) })
                  }
                  placeholder={tr('common.assignGroups')}
                  noOptionsText={tr('admin.groups.noGroups')}
                />
                {apiKeysOn && (
                  <UserApiAccessField
                    userId={editingUser.id}
                    value={editingUser.apiAccessOverride}
                    onChange={(v) => setEditingUser({ ...editingUser, apiAccessOverride: v })}
                  />
                )}
                <button type="submit" className="hidden" aria-hidden="true" />
              </form>
            </Modal>
          );
        })()}
    </>
  );
};

export default UsersTab;
