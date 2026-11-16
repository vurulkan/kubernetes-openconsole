import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Input, Modal } from '../../components/ui';
import { confirm } from '../../components/ConfirmDialog';
import {
  createRole,
  deleteRole,
  listClustersAdmin,
  listNamespaces,
  updateRole,
  type ApiAccess,
  type ClusterListItem,
} from '../../services/api';
import { RolesSection } from './RolesSection';
import { RolePermissionsPanel } from './RolePermissionsPanel';
import { ClassicRolePermissions } from './ClassicRolePermissions';
import { RoleApiAccessField } from './ApiAccessParts';
import { SectionCard } from './SectionCard';
import { useDirectory, type DirectoryKind } from './useDirectory';

const KINDS: DirectoryKind[] = ['groups', 'roles'];

type RoleForm = { name: string; description: string; apiAccess: ApiAccess };
const emptyRole: RoleForm = { name: '', description: '', apiAccess: 'safe_read' };

/**
 * Admin → Roles: the role list with its create / edit / delete dialogs and the
 * Role Permissions card (new layout by default, classic kept in localStorage).
 * Also loads the clusters and namespaces the permission forms offer.
 */
export const RolesTab: React.FC<{
  filter: string;
  onFilter: (v: string) => void;
  onError: (msg: string | null) => void;
}> = ({ filter, onFilter, onError }) => {
  const { t: tr } = useTranslation();
  const { roles, groupRoles, refresh, loaded } = useDirectory(KINDS, onError);
  const [clusters, setClusters] = useState<ClusterListItem[]>([]);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [newRole, setNewRole] = useState<RoleForm>(emptyRole);
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<null | (RoleForm & { id: number })>(null);
  const [saving, setSaving] = useState(false);
  // Role Permissions UI switcher: the new layout is the default, classic
  // persists via localStorage so a single click reverts the whole experience.
  const [layout, setLayout] = useState<'new' | 'classic'>(() => {
    try {
      return localStorage.getItem('rolePermissionsLayout') === 'classic' ? 'classic' : 'new';
    } catch {
      return 'new';
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem('rolePermissionsLayout', layout);
    } catch {
      /* ignore */
    }
  }, [layout]);

  useEffect(() => {
    // The permission forms offer a per-cluster scope and the namespaces.
    listClustersAdmin()
      .then((r) => setClusters(r.items ?? []))
      .catch(() => setClusters([]));
    listNamespaces(true)
      .then((r) => setNamespaces(r.namespaces ?? []))
      .catch(() => setNamespaces([]));
  }, []);

  const createSubmit = async () => {
    if (!newRole.name) return;
    setSaving(true);
    onError(null);
    try {
      await createRole(newRole);
      setNewRole(emptyRole);
      await refresh();
      setShowCreate(false);
    } catch (err) {
      onError((err as Error).message || tr('common.createFailed'));
    } finally {
      setSaving(false);
    }
  };

  const editSubmit = async () => {
    if (!editing) return;
    setSaving(true);
    onError(null);
    try {
      await updateRole(editing.id, { name: editing.name, description: editing.description, apiAccess: editing.apiAccess });
      await refresh();
      setEditing(null);
    } catch (err) {
      onError((err as Error).message || tr('common.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  if (!loaded) return null;
  return (
    <div className="flex flex-col gap-5">
      <RolesSection
        roles={roles}
        groupRoles={groupRoles}
        filter={filter}
        onFilter={onFilter}
        onNew={() => {
          setNewRole(emptyRole);
          setShowCreate(true);
        }}
        onEdit={(r) => setEditing({ id: r.id, name: r.name, description: r.description, apiAccess: r.apiAccess })}
        onDelete={async (r) => {
          const ok = await confirm({
            title: tr('common.deleteRole', { name: r.name }),
            message: tr('admin.roles.deleteConfirm'),
            confirmText: tr('actions.delete'),
            variant: 'danger',
          });
          if (!ok) return;
          onError(null);
          try {
            await deleteRole(r.id);
            await refresh();
          } catch (err) {
            onError((err as Error).message || tr('common.deleteFailed'));
          }
        }}
      />

      <SectionCard title={tr('admin.sections.rolePermissions')}>
        {layout === 'new' ? (
          <RolePermissionsPanel
            roles={roles}
            clusters={clusters}
            namespaces={namespaces}
            onError={onError}
            onSwitchClassic={() => setLayout('classic')}
          />
        ) : (
          <ClassicRolePermissions
            roles={roles}
            clusters={clusters}
            namespaces={namespaces}
            onSwitchNew={() => setLayout('new')}
          />
        )}
      </SectionCard>

      {/* ── Create Role modal ─────────────────────────────────────── */}
      <Modal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        title={tr('admin.newRole')}
        size="sm"
        footer={
          <>
            <Button variant="outline" size="sm" onClick={() => setShowCreate(false)}>
              {tr('actions.cancel')}
            </Button>
            <Button variant="primary" size="sm" disabled={saving || !newRole.name} onClick={createSubmit}>
              {saving ? tr('admin.newUserMenu.creating') : tr('admin.roles.create')}
            </Button>
          </>
        }
      >
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            void createSubmit();
          }}
        >
          <Input
            label={tr('common.name')}
            value={newRole.name}
            onChange={(e) => setNewRole({ ...newRole, name: e.target.value })}
            autoFocus
          />
          <Input
            label={tr('common.description')}
            value={newRole.description}
            onChange={(e) => setNewRole({ ...newRole, description: e.target.value })}
          />
          <RoleApiAccessField value={newRole.apiAccess} onChange={(v) => setNewRole({ ...newRole, apiAccess: v })} />
          <button type="submit" className="hidden" aria-hidden="true" />
        </form>
      </Modal>

      {/* ── Edit Role modal ───────────────────────────────────────── */}
      {editing && (
        <Modal
          open={editing !== null}
          onClose={() => setEditing(null)}
          title={`Edit · ${editing.name}`}
          size="sm"
          footer={
            <>
              <Button variant="outline" size="sm" onClick={() => setEditing(null)}>
                {tr('actions.cancel')}
              </Button>
              <Button variant="primary" size="sm" disabled={saving} onClick={editSubmit}>
                {saving ? tr('yamlEditor.saving') : tr('actions.save')}
              </Button>
            </>
          }
        >
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void editSubmit();
            }}
          >
            <Input
              label={tr('common.name')}
              value={editing.name}
              onChange={(e) => setEditing({ ...editing, name: e.target.value })}
              autoFocus
            />
            <Input
              label={tr('common.description')}
              value={editing.description}
              onChange={(e) => setEditing({ ...editing, description: e.target.value })}
            />
            <RoleApiAccessField value={editing.apiAccess} onChange={(v) => setEditing({ ...editing, apiAccess: v })} />
            <button type="submit" className="hidden" aria-hidden="true" />
          </form>
        </Modal>
      )}
    </div>
  );
};

export default RolesTab;
