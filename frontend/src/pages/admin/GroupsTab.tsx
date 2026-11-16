import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Input, Modal, MultiSelect, MultiSelectOption } from '../../components/ui';
import { confirm } from '../../components/ConfirmDialog';
import { createGroup, deleteGroup, setGroupRoles, updateGroup } from '../../services/api';
import { GroupsSection } from './GroupsSection';
import { useDirectory, type DirectoryKind } from './useDirectory';

const KINDS: DirectoryKind[] = ['users', 'groups', 'roles'];

/** Admin → Groups: the group list (members, roles) with its create, edit and delete dialogs. */
export const GroupsTab: React.FC<{
  filter: string;
  onFilter: (v: string) => void;
  onError: (msg: string | null) => void;
}> = ({ filter, onFilter, onError }) => {
  const { t: tr } = useTranslation();
  const { users, groups, roles, userGroups, groupRoles, refresh } = useDirectory(KINDS, onError);
  const [newGroup, setNewGroup] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<null | { id: number; name: string; roleIds: number[] }>(null);
  const [saving, setSaving] = useState(false);

  const createSubmit = async () => {
    if (!newGroup) return;
    setSaving(true);
    onError(null);
    try {
      await createGroup(newGroup);
      setNewGroup('');
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
      await updateGroup(editing.id, editing.name);
      await setGroupRoles(editing.id, editing.roleIds);
      await refresh();
      setEditing(null);
    } catch (err) {
      onError((err as Error).message || tr('common.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <GroupsSection
        groups={groups}
        roles={roles}
        groupRoles={groupRoles}
        users={users}
        userGroups={userGroups}
        filter={filter}
        onFilter={onFilter}
        onNew={() => {
          setNewGroup('');
          setShowCreate(true);
        }}
        onEdit={(g) => setEditing({ id: g.id, name: g.name, roleIds: (groupRoles[g.id] ?? []).map((r) => r.id) })}
        onDelete={async (g) => {
          const ok = await confirm({
            title: tr('common.deleteGroup', { name: g.name }),
            message: tr('admin.groups.deleteConfirm'),
            confirmText: tr('actions.delete'),
            variant: 'danger',
          });
          if (!ok) return;
          onError(null);
          try {
            await deleteGroup(g.id);
            await refresh();
          } catch (err) {
            onError((err as Error).message || tr('common.deleteFailed'));
          }
        }}
      />

      {/* ── Create Group modal ────────────────────────────────────── */}
      <Modal
        open={showCreate}
        onClose={() => setShowCreate(false)}
        title={tr('admin.newGroup')}
        size="sm"
        footer={
          <>
            <Button variant="outline" size="sm" onClick={() => setShowCreate(false)}>
              {tr('actions.cancel')}
            </Button>
            <Button variant="primary" size="sm" disabled={saving || !newGroup} onClick={createSubmit}>
              {saving ? tr('admin.newUserMenu.creating') : tr('admin.groups.create')}
            </Button>
          </>
        }
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void createSubmit();
          }}
        >
          <Input label={tr('common.groupName')} value={newGroup} onChange={(e) => setNewGroup(e.target.value)} autoFocus />
          <button type="submit" className="hidden" aria-hidden="true" />
        </form>
      </Modal>

      {/* ── Edit Group modal ──────────────────────────────────────── */}
      {editing && (
        <Modal
          open={editing !== null}
          onClose={() => setEditing(null)}
          title={`Edit · ${editing.name}`}
          size="md"
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
            <MultiSelect
              label={tr('admin.tabs.roles')}
              options={roles.map((r) => ({ id: r.id, label: r.name }))}
              value={editing.roleIds.map((id) => {
                const r = roles.find((rr) => rr.id === id);
                return { id, label: r?.name ?? `Role ${id}` };
              })}
              onChange={(value: MultiSelectOption[]) => setEditing({ ...editing, roleIds: value.map((v) => Number(v.id)) })}
              placeholder={tr('admin.groups.assignRoles')}
              noOptionsText={tr('admin.groups.noRoles')}
            />
            <button type="submit" className="hidden" aria-hidden="true" />
          </form>
        </Modal>
      )}
    </>
  );
};

export default GroupsTab;
