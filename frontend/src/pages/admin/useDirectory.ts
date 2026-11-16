import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { listGroups, listRoles, listUsers, type Role, type User } from '../../services/api';

export type DirectoryKind = 'users' | 'groups' | 'roles';
export type NamedRef = { id: number; name: string };
export type Group = NamedRef & { roleIds?: number[] };

/**
 * Users, groups and roles for an Admin tab: loads only the lists in `kinds`
 * (a constant array) when the tab opens, and again on refresh() after an
 * action. The lists carry the memberships (users' groupIds, groups'
 * roleIds), so there is no request per user or group.
 */
export function useDirectory(kinds: readonly DirectoryKind[], onError: (msg: string | null) => void) {
  const { t } = useTranslation();
  const [users, setUsers] = useState<User[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  // False until the first load answers: the tables show nothing rather than
  // an empty-list message for data that is still coming.
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    const results = await Promise.allSettled([
      kinds.includes('users') ? listUsers() : null,
      kinds.includes('groups') ? listGroups() : null,
      kinds.includes('roles') ? listRoles() : null,
    ]);
    const [u, g, r] = results;
    if (u.status === 'fulfilled' && u.value) setUsers(u.value.items ?? []);
    if (g.status === 'fulfilled' && g.value) setGroups(g.value.items ?? []);
    if (r.status === 'fulfilled' && r.value) setRoles(r.value.items ?? []);
    if (results.some((x) => x.status === 'rejected')) onError(t('admin.loadFailed'));
    setLoaded(true);
  }, [kinds, onError, t]);

  useEffect(() => {
    void load();
  }, [load]);

  // After an action: clears the page error, as the old page-wide reload did.
  const refresh = useCallback(async () => {
    onError(null);
    await load();
  }, [load, onError]);

  const userGroups = useMemo(() => {
    const name = new Map(groups.map((g) => [g.id, g.name]));
    return Object.fromEntries(
      users.map((u) => [u.id, (u.groupIds ?? []).map((id) => ({ id, name: name.get(id) ?? `Group ${id}` }))]),
    ) as Record<number, NamedRef[]>;
  }, [users, groups]);

  const groupRoles = useMemo(() => {
    const name = new Map(roles.map((r) => [r.id, r.name]));
    return Object.fromEntries(
      groups.map((g) => [g.id, (g.roleIds ?? []).map((id) => ({ id, name: name.get(id) ?? `Role ${id}` }))]),
    ) as Record<number, NamedRef[]>;
  }, [groups, roles]);

  return { users, groups, roles, userGroups, groupRoles, refresh, loaded };
}
