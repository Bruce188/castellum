import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { api } from '../api/client';
import type { UserDto, UserRole } from '../api/types';

interface Props {
  isAdmin: boolean;
}

const ROLES: UserRole[] = ['ADMIN', 'VIEWER'];

/**
 * ADMIN-only user-management surface. Lists users (paginated), exposes a
 * create-user form, a role-change dropdown per row, and a disable button.
 *
 * <p>VIEWER and anonymous callers see a single read-only notice; the backend
 * enforces RBAC regardless.
 */
export function UserManagementPanel({ isAdmin }: Props) {
  const [users, setUsers] = useState<UserDto[]>([]);
  const [page, setPage] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [newUsername, setNewUsername] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('VIEWER');
  const [newPassword, setNewPassword] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const reload = useCallback(async (targetPage: number = 0) => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.listUsers(targetPage, 25);
      setUsers(result.content);
      setPage(result.number);
      setTotalPages(Math.max(result.totalPages, 1));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isAdmin) return;
    let cancelled = false;
    const run = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await api.listUsers(0, 25);
        if (cancelled) return;
        setUsers(result.content);
        setPage(result.number);
        setTotalPages(Math.max(result.totalPages, 1));
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'failed to load users');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void run();
    return () => { cancelled = true; };
  }, [isAdmin]);

  if (!isAdmin) {
    return (
      <section
        data-testid="user-management-panel"
        className="rounded border border-gray-200 bg-white p-4 mb-4"
      >
        <h2 className="text-base font-semibold text-gray-800">User management</h2>
        <p className="mt-2 text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-1 inline-block">
          ADMIN role required
        </p>
      </section>
    );
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (creating) return;
    setCreateError(null);
    if (newPassword.length < 8) {
      setCreateError('Initial password must be at least 8 characters.');
      return;
    }
    setCreating(true);
    try {
      await api.createUser({
        username: newUsername,
        role: newRole,
        initialPassword: newPassword,
      });
      setNewUsername('');
      setNewPassword('');
      setNewRole('VIEWER');
      void reload(0);
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'create failed');
    } finally {
      setCreating(false);
    }
  }

  async function handleRoleChange(username: string, role: UserRole) {
    try {
      await api.changeUserRole(username, role);
      void reload(page);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'role change failed');
    }
  }

  async function handleDisable(username: string) {
    if (!window.confirm(`Disable user "${username}"? They will be signed out immediately.`)) return;
    try {
      await api.disableUser(username);
      void reload(page);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'disable failed');
    }
  }

  return (
    <section
      data-testid="user-management-panel"
      className="rounded border border-gray-200 bg-white p-4 mb-4"
    >
      <header className="mb-3">
        <h2 className="text-base font-semibold text-gray-800">User management</h2>
      </header>

      <form onSubmit={handleCreate} className="grid gap-2 sm:grid-cols-4 mb-4 items-end" autoComplete="off">
        <label className="text-sm sm:col-span-1">
          <span className="block text-gray-700 mb-1">Username</span>
          <input
            type="text"
            data-testid="new-username-input"
            value={newUsername}
            onChange={e => setNewUsername(e.target.value)}
            required
            pattern="[A-Za-z0-9._-]+"
            className="w-full border border-gray-300 rounded px-2 py-1 text-sm"
          />
        </label>
        <label className="text-sm sm:col-span-1">
          <span className="block text-gray-700 mb-1">Role</span>
          <select
            data-testid="new-role-select"
            value={newRole}
            onChange={e => setNewRole(e.target.value as UserRole)}
            className="w-full border border-gray-300 rounded px-2 py-1 text-sm"
          >
            {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>
        <label className="text-sm sm:col-span-1">
          <span className="block text-gray-700 mb-1">Initial password</span>
          <input
            type="password"
            data-testid="new-password-input"
            value={newPassword}
            onChange={e => setNewPassword(e.target.value)}
            required
            minLength={8}
            autoComplete="new-password"
            className="w-full border border-gray-300 rounded px-2 py-1 text-sm"
          />
        </label>
        <div className="sm:col-span-1">
          <button
            type="submit"
            disabled={creating}
            className="w-full px-3 py-1 text-sm rounded bg-blue-600 text-white hover:bg-blue-700 disabled:bg-blue-300"
          >
            {creating ? 'Creating…' : 'Create user'}
          </button>
        </div>
        {createError && (
          <p role="alert" className="text-sm text-red-600 sm:col-span-4">{createError}</p>
        )}
      </form>

      {error && <p role="alert" className="text-sm text-red-600 mb-2">{error}</p>}

      <div className="overflow-x-auto">
        <table data-testid="users-table" className="w-full text-sm border border-gray-200">
          <thead className="bg-gray-50 text-left text-gray-700">
            <tr>
              <th className="px-2 py-1 border-b">Username</th>
              <th className="px-2 py-1 border-b">Role</th>
              <th className="px-2 py-1 border-b">Enabled</th>
              <th className="px-2 py-1 border-b">Created</th>
              <th className="px-2 py-1 border-b">Last login</th>
              <th className="px-2 py-1 border-b">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} className="px-2 py-2 text-gray-500">Loading…</td></tr>
            )}
            {!loading && users.length === 0 && (
              <tr><td colSpan={6} className="px-2 py-2 text-gray-500">No users.</td></tr>
            )}
            {!loading && users.map(u => (
              <tr key={u.username} className="border-b last:border-0" data-testid={`user-row-${u.username}`}>
                <td className="px-2 py-1">{u.username}</td>
                <td className="px-2 py-1">
                  <select
                    data-testid={`role-select-${u.username}`}
                    value={u.role}
                    onChange={e => handleRoleChange(u.username, e.target.value as UserRole)}
                    className="border border-gray-300 rounded px-1 py-0.5 text-xs"
                  >
                    {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                </td>
                <td className="px-2 py-1">{u.enabled ? 'yes' : 'no'}</td>
                <td className="px-2 py-1 text-xs text-gray-600">{u.createdAt ?? '-'}</td>
                <td className="px-2 py-1 text-xs text-gray-600">{u.lastLoginAt ?? '-'}</td>
                <td className="px-2 py-1">
                  <button
                    type="button"
                    data-testid={`disable-btn-${u.username}`}
                    onClick={() => handleDisable(u.username)}
                    disabled={!u.enabled}
                    className="px-2 py-0.5 text-xs rounded border border-red-300 text-red-700 hover:bg-red-50 disabled:text-gray-400 disabled:border-gray-200 disabled:cursor-not-allowed"
                  >
                    Disable
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center gap-2 mt-2 text-sm">
          <button
            type="button"
            data-testid="users-prev"
            onClick={() => reload(page - 1)}
            disabled={page === 0}
            className="px-2 py-0.5 border border-gray-300 rounded disabled:opacity-50"
          >
            Prev
          </button>
          <span className="text-gray-600">Page {page + 1} of {totalPages}</span>
          <button
            type="button"
            data-testid="users-next"
            onClick={() => reload(page + 1)}
            disabled={page + 1 >= totalPages}
            className="px-2 py-0.5 border border-gray-300 rounded disabled:opacity-50"
          >
            Next
          </button>
        </div>
      )}
    </section>
  );
}
