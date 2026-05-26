import { useState, type FormEvent } from 'react';
import { setAuth } from '../hooks/useAuth';

const BASE = (import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080') as string;

export function Login() {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch(`${BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        setError(res.status === 401 ? 'Invalid credentials' : `Login failed: ${res.status}`);
        return;
      }
      const data = (await res.json()) as { token: string; mustChangePassword?: boolean };
      if (!data.token) {
        setError('Login response missing token');
        return;
      }
      setAuth(data.token, username, Boolean(data.mustChangePassword));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <form onSubmit={onSubmit} className="w-full max-w-sm bg-white p-6 rounded shadow space-y-4">
        <h1 className="text-xl font-semibold text-gray-800">Castellum</h1>
        <label className="block">
          <span className="text-sm text-gray-700">Username</span>
          <input
            type="text"
            value={username}
            onChange={e => setUsername(e.target.value)}
            autoComplete="username"
            required
            className="mt-1 w-full px-3 py-2 border border-gray-300 rounded"
          />
        </label>
        <label className="block">
          <span className="text-sm text-gray-700">Password</span>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            className="mt-1 w-full px-3 py-2 border border-gray-300 rounded"
          />
        </label>
        {error && <p className="text-sm text-red-600">{error}</p>}
        <button
          type="submit"
          disabled={submitting}
          className="w-full px-3 py-2 bg-blue-600 text-white rounded disabled:opacity-50"
        >
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
