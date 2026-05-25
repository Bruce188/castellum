import { useEffect, useState } from 'react';

const TOKEN_KEY = 'castellum.jwt';
const USER_KEY = 'castellum.user';
const AUTH_EVENT = 'castellum:auth';

export interface AuthState {
  token: string | null;
  username: string | null;
  /** Roles extracted from the JWT payload's {@code roles} claim. Defaults to {@code []}. */
  roles: string[];
}

/**
 * Decodes the {@code roles} claim from a raw JWT token without verifying the signature.
 * Signature verification is the backend's responsibility; here we only need the claim
 * for UI role-gating decisions.
 */
function decodeRoles(token: string | null): string[] {
  if (!token) return [];
  try {
    const [, payload] = token.split('.');
    const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    const roles = decoded?.roles;
    if (Array.isArray(roles)) return roles as string[];
  } catch {
    // malformed token — safe default
  }
  return [];
}

function read(): AuthState {
  const token = localStorage.getItem(TOKEN_KEY);
  return {
    token,
    username: localStorage.getItem(USER_KEY),
    roles: decodeRoles(token),
  };
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setAuth(token: string, username: string) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, username);
  window.dispatchEvent(new Event(AUTH_EVENT));
}

export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  window.dispatchEvent(new Event(AUTH_EVENT));
}

export function useAuth(): AuthState {
  const [state, setState] = useState<AuthState>(read);
  useEffect(() => {
    const handler = () => setState(read());
    window.addEventListener(AUTH_EVENT, handler);
    window.addEventListener('storage', handler);
    return () => {
      window.removeEventListener(AUTH_EVENT, handler);
      window.removeEventListener('storage', handler);
    };
  }, []);
  return state;
}
