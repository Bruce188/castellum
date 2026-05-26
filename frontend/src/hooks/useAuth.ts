import { useEffect, useState } from 'react';

const TOKEN_KEY = 'castellum.jwt';
const USER_KEY = 'castellum.user';
const MUST_CHANGE_KEY = 'castellum.mustChangePassword';
const AUTH_EVENT = 'castellum:auth';

export interface AuthState {
  token: string | null;
  username: string | null;
  /** Roles extracted from the JWT payload's {@code roles} claim. Defaults to {@code []}. */
  roles: string[];
  /**
   * Mirror of the {@code mustChangePassword} field from the login response. When
   * {@code true}, the app shell renders a non-dismissable rotation overlay
   * instead of any routed page.
   */
  mustChangePassword: boolean;
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
    mustChangePassword: localStorage.getItem(MUST_CHANGE_KEY) === '1',
  };
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setAuth(token: string, username: string, mustChangePassword: boolean = false) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, username);
  if (mustChangePassword) {
    localStorage.setItem(MUST_CHANGE_KEY, '1');
  } else {
    localStorage.removeItem(MUST_CHANGE_KEY);
  }
  window.dispatchEvent(new Event(AUTH_EVENT));
}

/**
 * Clears the {@code mustChangePassword} flag without touching the token. Called
 * after a successful first-login rotation so the user can proceed to the app
 * without re-authenticating.
 */
export function clearMustChangePassword() {
  localStorage.removeItem(MUST_CHANGE_KEY);
  window.dispatchEvent(new Event(AUTH_EVENT));
}

export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  localStorage.removeItem(MUST_CHANGE_KEY);
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
