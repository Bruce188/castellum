import { useEffect, useState } from 'react';

const TOKEN_KEY = 'castellum.jwt';
const USER_KEY = 'castellum.user';
const AUTH_EVENT = 'castellum:auth';

export interface AuthState {
  token: string | null;
  username: string | null;
}

function read(): AuthState {
  return {
    token: localStorage.getItem(TOKEN_KEY),
    username: localStorage.getItem(USER_KEY),
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
