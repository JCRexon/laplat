import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { loadSession, saveSession } from "../api/client";
import { logout, me, refreshSession } from "../api/endpoints";
import type { Me } from "../api/types";

interface AuthState {
  me: Me | null;
  loading: boolean;
  signedIn: boolean;
  // onSignedIn loads /me after a verify flow has stored a session.
  onSignedIn: () => Promise<void>;
  // refreshMe re-mints the token (to reflect a tier climb) and reloads /me.
  refreshMe: () => Promise<void>;
  signOut: () => Promise<void>;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  async function loadMe() {
    if (!loadSession()) {
      setUser(null);
      return;
    }
    try {
      setUser(await me());
    } catch {
      // Session unusable (refresh rejected); drop it.
      saveSession(null);
      setUser(null);
    }
  }

  useEffect(() => {
    loadMe().finally(() => setLoading(false));
  }, []);

  const value: AuthState = {
    me: user,
    loading,
    signedIn: user !== null,
    onSignedIn: loadMe,
    refreshMe: async () => {
      await refreshSession();
      await loadMe();
    },
    signOut: async () => {
      const s = loadSession();
      if (s) {
        try {
          await logout(s.refreshToken);
        } catch {
          // Best-effort; clear locally regardless.
        }
      }
      saveSession(null);
      setUser(null);
    },
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth must be used within AuthProvider");
  return v;
}
