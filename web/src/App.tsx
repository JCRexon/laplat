import { lazy, Suspense, type ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth/AuthContext";
import { Layout } from "./components/Layout";
import { Catalog } from "./pages/Catalog";
import { Onboarding } from "./pages/Onboarding";
import { SignIn } from "./pages/SignIn";

// The live room pulls in the LiveKit SDK (~600 kB); load it only when a user
// actually joins, keeping the initial bundle small.
const SessionRoom = lazy(() =>
  import("./pages/SessionRoom").then((m) => ({ default: m.SessionRoom })),
);

function RequireAuth({ children }: { children: ReactNode }) {
  const { signedIn, loading } = useAuth();
  if (loading) return <p className="muted center">Loading…</p>;
  if (!signedIn) return <Navigate to="/signin" replace />;
  return <>{children}</>;
}

export function App() {
  return (
    <Routes>
      <Route path="/signin" element={<SignIn />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/" element={<Navigate to="/catalog" replace />} />
        <Route path="/catalog" element={<Catalog />} />
        <Route path="/onboarding" element={<Onboarding />} />
        <Route
          path="/room/:id"
          element={
            <Suspense fallback={<p className="muted center">Loading room…</p>}>
              <SessionRoom />
            </Suspense>
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
