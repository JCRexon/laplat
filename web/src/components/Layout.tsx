import { Link, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { TierBadge } from "./TierBadge";

export function Layout() {
  const { me, signedIn, signOut } = useAuth();
  const navigate = useNavigate();

  return (
    <div className="app">
      <header className="topbar">
        <Link to="/" className="brand">
          laplat
        </Link>
        <nav>
          <Link to="/catalog">Catalog</Link>
          <Link to="/onboarding">My identity</Link>
        </nav>
        <div className="topbar-right">
          {me && <TierBadge tier={me.identityVerification} />}
          {signedIn && (
            <button
              className="link-btn"
              onClick={async () => {
                await signOut();
                navigate("/signin");
              }}
            >
              Sign out
            </button>
          )}
        </div>
      </header>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
