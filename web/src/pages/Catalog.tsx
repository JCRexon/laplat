import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listSessions, publishedClasses } from "../api/endpoints";
import { ApiError } from "../api/client";
import type { ClassView, SessionSummary } from "../api/types";

export function Catalog() {
  const [classes, setClasses] = useState<ClassView[]>([]);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  // Listing sessions requires the declared tier; below it the API returns 403.
  const [sessionsLocked, setSessionsLocked] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        setClasses(await publishedClasses());
      } catch (e) {
        setError(e instanceof Error ? e.message : "could not load catalog");
      }
      try {
        setSessions(await listSessions());
      } catch (e) {
        if (e instanceof ApiError && e.status === 403) setSessionsLocked(true);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) return <p className="muted">Loading…</p>;

  return (
    <div className="stack">
      <section className="card">
        <h1>Classes</h1>
        {classes.length === 0 ? (
          <p className="muted">No published classes yet.</p>
        ) : (
          <ul className="list">
            {classes.map((c) => (
              <li key={c.id}>
                <strong>{c.title}</strong>
                <p className="muted small">{c.description}</p>
              </li>
            ))}
          </ul>
        )}
        {error && <p className="error">{error}</p>}
      </section>

      <section className="card">
        <h2>Live & scheduled sessions</h2>
        {sessionsLocked ? (
          <p className="muted">
            Verify you're 18+ on <Link to="/onboarding">My identity</Link> to see session schedules.
          </p>
        ) : sessions.length === 0 ? (
          <p className="muted">No sessions right now.</p>
        ) : (
          <ul className="list">
            {sessions.map((s) => (
              <li key={s.sessionId} className="row spread">
                <span>
                  <strong>{s.kind}</strong> · {s.status}
                </span>
                {s.status === "live" && (
                  <Link className="btn-link" to={`/room/${s.sessionId}`}>
                    Join
                  </Link>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
