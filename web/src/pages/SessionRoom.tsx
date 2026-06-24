import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { LiveKitRoom, VideoConference } from "@livekit/components-react";
import "@livekit/components-styles";
import { ApiError } from "../api/client";
import { joinSession } from "../api/endpoints";
import type { JoinGrant } from "../api/types";

// SessionRoom exchanges the session id for a LiveKit grant (POST .../join) and
// connects to the SFU. Joining requires the phone_verified tier; below it the
// API returns 403 (the Decree 147 interaction floor).
export function SessionRoom() {
  const { id } = useParams<{ id: string }>();
  const [grant, setGrant] = useState<JoinGrant | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [forbidden, setForbidden] = useState(false);

  useEffect(() => {
    if (!id) return;
    joinSession(id)
      .then(setGrant)
      .catch((e) => {
        if (e instanceof ApiError && e.status === 403) setForbidden(true);
        else setError(e instanceof Error ? e.message : "could not join");
      });
  }, [id]);

  if (forbidden) {
    return (
      <div className="card narrow">
        <h1>Verify to join live</h1>
        <p className="muted">
          Joining a live session needs a verified phone. Add one on{" "}
          <Link to="/onboarding">My identity</Link>.
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card narrow">
        <p className="error">{error}</p>
        <Link to="/catalog">Back to catalog</Link>
      </div>
    );
  }

  if (!grant) return <p className="muted">Joining…</p>;

  return (
    <div className="room">
      <LiveKitRoom
        serverUrl={grant.wsUrl}
        token={grant.token}
        connect
        video
        audio
        data-lk-theme="default"
        style={{ height: "100%" }}
      >
        <VideoConference />
      </LiveKitRoom>
    </div>
  );
}
