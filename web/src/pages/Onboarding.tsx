import { useState } from "react";
import {
  applyInstructor,
  attestAdult,
  beginVerify,
  requestPhoneCode,
  verifyPhoneCode,
} from "../api/endpoints";
import { useAuth } from "../auth/AuthContext";
import { LADDER, TIER_LABEL, TIER_UNLOCKS, meets } from "../tier";
import { TierBadge } from "../components/TierBadge";

export function Onboarding() {
  const { me, refreshMe } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Phone sub-flow state.
  const [phoneStep, setPhoneStep] = useState<"idle" | "code">("idle");
  const [phone, setPhone] = useState("");
  const [phoneCode, setPhoneCode] = useState("");

  // eKYC handoff target (provider not wired in dev).
  const [verifyUrl, setVerifyUrl] = useState<string | null>(null);

  if (!me) return null;
  const tier = me.identityVerification;

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await refreshMe();
    } catch (e) {
      setError(e instanceof Error ? e.message : "something went wrong");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <div className="row spread">
        <h1>Your identity</h1>
        <TierBadge tier={tier} />
      </div>
      <p className="muted">
        Assurance climbs with what you want to do. Each step proves a little more.
      </p>

      <ol className="ladder">
        {LADDER.map((rung) => {
          const reached = meets(tier, rung);
          const isNext = !reached && LADDER.indexOf(rung) === LADDER.findIndex((r) => !meets(tier, r));
          return (
            <li key={rung} className={reached ? "rung done" : isNext ? "rung next" : "rung"}>
              <div className="rung-head">
                <span className="check">{reached ? "✓" : isNext ? "→" : "•"}</span>
                <strong>{TIER_LABEL[rung]}</strong>
              </div>
              <p className="muted small">{TIER_UNLOCKS[rung]}</p>

              {isNext && rung === "declared" && (
                <button disabled={busy} onClick={() => run(attestAdult)}>
                  I confirm I am 18 or older
                </button>
              )}

              {isNext && rung === "phone_verified" && (
                <div className="subflow">
                  {phoneStep === "idle" ? (
                    <>
                      <input
                        placeholder="+84…"
                        value={phone}
                        onChange={(e) => setPhone(e.target.value)}
                      />
                      <button
                        disabled={busy || !phone}
                        onClick={async () => {
                          setBusy(true);
                          setError(null);
                          try {
                            await requestPhoneCode(phone);
                            setPhoneStep("code");
                          } catch (e) {
                            setError(e instanceof Error ? e.message : "could not send code");
                          } finally {
                            setBusy(false);
                          }
                        }}
                      >
                        Send code
                      </button>
                    </>
                  ) : (
                    <>
                      <input
                        inputMode="numeric"
                        placeholder="123456"
                        value={phoneCode}
                        onChange={(e) => setPhoneCode(e.target.value)}
                      />
                      <button
                        disabled={busy || !phoneCode}
                        onClick={() => run(() => verifyPhoneCode(phone, phoneCode))}
                      >
                        Verify phone
                      </button>
                    </>
                  )}
                </div>
              )}

              {isNext && rung === "verified" && (
                <div className="subflow">
                  <button
                    disabled={busy}
                    onClick={() =>
                      run(async () => {
                        const r = await beginVerify();
                        setVerifyUrl(r.redirectUrl ?? null);
                      })
                    }
                  >
                    Start ID verification (eKYC)
                  </button>
                  {verifyUrl && (
                    <p className="muted small">
                      Continue at your eKYC provider: <code>{verifyUrl}</code>
                    </p>
                  )}
                  <p className="muted small">
                    Note: the eKYC provider isn't wired in local dev — this starts the handoff only.
                  </p>
                </div>
              )}
            </li>
          );
        })}
      </ol>

      {tier === "pending" && (
        <p className="muted">Your ID verification is under review. You keep your current access meanwhile.</p>
      )}

      {tier === "verified" && (
        <div className="subflow">
          <h2>Teach on laplat</h2>
          {me.capabilities.includes("can_instruct") ? (
            <p className="muted">You're an instructor — you can create and host classes.</p>
          ) : (
            <button disabled={busy} onClick={() => run(applyInstructor)}>
              Become an instructor
            </button>
          )}
        </div>
      )}

      {error && <p className="error">{error}</p>}
    </div>
  );
}
