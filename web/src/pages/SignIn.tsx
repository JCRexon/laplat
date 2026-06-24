import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { requestEmailCode, verifyEmailCode } from "../api/endpoints";
import { useAuth } from "../auth/AuthContext";

// Email-OTP sign-in. In dev the console code sender logs the code to authd's
// output, so the loop runs without an SMTP vendor.
export function SignIn() {
  const { onSignedIn } = useAuth();
  const navigate = useNavigate();
  const [step, setStep] = useState<"email" | "code">("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function send() {
    setBusy(true);
    setError(null);
    try {
      await requestEmailCode(email);
      setStep("code");
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not send code");
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    setBusy(true);
    setError(null);
    try {
      await verifyEmailCode(email, code);
      await onSignedIn();
      navigate("/onboarding");
    } catch (e) {
      setError(e instanceof Error ? e.message : "invalid code");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card narrow">
      <h1>Sign in</h1>
      <p className="muted">
        Sign in with your email. We'll send a one-time code.
      </p>
      {step === "email" ? (
        <>
          <input
            type="email"
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && email && send()}
          />
          <button disabled={!email || busy} onClick={send}>
            {busy ? "Sending…" : "Send code"}
          </button>
        </>
      ) : (
        <>
          <p className="muted">Code sent to {email} (check authd's console in dev).</p>
          <input
            inputMode="numeric"
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && code && verify()}
          />
          <button disabled={!code || busy} onClick={verify}>
            {busy ? "Verifying…" : "Verify & continue"}
          </button>
          <button className="link-btn" onClick={() => setStep("email")}>
            Use a different email
          </button>
        </>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
