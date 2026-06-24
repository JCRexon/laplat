// DTOs mirror the authd JSON contracts (see internal/auth, internal/class,
// internal/session HTTP handlers). Field names match the Go `json:` tags.

// The cumulative assurance ladder (pkg/contracts/token.go). Ordered
// none < declared < phone_verified < verified; "pending" is orthogonal.
export type Tier =
  | "none"
  | "declared"
  | "phone_verified"
  | "verified"
  | "pending";

export type Capability = "can_instruct" | "platform_moderator";

// Returned by the login/verify and refresh endpoints.
export interface Session {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: number; // unix seconds
  refreshExpiresAt: number;
}

// GET /v1/me
export interface Me {
  userId: string;
  identityVerification: Tier;
  capabilities: Capability[];
}

// GET /v1/classes/published
export interface ClassView {
  id: string;
  title: string;
  description: string;
  status: string;
}

// GET /v1/sessions
export interface SessionSummary {
  sessionId: string;
  kind: string;
  status: string;
  room: string;
}

// POST /v1/sessions/{id}/join — the LiveKit connection grant.
export interface JoinGrant {
  sessionId: string;
  room: string;
  role: string;
  token: string; // LiveKit access token
  wsUrl: string; // LiveKit SFU URL
}

// POST /v1/identity/verify/begin — eKYC handoff (provider not wired in dev).
export interface VerifyBegin {
  verificationId?: string;
  redirectUrl?: string;
}
