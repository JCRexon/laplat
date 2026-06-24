// DTOs mirror the authd JSON contracts (internal/auth, internal/class,
// internal/session). Field names match the Go `json:` tags.

// Cumulative assurance ladder (pkg/contracts/token.go):
// none < declared < phone_verified < verified; "pending" is orthogonal.
export type Tier = "none" | "declared" | "phone_verified" | "verified" | "pending";

export type Capability = "can_instruct" | "platform_moderator";

export interface Session {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
}

export interface Me {
  userId: string;
  identityVerification: Tier;
  capabilities: Capability[];
}

export interface ClassView {
  id: string;
  title: string;
  description: string;
  status: string;
}

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
  token: string;
  wsUrl: string;
}

export interface VerifyBegin {
  verificationId?: string;
  redirectUrl?: string;
}
