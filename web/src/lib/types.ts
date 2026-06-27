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
  enrolled?: boolean;
}

export interface SessionSummary {
  sessionId: string;
  kind: string;
  status: string;
  room: string;
  scheduledStart?: string; // RFC3339
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

// GET /v1/moderation/users — user list for the moderation dashboard.
export interface UserSummary {
  id: string;
  handle: string;
  displayName: string;
  status: string;
  canInstruct: boolean;
  isPlatformModerator: boolean;
}

// GET /v1/me/identities — login methods linked to the account.
export interface IdentityFactors {
  email: string | null;
  phone: string | null;
  federated: string[];
}

// GET /v1/me/sessions — participation history entry.
export interface SessionHistoryEntry {
  sessionId: string;
  kind: string;
  status: string;
  role: string;
  joinedAt: string; // RFC3339
  leftAt: string | null; // RFC3339
  classId: string | null;
  classTitle: string | null;
  scheduledStart: string | null; // RFC3339
  durationMinutes: number | null;
}

// GET /v1/me/consents — consent ledger entry.
export interface ConsentHistoryEntry {
  id: string;
  sessionId: string;
  purpose: string;
  granted: boolean;
  grantedAt: string; // RFC3339
}

// GET /v1/me/login-events — recent authentication activity.
export interface LoginEvent {
  id: string;
  method: string; // 'email' | 'phone' | 'google' | 'apple' | 'zalo'
  createdAt: string; // RFC3339
}

// GET /v1/me/progress — attendance per enrolled class.
export interface ClassProgress {
  classId: string;
  title: string;
  totalSessions: number;
  attended: number;
}

// GET /v1/me/completions — per-class completion + the learner's name for certs.
export interface ClassCompletion {
  classId: string;
  title: string;
  instructorName: string;
  totalSessions: number;
  endedSessions: number;
  attendedEnded: number;
  complete: boolean;
  completedAt: string | null; // RFC3339
}

export interface CompletionsResponse {
  learnerName: string;
  completions: ClassCompletion[];
}

// GET /v1/me/stepup/request — which factor a step-up code went to.
export interface StepUpChannel {
  channel: string; // 'phone' | 'email'
  hint: string; // masked target
}

// GET /v1/me/data-export — consolidated right-of-access view.
export interface DataExport {
  profile: {
    userId: string;
    handle: string;
    displayName: string;
    bio: string;
    locale: string;
    status: string;
    createdAt: string;
  };
  identity: {
    verificationStatus: string;
    isAdult: boolean;
    verifiedAt: string | null;
    retainUntil: string | null;
    fullNameOnFile: boolean;
    dobOnFile: boolean;
    emailOnFile: boolean;
  };
  loginMethods: {
    email: string | null;
    phone: string | null;
    federated: string[];
  };
  enrolledClasses: { id: string; title: string; status: string }[];
  tosAcceptances: { version: string; adultAttested: boolean; acceptedAt: string }[];
  activity: { sessionCount: number; consentCount: number };
}

// GET /v1/recordings/sessions/{id}/playback — completed recordings (free tier).
export interface RecordingView {
  id: string;
  sessionId: string;
  status: string;
  startedAt: number;
  endedAt?: number;
  outputUri?: string;
  playbackUrl?: string;
}
