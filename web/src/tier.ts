import type { Tier } from "./api/types";

// The assurance ladder, in order. "pending" is orthogonal (an eKYC check in
// flight) and is handled separately, not as a rung.
export const LADDER: Exclude<Tier, "pending">[] = [
  "none",
  "declared",
  "phone_verified",
  "verified",
];

export const TIER_LABEL: Record<Tier, string> = {
  none: "Browsing",
  declared: "Declared (18+)",
  phone_verified: "Phone verified",
  verified: "ID verified",
  pending: "Verification pending",
};

// What each tier unlocks (mirrors ACCESS-MODEL.md).
export const TIER_UNLOCKS: Record<Tier, string> = {
  none: "Browse the catalog and free recordings.",
  declared: "General features and class schedules.",
  phone_verified: "Join live sessions and 1:1 calls (the Decree 147 floor).",
  verified: "Become an instructor; payments.",
  pending: "Keeps your current tier while eKYC is reviewed.",
};

export function rank(t: Tier): number {
  // pending ranks alongside its underlying tier for gating purposes; treat it
  // as below declared for "what can I do now" display.
  if (t === "pending") return 0;
  return LADDER.indexOf(t);
}

// meets reports whether the held tier satisfies a required rung.
export function meets(held: Tier, required: Exclude<Tier, "pending">): boolean {
  return rank(held) >= LADDER.indexOf(required);
}
