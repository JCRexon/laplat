import type { Tier } from "./types";

// The assurance ladder, in order. "pending" is orthogonal (eKYC in flight).
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

export const TIER_UNLOCKS: Record<Tier, string> = {
  none: "Browse the catalog and free recordings.",
  declared: "General features and class schedules.",
  phone_verified: "Join live sessions and 1:1 calls (the Decree 147 floor).",
  verified: "Become an instructor; payments.",
  pending: "Keeps your current tier while eKYC is reviewed.",
};

export function rank(t: Tier): number {
  if (t === "pending") return 0;
  return LADDER.indexOf(t);
}

export function meets(held: Tier, required: Exclude<Tier, "pending">): boolean {
  return rank(held) >= LADDER.indexOf(required);
}

// nextRung returns the first ladder rung the held tier has not yet reached, or
// null when fully verified.
export function nextRung(held: Tier): Exclude<Tier, "pending"> | null {
  for (const r of LADDER) {
    if (!meets(held, r)) return r;
  }
  return null;
}
