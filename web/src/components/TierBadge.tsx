import type { Tier } from "../api/types";
import { TIER_LABEL } from "../tier";

const COLOR: Record<Tier, string> = {
  none: "#6b7280",
  declared: "#0ea5e9",
  phone_verified: "#6366f1",
  verified: "#16a34a",
  pending: "#d97706",
};

export function TierBadge({ tier }: { tier: Tier }) {
  return (
    <span className="badge" style={{ background: COLOR[tier] }}>
      {TIER_LABEL[tier]}
    </span>
  );
}
