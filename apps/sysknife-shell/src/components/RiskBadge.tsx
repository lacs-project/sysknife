import type React from "react";

interface Props {
  level: "low" | "medium" | "high";
}

const STYLES: Record<"low" | "medium" | "high", React.CSSProperties> = {
  low:    { background: "#166534", color: "#4ade80" },
  medium: { background: "#7c2d12", color: "#fb923c" },
  high:   { background: "#7f1d1d", color: "#f87171" },
};

export function RiskBadge({ level }: Props) {
  return (
    <span className="risk-badge" style={STYLES[level]} aria-label={`${level} risk`}>
      ● {level.toUpperCase()}
    </span>
  );
}
