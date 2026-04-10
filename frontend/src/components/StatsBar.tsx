import type { ProtocolStats } from "../types";

interface StatsBarProps {
  borrowerCount: number;
  hasPosition: boolean;
  protocolStats: ProtocolStats | null;
}

export default function StatsBar({ borrowerCount, hasPosition, protocolStats }: StatsBarProps) {
  return (
    <div className="sl-grid-3">
      <div className="sl-card">
        <div className="sl-card-label">Active Borrowers</div>
        <div className="sl-card-value">{borrowerCount}</div>
      </div>
      <div className={`sl-card ${hasPosition ? "sl-stat-active" : ""}`}>
        <div className="sl-card-label">Your Position</div>
        <div className="sl-card-value">
          {hasPosition ? "Active" : <span style={{ color: "var(--muted)", fontSize: 20, WebkitTextFillColor: "var(--muted)" }}>None</span>}
        </div>
      </div>
      <div className="sl-card">
        <div className="sl-card-label">Protocol Reserve</div>
        <div className="sl-card-value" style={{ fontSize: 20 }}>
          {protocolStats ? `${(Number(protocolStats.protocolReserve) / 1e18).toFixed(4)}` : "\u2014"}
        </div>
        {protocolStats && (
          <div style={{ fontSize: 10, color: "var(--muted)", marginTop: 2 }}>
            ETH &middot; rate {protocolStats.effectiveRateBps.toString()}bps
          </div>
        )}
      </div>
    </div>
  );
}
