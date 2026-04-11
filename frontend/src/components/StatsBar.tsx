import { motion } from "framer-motion";
import type { ProtocolStats } from "../types";

interface StatsBarProps {
  borrowerCount: number;
  hasPosition: boolean;
  protocolStats: ProtocolStats | null;
}

export default function StatsBar({ borrowerCount, hasPosition, protocolStats }: StatsBarProps) {
  return (
    <div className="sl-grid-3">
      {[
        {
          label: "Active Borrowers",
          value: <div className="sl-card-value">{borrowerCount}</div>,
          active: false,
        },
        {
          label: "Your Position",
          value: (
            <div className="sl-card-value">
              {hasPosition ? "Active" : <span style={{ color: "var(--muted)", fontSize: 20, WebkitTextFillColor: "var(--muted)" }}>None</span>}
            </div>
          ),
          active: hasPosition,
        },
        {
          label: "Protocol Reserve",
          value: (
            <>
              <div className="sl-card-value" style={{ fontSize: 20 }}>
                {protocolStats ? `${(Number(protocolStats.protocolReserve) / 1e18).toFixed(4)}` : "\u2014"}
              </div>
              {protocolStats && (
                <div style={{ fontSize: 10, color: "var(--muted)", marginTop: 2 }}>
                  ETH &middot; rate {protocolStats.effectiveRateBps.toString()}bps
                </div>
              )}
            </>
          ),
          active: false,
        },
      ].map((card, i) => (
        <motion.div
          key={card.label}
          className={`sl-card-glass ${card.active ? "sl-stat-active" : ""}`}
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: i * 0.08, ease: "easeOut" }}
        >
          <div className="sl-card-label">{card.label}</div>
          {card.value}
        </motion.div>
      ))}
    </div>
  );
}
