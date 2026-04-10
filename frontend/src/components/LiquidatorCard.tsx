import type { BorrowerEntry, ModalType } from "../types";

interface LiquidatorCardProps {
  borrowers: BorrowerEntry[];
  isAdmin: boolean;
  loading: boolean;
  setModal: (m: ModalType) => void;
  onRequestReveal: (addr: string) => void;
  onLiquidate: (addr: string) => void;
  onAccrueInterest: (addr: string) => void;
  onEmergencyLiquidate: (addr: string) => void;
}

export default function LiquidatorCard({
  borrowers, isAdmin, loading, setModal,
  onRequestReveal, onLiquidate, onAccrueInterest, onEmergencyLiquidate,
}: LiquidatorCardProps) {
  const renderEntry = (b: BorrowerEntry) => (
    <div className="sl-borrower-item" key={b.address}>
      <div className="sl-borrower-row">
        <div>
          <div style={{ fontSize: 12, fontFamily: "Space Mono,monospace", marginBottom: 6 }}>
            {b.address.slice(0, 10)}...{b.address.slice(-6)}
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <span className="enc-tag">&#x1F512; health factor encrypted</span>
            {b.pendingReveal && <span className="sl-step-pill pending">reveal pending</span>}
            {b.confirmedLiq && <span className="sl-step-pill danger">confirmed liq</span>}
            {b.pendingClose && <span className="sl-step-pill pending">close pending</span>}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {!b.pendingReveal && !b.confirmedLiq && (
            <button className="sl-btn-ghost" onClick={() => onRequestReveal(b.address)} disabled={loading} style={{ fontSize: 11 }}>
              &#x1F50D; Request Reveal
            </button>
          )}
          {b.pendingReveal && !b.confirmedLiq && (
            <span style={{ fontSize: 11, color: "var(--muted)", padding: "8px 0" }}>Awaiting relayer...</span>
          )}
          {b.confirmedLiq && (
            <button className="sl-btn-danger" onClick={() => onLiquidate(b.address)} disabled={loading}>
              {loading ? <span className="sl-spinner" /> : "Liquidate \u21AF"}
            </button>
          )}
          {isAdmin && (
            <button className="sl-btn-warn" onClick={() => onAccrueInterest(b.address)} disabled={loading} style={{ fontSize: 11 }}>
              + Interest
            </button>
          )}
          {isAdmin && (
            <button className="sl-btn-danger" onClick={() => onEmergencyLiquidate(b.address)} disabled={loading} style={{ fontSize: 11 }}>
              &#x26A1; Emergency
            </button>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <div className="sl-card">
      <div className="sl-section-title">Active Positions ({borrowers.length})</div>
      {isAdmin && (
        <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 16 }}>
          <button className="sl-btn-warn" onClick={() => setModal("score")} disabled={loading} style={{ fontSize: 11 }}>
            Update Credit Score
          </button>
        </div>
      )}
      {borrowers.length === 0
        ? <div className="sl-empty"><div className="sl-empty-icon">&#x2713;</div>No active positions</div>
        : borrowers.map(renderEntry)
      }
    </div>
  );
}
