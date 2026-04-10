import type { CloseStep, ModalType, ProtocolStats } from "../types";
import { CONTRACT_ADDRESS, SCORE_CONTRACT_ADDRESS } from "../config";

interface BorrowerCardProps {
  hasPosition: boolean;
  activeTab: "position" | "protocol";
  setActiveTab: (tab: "position" | "protocol") => void;
  closeStep: CloseStep;
  loading: boolean;
  fhevmInst: any;
  protocolStats: ProtocolStats | null;
  setModal: (m: ModalType) => void;
  onDecrypt: () => void;
  onRequestClose: () => void;
}

export default function BorrowerCard({
  hasPosition, activeTab, setActiveTab, closeStep,
  loading, fhevmInst, protocolStats, setModal, onDecrypt, onRequestClose,
}: BorrowerCardProps) {
  const renderCloseSection = () => {
    if (closeStep === "pending") return (
      <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 0", borderTop: "1px solid var(--border)" }}>
        <span className="sl-step-pill pending">&#x23F3; Close Pending</span>
        <span style={{ fontSize: 12, color: "var(--muted)" }}>Zama relayer is verifying zero-debt &mdash; position will close automatically</span>
      </div>
    );
    return (
      <div style={{ padding: "14px 0", borderTop: "1px solid var(--border)" }}>
        <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 10 }}>
          Withdraw your collateral ETH &mdash; requires zero debt. Relayer verifies on-chain.
        </div>
        <button className="sl-btn-warn" onClick={onRequestClose} disabled={loading}>
          {loading ? <span className="sl-spinner" /> : "Request Close Position"}
        </button>
      </div>
    );
  };

  return (
    <div className="sl-card">
      <div className="sl-tab-row">
        <button className={`sl-tab ${activeTab === "position" ? "active" : ""}`} onClick={() => setActiveTab("position")}>Position</button>
        <button className={`sl-tab ${activeTab === "protocol" ? "active" : ""}`} onClick={() => setActiveTab("protocol")}>Protocol</button>
      </div>
      {activeTab === "position" ? (
        hasPosition ? (
          <>
            <div className="sl-row"><span className="sl-row-label">Collateral (ETH)</span><span className="enc-tag">&#x1F512; euint64</span></div>
            <div className="sl-row"><span className="sl-row-label">Total Debt</span><span className="enc-tag">&#x1F512; euint64</span></div>
            <div className="sl-row"><span className="sl-row-label">Interest Rate</span><span className="enc-tag">&#x1F512; euint64</span></div>
            <div className="sl-row"><span className="sl-row-label">Credit Score</span><span className="enc-tag">&#x1F512; euint64</span></div>
            <div className="sl-row"><span className="sl-row-label">Health Factor</span><span className="enc-tag">&#x1F512; ebool</span></div>
            <div className="sl-actions">
              <button className="sl-btn" onClick={() => setModal("deposit")} disabled={loading}>+ Deposit</button>
              <button className="sl-btn" onClick={() => setModal("borrow")} disabled={loading}>Borrow</button>
              <button className="sl-btn" onClick={() => setModal("repay")} disabled={loading}>Repay</button>
              <button className="sl-btn-ghost" onClick={onDecrypt} disabled={loading || !fhevmInst}>
                {loading ? <span className="sl-spinner" /> : "\uD83D\uDD13 Decrypt Position"}
              </button>
            </div>
            {renderCloseSection()}
          </>
        ) : (
          <div className="sl-empty">
            <div className="sl-empty-icon">&#x1F3E6;</div>
            <div style={{ marginBottom: 20 }}>No active position. Deposit ETH collateral to get started.</div>
            <button className="sl-btn" onClick={() => setModal("deposit")}>Deposit Collateral &rarr;</button>
          </div>
        )
      ) : (
        <>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 13 }}>Effective Rate</span>
            <span style={{ fontSize: 13 }}>{protocolStats ? `${protocolStats.effectiveRateBps} bps (${Number(protocolStats.effectiveRateBps) / 100}%)` : "500 bps"}</span>
          </div>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 13 }}>Protocol Reserve</span>
            <span style={{ fontSize: 13 }}>{protocolStats ? `${(Number(protocolStats.protocolReserve) / 1e18).toFixed(6)} ETH` : "\u2014"}</span>
          </div>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 13 }}>Total Reserves</span>
            <span style={{ fontSize: 13 }}>{protocolStats ? `${(Number(protocolStats.totalReserves) / 1e18).toFixed(6)} ETH` : "\u2014"}</span>
          </div>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 13 }}>Supply Cap</span>
            <span style={{ fontSize: 13 }}>{protocolStats ? (protocolStats.ethSupplyCap === 0n ? "uncapped" : `${(Number(protocolStats.ethSupplyCap) / 1e18).toFixed(4)} ETH`) : "\u2014"}</span>
          </div>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 13 }}>Reserve Factor</span>
            <span style={{ fontSize: 13 }}>{protocolStats ? `${protocolStats.reserveFactorBps} bps (${Number(protocolStats.reserveFactorBps) / 100}%)` : "\u2014"}</span>
          </div>
          <div className="sl-info-row"><span style={{ color: "var(--muted)", fontSize: 13 }}>Network</span><span style={{ fontSize: 13 }}>Sepolia Testnet</span></div>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 13 }}>Lending Contract</span>
            <a href={`https://sepolia.etherscan.io/address/${CONTRACT_ADDRESS}`} target="_blank" rel="noreferrer" className="sl-contract-link">
              {CONTRACT_ADDRESS.slice(0, 10)}...{CONTRACT_ADDRESS.slice(-6)} &nearr;
            </a>
          </div>
          {SCORE_CONTRACT_ADDRESS && (
            <div className="sl-info-row">
              <span style={{ color: "var(--muted)", fontSize: 13 }}>ShieldScore Contract</span>
              <a href={`https://sepolia.etherscan.io/address/${SCORE_CONTRACT_ADDRESS}`} target="_blank" rel="noreferrer" className="sl-contract-link">
                {SCORE_CONTRACT_ADDRESS.slice(0, 10)}...{SCORE_CONTRACT_ADDRESS.slice(-6)} &nearr;
              </a>
            </div>
          )}
        </>
      )}
    </div>
  );
}
