import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import type { CloseStep, ModalType, ProtocolStats } from "../types";
import { CONTRACT_ADDRESS, SCORE_CONTRACT_ADDRESS } from "../config";

export type DecryptPhase = "encrypted" | "computing" | "decrypted";

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
  onFinalizeClose: () => void;
  decryptPhase: DecryptPhase;
  decryptedValues: Record<string, string> | null;
}

function EncryptedField({ label, value, index, phase, ciphertextHandle, showOnChain }: {
  label: string; value?: string; index: number; phase: DecryptPhase; ciphertextHandle?: string; showOnChain?: boolean;
}) {
  const isHealth = label === "Health Factor";
  const isAtRisk = isHealth && value === "At Risk";

  return (
    <div className="sl-row">
      <span className="sl-row-label">{label}</span>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 2 }}>
        <AnimatePresence mode="wait">
          {phase === "decrypted" && value ? (
            <motion.span
              key="value"
              initial={{ opacity: 0, filter: "blur(8px)", y: 6 }}
              animate={{ opacity: 1, filter: "blur(0px)", y: 0 }}
              transition={{ duration: 0.4, delay: index * 0.08, ease: "easeOut" }}
              style={{
                color: isHealth
                  ? (isAtRisk ? "var(--danger)" : "var(--enc)")
                  : "var(--enc)",
                fontWeight: 700,
                fontSize: 13,
              }}
            >
              {isHealth ? (isAtRisk ? "⚠ At Risk" : "✓ Healthy") : value}
            </motion.span>
          ) : phase === "computing" ? (
            <motion.span
              key="computing"
              animate={{ opacity: [0.4, 1, 0.4] }}
              transition={{ repeat: Infinity, duration: 1.2 }}
              className="enc-tag"
            >
              decrypting...
            </motion.span>
          ) : (
            <span key="enc" className="enc-shimmer" />
          )}
        </AnimatePresence>
        {/* Ciphertext handle — shows what's actually stored on-chain */}
        {phase === "decrypted" && ciphertextHandle && showOnChain && (
          <motion.span
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.3, delay: index * 0.08 + 0.3 }}
            style={{ fontSize: 9, color: "var(--muted)", fontFamily: "'Space Mono', monospace", opacity: 0.6 }}
            title={ciphertextHandle}
          >
            on-chain: {ciphertextHandle.slice(0, 10)}...{ciphertextHandle.slice(-6)}
          </motion.span>
        )}
      </div>
    </div>
  );
}

function Pipeline({ phase }: { phase: DecryptPhase }) {
  const pct = phase === "encrypted" ? "0%" : phase === "computing" ? "60%" : "100%";
  return (
    <div className="sl-pipeline">
      <span className={`sl-pipeline-step ${phase !== "encrypted" ? "done" : "active"}`}>
        {phase === "encrypted" ? "\uD83D\uDD12" : "\u2713"} Encrypted
      </span>
      <span className="sl-pipeline-arrow">&rarr;</span>
      <span className={`sl-pipeline-step ${phase === "computing" ? "active" : phase === "decrypted" ? "done" : ""}`}>
        {phase === "decrypted" ? "\u2713" : "\uD83E\uDDE0"} FHE Compute
      </span>
      <span className="sl-pipeline-arrow">&rarr;</span>
      <span className={`sl-pipeline-step ${phase === "decrypted" ? "done" : ""}`}>
        {phase === "decrypted" ? "\uD83D\uDD13" : "\uD83D\uDD10"} Output
      </span>
      <div className="sl-pipeline-bar">
        <div className="sl-pipeline-fill" style={{ width: pct }} />
      </div>
    </div>
  );
}

export default function BorrowerCard({
  hasPosition, activeTab, setActiveTab, closeStep,
  loading, fhevmInst, protocolStats, setModal, onDecrypt, onRequestClose, onFinalizeClose,
  decryptPhase, decryptedValues,
}: BorrowerCardProps) {
  const renderCloseSection = () => {
    if (closeStep === "pending") return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10, padding: "14px 0", borderTop: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span className="sl-step-pill pending">&#x23F3; Close Pending</span>
          <span style={{ fontSize: 12, color: "var(--muted)" }}>Debt marked publicly decryptable &mdash; finalize to verify zero and reclaim collateral</span>
        </div>
        <button className="sl-btn-warn" onClick={onFinalizeClose} disabled={loading || !fhevmInst}>
          {loading ? <span className="sl-spinner" /> : "Finalize Close \u2192"}
        </button>
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

  const [showOnChain, setShowOnChain] = useState(false);

  const fields: { label: string; key: string }[] = [
    { label: "Collateral (ETH)", key: "collateral" },
    { label: "Total Debt", key: "debt" },
    { label: "Interest Rate", key: "rate" },
    { label: "Credit Score", key: "score" },
    { label: "Health Factor", key: "health" },
  ];

  return (
    <motion.div
      className="sl-card-glass"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: "easeOut" }}
    >
      <div className="sl-tab-row">
        <button className={`sl-tab ${activeTab === "position" ? "active" : ""}`} onClick={() => setActiveTab("position")}>Position</button>
        <button className={`sl-tab ${activeTab === "protocol" ? "active" : ""}`} onClick={() => setActiveTab("protocol")}>Protocol</button>
      </div>
      {activeTab === "position" ? (
        hasPosition ? (
          <>
            <Pipeline phase={decryptPhase} />
            {fields.map((f, i) => (
              <EncryptedField
                key={f.key}
                label={f.label}
                value={decryptedValues?.[f.key]}
                index={i}
                phase={decryptPhase}
                ciphertextHandle={decryptedValues?.[`_handle_${f.key}`]}
                showOnChain={showOnChain}
              />
            ))}
            <div className="sl-actions">
              <button className="sl-btn" onClick={() => setModal("deposit")} disabled={loading}>+ Deposit</button>
              <button className="sl-btn" onClick={() => setModal("borrow")} disabled={loading}>Borrow</button>
              <button className="sl-btn" onClick={() => setModal("repay")} disabled={loading}>Repay</button>
              <motion.button
                className="sl-btn-ghost"
                onClick={onDecrypt}
                disabled={loading || !fhevmInst || decryptPhase === "computing"}
                whileTap={{ scale: 0.95 }}
                style={{ position: "relative", overflow: "hidden" }}
              >
                {decryptPhase === "computing" && (
                  <motion.span
                    style={{
                      position: "absolute", inset: 0,
                      background: "linear-gradient(90deg, transparent, rgba(139,92,246,0.2), transparent)",
                    }}
                    animate={{ x: ["-100%", "100%"] }}
                    transition={{ repeat: Infinity, duration: 1.2 }}
                  />
                )}
                {decryptPhase === "computing" ? "Decrypting..." : decryptPhase === "decrypted" ? "\uD83D\uDD13 Decrypted" : "\uD83D\uDD13 Decrypt Position"}
              </motion.button>
              {decryptPhase === "decrypted" && (
                <button
                  className="sl-btn-ghost"
                  onClick={() => setShowOnChain(v => !v)}
                  style={{ fontSize: 10, padding: "6px 12px", opacity: 0.7 }}
                >
                  {showOnChain ? "Hide ciphertexts" : "Show on-chain data"}
                </button>
              )}
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
    </motion.div>
  );
}
