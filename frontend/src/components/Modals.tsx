import { useState } from "react";
import { motion } from "framer-motion";
import { TOKENS, type TokenSymbol } from "../config";

interface DepositModalProps {
  loading: boolean;
  onDeposit: (amount: string, token: TokenSymbol) => void;
  onClose: () => void;
}

export function DepositModal({ loading, onDeposit, onClose }: DepositModalProps) {
  const [amount, setAmount] = useState("");
  const [selectedToken, setSelectedToken] = useState<TokenSymbol>("ETH");

  return (
    <div className="sl-overlay" onClick={onClose}>
      <div className="sl-modal" onClick={e => e.stopPropagation()}>
        <div className="sl-modal-title">Deposit Collateral</div>
        <div className="sl-modal-sub">Select asset. Amount encrypted client-side via Zama FHE before submission.</div>
        <div className="sl-token-grid">
          {TOKENS.map(t => (
            <button
              key={t.symbol}
              className={`sl-token-btn ${selectedToken === t.symbol ? "active" : ""}`}
              onClick={() => { setSelectedToken(t.symbol as TokenSymbol); setAmount(""); }}
            >
              <div className="sl-token-icon" style={{ background: t.color }}>{t.icon}</div>
              <span className="sl-token-symbol">{t.symbol}</span>
              <span className="sl-token-name">{t.name}</span>
            </button>
          ))}
        </div>
        <input
          className="sl-input" type="number" step="0.001" min="0"
          placeholder={`Amount in ${selectedToken}`}
          value={amount} onChange={e => setAmount(e.target.value)} autoFocus
        />
        {selectedToken !== "ETH" && (
          <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 12, marginTop: -8 }}>
            &asymp; {amount ? (Number(amount) * (selectedToken === "USDC" ? 1 / 3000 : 1 / 100)).toFixed(4) : "0"} ETH equivalent &middot; Approve + deposit in 2 txns
          </div>
        )}
        <div style={{ display: "flex", gap: 8 }}>
          <button className="sl-btn" style={{ flex: 1 }} disabled={loading || !amount} onClick={() => onDeposit(amount, selectedToken)}>
            {loading ? <span className="sl-spinner" /> : `Deposit ${selectedToken} \u2192`}
          </button>
          <button className="sl-btn-ghost" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

interface AmountModalProps {
  type: "borrow" | "repay";
  loading: boolean;
  onSubmit: (amount: string) => void;
  onClose: () => void;
}

export function AmountModal({ type, loading, onSubmit, onClose }: AmountModalProps) {
  const [amount, setAmount] = useState("");
  const title = type === "borrow" ? "Borrow Against Collateral" : "Repay Debt";
  const sub = type === "borrow"
    ? "Borrow up to 66% of collateral value. Health factor enforced via encrypted comparison."
    : "Partial or full repayment. Encrypted subtraction with floor-at-zero applied on-chain.";

  return (
    <div className="sl-overlay" onClick={onClose}>
      <div className="sl-modal" onClick={e => e.stopPropagation()}>
        <div className="sl-modal-title">{title}</div>
        <div className="sl-modal-sub">{sub}</div>
        <input className="sl-input" type="number" step="0.001" min="0" placeholder="Amount in ETH (e.g. 0.1)"
          value={amount} onChange={e => setAmount(e.target.value)} autoFocus />
        <div style={{ display: "flex", gap: 8 }}>
          <button className="sl-btn" style={{ flex: 1 }} disabled={loading || !amount}
            onClick={() => onSubmit(amount)}>
            {loading ? <span className="sl-spinner" /> : type === "borrow" ? "Borrow \u2192" : "Repay \u2192"}
          </button>
          <button className="sl-btn-ghost" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

interface ScoreModalProps {
  loading: boolean;
  onSubmit: (addr: string, score: string) => void;
  onClose: () => void;
}

export function ScoreModal({ loading, onSubmit, onClose }: ScoreModalProps) {
  const [scoreAddr, setScoreAddr] = useState("");
  const [scoreTarget, setScoreTarget] = useState("");

  return (
    <div className="sl-overlay" onClick={onClose}>
      <div className="sl-modal" onClick={e => e.stopPropagation()}>
        <div className="sl-modal-title">Update Credit Score</div>
        <div className="sl-modal-sub">Score encrypted before submission (0&ndash;1000). Higher score reduces interest rate. Admin only.</div>
        <input className="sl-input" type="text" placeholder="Borrower address (0x...)"
          value={scoreAddr} onChange={e => setScoreAddr(e.target.value)} />
        <input className="sl-input" type="number" min="0" max="1000" placeholder="Score (0-1000)"
          value={scoreTarget} onChange={e => setScoreTarget(e.target.value)} autoFocus />
        <div style={{ display: "flex", gap: 8 }}>
          <button className="sl-btn" style={{ flex: 1 }} disabled={loading || !scoreAddr || !scoreTarget}
            onClick={() => onSubmit(scoreAddr, scoreTarget)}>
            {loading ? <span className="sl-spinner" /> : "Set Score \u2192"}
          </button>
          <button className="sl-btn-ghost" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

interface ResultModalProps {
  resultMsg: string;
  onClose: () => void;
}

export function ResultModal({ resultMsg, onClose }: ResultModalProps) {
  const lines = resultMsg.split("\n").filter(Boolean);

  return (
    <motion.div
      className="sl-overlay"
      onClick={onClose}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.15 }}
    >
      <motion.div
        className="sl-modal"
        onClick={e => e.stopPropagation()}
        initial={{ opacity: 0, y: 24, scale: 0.96 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.3, ease: "easeOut" }}
      >
        <div className="sl-modal-title">&#x1F513; Decrypted Position</div>
        <div className="sl-modal-sub">Re-encrypted via Zama KMS &mdash; decrypted locally with your wallet keypair.</div>
        <div className="sl-result-pre">
          {lines.map((line, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, filter: "blur(8px)", y: 6 }}
              animate={{ opacity: 1, filter: "blur(0px)", y: 0 }}
              transition={{ duration: 0.4, delay: 0.15 + i * 0.08, ease: "easeOut" }}
            >
              {line}
            </motion.div>
          ))}
        </div>
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.15 + lines.length * 0.08 + 0.2 }}
          style={{ fontSize: 11, color: "var(--enc)", marginTop: 12, display: "flex", alignItems: "center", gap: 6 }}
        >
          &#x2713; Verified private computation via FHE
        </motion.div>
        <button className="sl-btn" style={{ marginTop: 16, width: "100%" }} onClick={onClose}>Close</button>
      </motion.div>
    </motion.div>
  );
}
