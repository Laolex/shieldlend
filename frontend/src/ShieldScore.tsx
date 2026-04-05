/**
 * ShieldScore — Confidential Credit Score module
 * Extractable: this component + shieldscore-abi.json are self-contained.
 * To use standalone: import ShieldScore from './ShieldScore', pass signer + fhevmInstance.
 */
import { Contract } from "ethers";
import { useState, useCallback } from "react";
import SCORE_ABI from "./shieldscore-abi.json";

// ─── Config — update if deploying separately ─────────────────────────────────
export const SCORE_CONTRACT_ADDRESS = import.meta.env.VITE_SCORE_CONTRACT_ADDRESS ?? "";

// ─── Tier thresholds (mirror contract constants) ─────────────────────────────
export const TIER_PREMIUM  = 800;
export const TIER_STANDARD = 600;

// ─── Types ────────────────────────────────────────────────────────────────────
interface ShieldScoreProps {
  account:    string;
  provider:   any;   // BrowserProvider
  fhevmInst:  any;   // relayer-sdk instance (null if offline)
  isOracle?:  boolean;
  onToast:    (msg: string, kind?: "success" | "error" | "info") => void;
}

interface DisputeState {
  active:    boolean;
  deadline:  number;
}

// ─── Inline styles (scoped to .ss- prefix) ───────────────────────────────────
const SCORE_STYLES = `
  .ss-wrap{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px;margin-bottom:16px;position:relative;overflow:hidden;}
  .ss-wrap::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(79,209,197,0.25),transparent);}
  .ss-title{font-size:10px;font-weight:700;letter-spacing:0.25em;color:var(--muted);text-transform:uppercase;margin-bottom:20px;display:flex;align-items:center;gap:10px;}
  .ss-title::after{content:'';flex:1;height:1px;background:var(--border);}
  .ss-score-display{display:flex;align-items:center;gap:20px;margin-bottom:24px;}
  .ss-score-ring{width:80px;height:80px;border-radius:50%;border:3px solid var(--accent2);display:flex;align-items:center;justify-content:center;flex-direction:column;flex-shrink:0;}
  .ss-score-num{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:var(--accent2);}
  .ss-score-label{font-size:9px;color:var(--muted);letter-spacing:0.15em;}
  .ss-tiers{display:flex;flex-direction:column;gap:8px;flex:1;}
  .ss-tier{display:flex;align-items:center;justify-content:space-between;font-size:12px;padding:8px 12px;border-radius:8px;border:1px solid var(--border);}
  .ss-tier.met{border-color:var(--enc-border);background:var(--enc-bg);}
  .ss-tier.unmet{opacity:0.5;}
  .ss-tier-name{font-weight:700;}
  .ss-tier.met .ss-tier-name{color:var(--enc);}
  .ss-tier.unmet .ss-tier-name{color:var(--muted);}
  .ss-check{font-size:14px;}
  .ss-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px;}
  .ss-enc-banner{display:flex;align-items:center;gap:10px;padding:12px 14px;background:var(--enc-bg);border:1px solid var(--enc-border);border-radius:10px;font-size:12px;color:var(--enc);margin-bottom:16px;}
  .ss-dispute-badge{display:inline-flex;align-items:center;gap:6px;font-size:10px;font-weight:700;letter-spacing:0.12em;padding:3px 10px;border-radius:20px;text-transform:uppercase;color:var(--warn);background:rgba(246,173,85,0.08);border:1px solid rgba(246,173,85,0.25);}
  .ss-oracle-input{width:100%;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:10px 14px;color:var(--text);font-size:13px;font-family:'Space Mono',monospace;margin-bottom:10px;outline:none;transition:border-color 0.2s;}
  .ss-oracle-input:focus{border-color:rgba(79,209,197,0.4);}
  .ss-oracle-input::placeholder{color:var(--muted);}
  .ss-divider{height:1px;background:var(--border);margin:16px 0;}
  .ss-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:12px;}
  .ss-row:last-of-type{border-bottom:none;}
  .ss-muted{color:var(--muted);}
`;

export default function ShieldScore({ account, provider, fhevmInst, isOracle, onToast }: ShieldScoreProps) {
  const [scoreContract, setScoreContract] = useState<Contract | null>(null);
  const [revealedScore,  setRevealedScore]  = useState<bigint | null>(null);
  const [tierPremium,    setTierPremium]    = useState<boolean | null>(null);
  const [tierStandard,   setTierStandard]   = useState<boolean | null>(null);
  const [hasScoreRecord, setHasScoreRecord] = useState<boolean | null>(null);
  const [dispute,        setDispute]        = useState<DisputeState | null>(null);
  const [loading,        setLoading]        = useState(false);

  // Oracle panel state
  const [oracleTarget,   setOracleTarget]   = useState("");
  const [oracleScore,    setOracleScore]    = useState("");

  // ─── Init contract ─────────────────────────────────────────────────────────
  const getContract = useCallback(async (): Promise<Contract | null> => {
    if (!SCORE_CONTRACT_ADDRESS) {
      onToast("VITE_SCORE_CONTRACT_ADDRESS not set", "info");
      return null;
    }
    if (scoreContract) return scoreContract;
    const signer = await provider.getSigner();
    const c = new Contract(SCORE_CONTRACT_ADDRESS, SCORE_ABI, signer);
    setScoreContract(c);
    return c;
  }, [scoreContract, provider, onToast]);

  // ─── Inject styles once ────────────────────────────────────────────────────
  const injectStyles = () => {
    const id = "ss-styles";
    if (!document.getElementById(id)) {
      const el = document.createElement("style");
      el.id = id; el.textContent = SCORE_STYLES;
      document.head.appendChild(el);
    }
  };
  injectStyles();

  // ─── Load score + tiers via re-encryption ──────────────────────────────────
  const loadScore = async () => {
    setLoading(true);
    try {
      const c = await getContract();
      if (!c) return;

      const exists = await c.hasScore(account);
      setHasScoreRecord(exists);

      if (exists) {
        if (fhevmInst) {
          // Re-encrypt own score
          const handle = await c.getEncryptedScore(account);
          const { publicKey, privateKey } = fhevmInst.generateKeypair();
          const eip712  = fhevmInst.createEIP712(publicKey, SCORE_CONTRACT_ADDRESS);
          const signer  = await provider.getSigner();
          const sig     = await signer.signTypedData(
            eip712.domain, { Reencrypt: eip712.types.Reencrypt }, eip712.message
          );
          const score   = await fhevmInst.reencrypt(
            handle, privateKey, publicKey, sig, SCORE_CONTRACT_ADDRESS, account
          );
          setRevealedScore(score);
          setTierPremium(Number(score)  >= TIER_PREMIUM);
          setTierStandard(Number(score) >= TIER_STANDARD);
        }

        const disputeActive   = await c.isDisputeActive(account);
        const disputeDeadline = disputeActive ? Number(await c.disputeDeadline(account)) : 0;
        setDispute({ active: disputeActive, deadline: disputeDeadline });
      }

      onToast("Score loaded");
    } catch (e: any) { onToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  // ─── Open dispute ──────────────────────────────────────────────────────────
  const handleOpenDispute = async () => {
    setLoading(true);
    try {
      const c = await getContract();
      if (!c) return;
      const tx = await c.openDispute(account);
      await tx.wait();
      const deadline = Number(await c.disputeDeadline(account));
      setDispute({ active: true, deadline });
      onToast("Dispute opened — reviewers have 3 days to vote");
    } catch (e: any) { onToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  // ─── Request public score reveal ───────────────────────────────────────────
  const handleRevealPublic = async () => {
    setLoading(true);
    try {
      const c = await getContract();
      if (!c) return;
      const tx = await c.requestScoreReveal(account);
      await tx.wait();
      onToast("Score reveal requested — Zama relayer will publish result", "info");
    } catch (e: any) { onToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  // ─── Oracle: set score ─────────────────────────────────────────────────────
  const handleOracleSetScore = async () => {
    if (!oracleTarget || !oracleScore) return;
    setLoading(true);
    try {
      const c = await getContract();
      if (!c || !fhevmInst) throw new Error("FHE unavailable");
      const input = fhevmInst.createEncryptedInput(SCORE_CONTRACT_ADDRESS, account);
      input.add64(BigInt(oracleScore));
      const r = await input.encrypt();
      const { ethers } = await import("ethers");
      const handle = ethers.hexlify(r.handles[0]);
      const proof  = ethers.hexlify(r.inputProof);
      const tx     = await c.setScore(oracleTarget, handle, proof);
      await tx.wait();
      setOracleTarget(""); setOracleScore("");
      onToast(`Score set for ${oracleTarget.slice(0,6)}...`);
    } catch (e: any) { onToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  // ─── Render ────────────────────────────────────────────────────────────────
  const fmtDeadline = (ts: number) => {
    const d = new Date(ts * 1000);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString();
  };

  const spinnerEl = <span style={{
    display:"inline-block", width:12, height:12,
    border:"2px solid rgba(79,209,197,0.3)", borderTopColor:"var(--accent2)",
    borderRadius:"50%", animation:"spin 0.7s linear infinite"
  }} />;

  return (
    <div className="ss-wrap">
      <div className="ss-title">ShieldScore — Confidential Credit</div>

      {/* Score not loaded yet */}
      {hasScoreRecord === null && (
        <div style={{ textAlign:"center", padding:"20px 0" }}>
          <div style={{ fontSize:12, color:"var(--muted)", marginBottom:16 }}>
            Your credit score stays encrypted on-chain. Only you can decrypt it.
          </div>
          <button
            style={{ background:"var(--accent2)", border:"none", color:"#05080f", borderRadius:8, padding:"10px 20px", fontWeight:700, cursor:"pointer", fontSize:12, fontFamily:"Space Mono,monospace" }}
            onClick={loadScore} disabled={loading}
          >
            {loading ? spinnerEl : "Load My Score →"}
          </button>
        </div>
      )}

      {/* No score record */}
      {hasScoreRecord === false && (
        <div style={{ fontSize:12, color:"var(--muted)", textAlign:"center", padding:"20px 0" }}>
          No score record. An oracle must assign your initial credit score.
        </div>
      )}

      {/* Score loaded */}
      {hasScoreRecord === true && (
        <>
          <div className="ss-enc-banner">
            🔒 Score stored as euint64 ciphertext — visible only to you via re-encryption
          </div>

          <div className="ss-score-display">
            <div className="ss-score-ring">
              {revealedScore !== null
                ? <><div className="ss-score-num">{Number(revealedScore)}</div><div className="ss-score-label">/ 1000</div></>
                : <div className="ss-score-label" style={{ textAlign:"center" }}>🔒<br/>encrypted</div>
              }
            </div>
            <div className="ss-tiers">
              {[
                { label:"Premium",  threshold:TIER_PREMIUM,  benefit:"110% collateral ratio", met:tierPremium },
                { label:"Standard", threshold:TIER_STANDARD, benefit:"130% collateral ratio", met:tierStandard },
                { label:"Base",     threshold:0,             benefit:"150% collateral ratio", met:true },
              ].map(t => (
                <div key={t.label} className={`ss-tier ${t.met ? "met" : "unmet"}`}>
                  <div>
                    <div className="ss-tier-name">{t.label}</div>
                    <div style={{ fontSize:10, color:"var(--muted)", marginTop:2 }}>
                      {t.threshold > 0 ? `Score ≥ ${t.threshold}` : "Default"} — {t.benefit}
                    </div>
                  </div>
                  <span className="ss-check">{t.met ? "✓" : "—"}</span>
                </div>
              ))}
            </div>
          </div>

          {dispute?.active && (
            <div className="ss-dispute-badge" style={{ marginBottom:12 }}>
              ⏳ Dispute active — voting ends {fmtDeadline(dispute.deadline)}
            </div>
          )}

          <div className="ss-actions">
            <button
              style={{ background:"transparent", border:"1px solid var(--border2)", color:"var(--accent2)", borderRadius:8, padding:"8px 16px", fontWeight:700, cursor:"pointer", fontSize:11, fontFamily:"Space Mono,monospace" }}
              onClick={loadScore} disabled={loading}
            >
              {loading ? spinnerEl : "↻ Refresh"}
            </button>
            {!dispute?.active && (
              <button
                style={{ background:"transparent", border:"1px solid rgba(246,173,85,0.3)", color:"var(--warn)", borderRadius:8, padding:"8px 16px", fontWeight:700, cursor:"pointer", fontSize:11, fontFamily:"Space Mono,monospace" }}
                onClick={handleOpenDispute} disabled={loading}
              >
                {loading ? spinnerEl : "Open Dispute"}
              </button>
            )}
            <button
              style={{ background:"transparent", border:"1px solid var(--border2)", color:"var(--muted)", borderRadius:8, padding:"8px 16px", fontWeight:700, cursor:"pointer", fontSize:11, fontFamily:"Space Mono,monospace" }}
              onClick={handleRevealPublic} disabled={loading}
            >
              {loading ? spinnerEl : "Publish Score"}
            </button>
          </div>

          <div className="ss-divider" />
          <div className="ss-row"><span className="ss-muted">Score contract</span>
            <a href={`https://sepolia.etherscan.io/address/${SCORE_CONTRACT_ADDRESS}`} target="_blank" rel="noreferrer"
              style={{ color:"var(--accent2)", fontSize:11, textDecoration:"none", opacity:0.8 }}>
              {SCORE_CONTRACT_ADDRESS.slice(0,10)}...{SCORE_CONTRACT_ADDRESS.slice(-6)} ↗
            </a>
          </div>
          <div className="ss-row"><span className="ss-muted">Dispute duration</span><span style={{ fontSize:12 }}>3 days</span></div>
          <div className="ss-row"><span className="ss-muted">Dispute resolution</span><span style={{ fontSize:12 }}>Encrypted vote tally via FHE.add</span></div>
        </>
      )}

      {/* Oracle panel */}
      {isOracle && (
        <>
          <div className="ss-divider" />
          <div className="ss-title" style={{ marginBottom:14 }}>Oracle Panel</div>
          <input className="ss-oracle-input" placeholder="Borrower address (0x...)"
            value={oracleTarget} onChange={e => setOracleTarget(e.target.value)} />
          <input className="ss-oracle-input" type="number" min="0" max="1000" placeholder="Score (0–1000)"
            value={oracleScore} onChange={e => setOracleScore(e.target.value)} />
          <button
            style={{ background:"var(--accent2)", border:"none", color:"#05080f", borderRadius:8, padding:"10px 18px", fontWeight:700, cursor:"pointer", fontSize:12, fontFamily:"Space Mono,monospace", opacity: (!oracleTarget || !oracleScore || loading) ? 0.4 : 1 }}
            onClick={handleOracleSetScore} disabled={loading || !oracleTarget || !oracleScore}
          >
            {loading ? spinnerEl : "Set Score →"}
          </button>
        </>
      )}
    </div>
  );
}
