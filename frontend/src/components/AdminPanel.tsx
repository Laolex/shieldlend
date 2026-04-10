import { parseEther } from "ethers";
import type { Contract } from "ethers";
import { useState } from "react";
import type { BorrowerEntry, ProtocolStats } from "../types";

interface AdminPanelProps {
  contract: Contract;
  borrowers: BorrowerEntry[];
  protocolStats: ProtocolStats | null;
  loading: boolean;
  setLoading: (v: boolean) => void;
  showToast: (msg: string, kind?: "success" | "error" | "info") => void;
  onRefreshStats: () => void;
  onEmergencyLiquidate: (addr: string) => void;
}

type AdminTab = "reserve" | "rate" | "caps" | "emergency";

export default function AdminPanel({
  contract, borrowers, protocolStats, loading, setLoading,
  showToast, onRefreshStats, onEmergencyLiquidate,
}: AdminPanelProps) {
  const [adminTab, setAdminTab] = useState<AdminTab>("reserve");
  const [adminA, setAdminA] = useState("");
  const [adminB, setAdminB] = useState("");
  const [adminC, setAdminC] = useState("");

  const resetInputs = () => { setAdminA(""); setAdminB(""); setAdminC(""); };

  const handleReplenishReserve = async () => {
    if (!adminA) return;
    setLoading(true);
    try {
      const tx = await contract.replenishReserve({ value: parseEther(adminA) });
      await tx.wait();
      setAdminA("");
      showToast(`Reserve topped up with ${adminA} ETH`);
      onRefreshStats();
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleSetRateParams = async () => {
    if (!adminA || !adminB || !adminC) return;
    setLoading(true);
    try {
      const tx = await contract.setRateParams(Number(adminA), Number(adminB), Number(adminC));
      await tx.wait();
      resetInputs();
      showToast("Rate model updated");
      onRefreshStats();
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleSetReserveParams = async () => {
    if (!adminA || !adminB) return;
    setLoading(true);
    try {
      const tx = await contract.setReserveParams(BigInt(adminA), BigInt(adminB));
      await tx.wait();
      setAdminA(""); setAdminB("");
      showToast("Reserve params updated");
      onRefreshStats();
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleSetCaps = async () => {
    setLoading(true);
    try {
      const supCap = adminA ? parseEther(adminA) : 0n;
      const borCap = adminB ? parseEther(adminB) : 0n;
      const tx = await contract.setCaps(supCap, borCap);
      await tx.wait();
      setAdminA(""); setAdminB("");
      showToast("Caps updated (0 = uncapped)");
      onRefreshStats();
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const fmtEth = (v: bigint) => v === 0n ? "uncapped" : `${(Number(v) / 1e18).toFixed(4)} ETH`;
  const s = protocolStats;

  return (
    <div className="sl-card sl-admin-card">
      <div className="sl-section-title" style={{ color: "var(--warn)" }}>Admin Panel</div>
      <div className="sl-tab-row">
        {(["reserve", "rate", "caps", "emergency"] as const).map(t => (
          <button key={t} className={`sl-tab ${adminTab === t ? "active" : ""}`}
            onClick={() => { setAdminTab(t); resetInputs(); }}>
            {t === "reserve" ? "Reserve" : t === "rate" ? "Rate Model" : t === "caps" ? "Caps" : "Emergency"}
          </button>
        ))}
      </div>

      {adminTab === "reserve" && (
        <>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 12 }}>Protocol Reserve</span>
            <span style={{ fontSize: 13, color: "var(--accent2)" }}>{s ? `${(Number(s.protocolReserve) / 1e18).toFixed(6)} ETH` : "\u2014"}</span>
          </div>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 12 }}>Total Reserves</span>
            <span style={{ fontSize: 13 }}>{s ? `${(Number(s.totalReserves) / 1e18).toFixed(6)} ETH` : "\u2014"}</span>
          </div>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 12 }}>Reserve Factor</span>
            <span style={{ fontSize: 13 }}>{s ? `${s.reserveFactorBps} bps` : "\u2014"}</span>
          </div>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 12 }}>Min Reserve Ratio</span>
            <span style={{ fontSize: 13 }}>{s ? (s.minReserveRatioBps === 0n ? "disabled" : `${s.minReserveRatioBps} bps`) : "\u2014"}</span>
          </div>
          <div className="sl-divider" />
          <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 8 }}>Replenish Reserve</div>
          <div style={{ display: "flex", gap: 8 }}>
            <input className="sl-input" style={{ marginBottom: 0 }} type="number" step="0.001" min="0"
              placeholder="ETH amount" value={adminA} onChange={e => setAdminA(e.target.value)} />
            <button className="sl-btn" disabled={loading || !adminA} onClick={handleReplenishReserve} style={{ whiteSpace: "nowrap" }}>
              {loading ? <span className="sl-spinner" /> : "Top Up"}
            </button>
          </div>
          <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 16, marginBottom: 8 }}>Set Reserve Params (factor bps, min ratio bps)</div>
          <div style={{ display: "flex", gap: 8 }}>
            <input className="sl-input" style={{ marginBottom: 0 }} type="number" placeholder="Factor bps (e.g. 200)" value={adminA} onChange={e => setAdminA(e.target.value)} />
            <input className="sl-input" style={{ marginBottom: 0 }} type="number" placeholder="Min ratio bps (0=off)" value={adminB} onChange={e => setAdminB(e.target.value)} />
            <button className="sl-btn" disabled={loading || !adminA || !adminB} onClick={handleSetReserveParams} style={{ whiteSpace: "nowrap" }}>
              {loading ? <span className="sl-spinner" /> : "Set"}
            </button>
          </div>
        </>
      )}

      {adminTab === "rate" && (
        <>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 12 }}>Effective Rate</span>
            <span style={{ fontSize: 13, color: "var(--accent2)" }}>{s ? `${s.effectiveRateBps} bps (${Number(s.effectiveRateBps) / 100}%)` : "\u2014"}</span>
          </div>
          <div className="sl-divider" />
          <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 8 }}>
            Set Rate Params &mdash; base bps &middot; utilization bps &middot; max uplift bps
          </div>
          <div style={{ fontSize: 10, color: "var(--muted)", marginBottom: 12 }}>
            Effective rate = base + (utilization &times; maxUplift / 10000). Example: 500 &middot; 5000 &middot; 400 &rarr; 700bps (7%)
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <input className="sl-input" style={{ marginBottom: 0, flex: 1, minWidth: 100 }} type="number" placeholder="Base bps" value={adminA} onChange={e => setAdminA(e.target.value)} />
            <input className="sl-input" style={{ marginBottom: 0, flex: 1, minWidth: 100 }} type="number" placeholder="Utilization bps" value={adminB} onChange={e => setAdminB(e.target.value)} />
            <input className="sl-input" style={{ marginBottom: 0, flex: 1, minWidth: 100 }} type="number" placeholder="Max uplift bps" value={adminC} onChange={e => setAdminC(e.target.value)} />
            <button className="sl-btn" disabled={loading || !adminA || !adminB || !adminC} onClick={handleSetRateParams} style={{ whiteSpace: "nowrap" }}>
              {loading ? <span className="sl-spinner" /> : "Update Rate"}
            </button>
          </div>
        </>
      )}

      {adminTab === "caps" && (
        <>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 12 }}>ETH Supply Cap</span>
            <span style={{ fontSize: 13 }}>{s ? fmtEth(s.ethSupplyCap) : "\u2014"}</span>
          </div>
          <div className="sl-info-row">
            <span style={{ color: "var(--muted)", fontSize: 12 }}>Max Borrow Per Position</span>
            <span style={{ fontSize: 13 }}>{s ? fmtEth(s.maxBorrowPerPosition) : "\u2014"}</span>
          </div>
          <div className="sl-divider" />
          <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 8 }}>
            Set Caps &mdash; supply cap ETH &middot; max collateral per position ETH (0 = uncapped)
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input className="sl-input" style={{ marginBottom: 0 }} type="number" step="0.001" placeholder="Supply cap (ETH, 0=off)" value={adminA} onChange={e => setAdminA(e.target.value)} />
            <input className="sl-input" style={{ marginBottom: 0 }} type="number" step="0.001" placeholder="Per-position cap (ETH, 0=off)" value={adminB} onChange={e => setAdminB(e.target.value)} />
            <button className="sl-btn" disabled={loading} onClick={handleSetCaps} style={{ whiteSpace: "nowrap" }}>
              {loading ? <span className="sl-spinner" /> : "Set Caps"}
            </button>
          </div>
        </>
      )}

      {adminTab === "emergency" && (
        <>
          <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 16, lineHeight: 1.7 }}>
            Emergency liquidation bypasses the reveal flow &mdash; admin can close any position immediately
            without waiting for the Zama relayer to confirm the health factor.
          </div>
          {borrowers.length === 0
            ? <div className="sl-empty"><div className="sl-empty-icon">&#x2713;</div>No active positions</div>
            : borrowers.map(b => (
              <div className="sl-borrower-item" key={b.address} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
                <div>
                  <div style={{ fontSize: 12, fontFamily: "Space Mono,monospace", marginBottom: 4 }}>
                    {b.address.slice(0, 10)}...{b.address.slice(-6)}
                  </div>
                  <div style={{ display: "flex", gap: 6 }}>
                    {b.confirmedLiq && <span className="sl-step-pill danger">confirmed liq</span>}
                    {b.pendingReveal && <span className="sl-step-pill pending">reveal pending</span>}
                  </div>
                </div>
                <button className="sl-btn-danger" onClick={() => onEmergencyLiquidate(b.address)} disabled={loading}>
                  {loading ? <span className="sl-spinner" /> : "\u26A1 Emergency Liquidate"}
                </button>
              </div>
            ))
          }
        </>
      )}
    </div>
  );
}
