import { BrowserProvider, Contract, parseEther } from "ethers";
import { createInstance } from "./vendor/relayer-sdk/web.js";
import { useCallback, useEffect, useState } from "react";
import ABI from "./abi.json";
import { CONTRACT_ADDRESS } from "./config";

type Role = "borrower" | "liquidator" | null;
type ModalType = "deposit" | "borrow" | "repay" | "result" | null;
type ToastType = { message: string; kind: "success" | "error" | "info" } | null;

interface Position {
  address: string;
  active: boolean;
  collateral: string;
  debt: string;
  interestRate: string;
  isLiquidatable: boolean;
}

const STYLES = `
  @import url('https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syne:wght@400;600;700;800&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:#05080f; --surface:#090e1a; --surface2:#0d1525;
    --border:rgba(99,179,237,0.12); --border2:rgba(99,179,237,0.22);
    --accent:#63b3ed; --accent2:#4fd1c5; --danger:#fc8181;
    --text:#e2e8f0; --muted:#4a5568; --enc:#68d391;
    --enc-bg:rgba(104,211,145,0.08); --enc-border:rgba(104,211,145,0.25);
  }
  html,body{background:var(--bg);color:var(--text);font-family:'Space Mono',monospace;}
  .sl-app{min-height:100vh;background:var(--bg);position:relative;overflow-x:hidden;}
  .sl-app::before{content:'';position:fixed;top:-20%;left:-10%;width:60vw;height:60vw;background:radial-gradient(circle,rgba(99,179,237,0.04) 0%,transparent 65%);pointer-events:none;z-index:0;}
  .sl-app::after{content:'';position:fixed;bottom:-20%;right:-10%;width:50vw;height:50vw;background:radial-gradient(circle,rgba(79,209,197,0.035) 0%,transparent 65%);pointer-events:none;z-index:0;}
  .sl-header{position:sticky;top:0;z-index:50;background:rgba(5,8,15,0.85);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);padding:0 40px;height:64px;display:flex;align-items:center;justify-content:space-between;}
  .sl-logo{font-family:'Syne',sans-serif;font-weight:800;font-size:17px;letter-spacing:0.15em;color:var(--text);display:flex;align-items:center;gap:10px;}
  .sl-logo-icon{width:28px;height:28px;border:1.5px solid var(--accent);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px;color:var(--accent);}
  .sl-header-right{display:flex;align-items:center;gap:12px;}
  .sl-role-badge{font-size:10px;font-weight:700;letter-spacing:0.2em;color:var(--accent2);background:rgba(79,209,197,0.08);border:1px solid rgba(79,209,197,0.25);border-radius:4px;padding:3px 10px;text-transform:uppercase;}
  .sl-addr{font-size:12px;color:var(--muted);font-family:'Space Mono',monospace;}
  .sl-main{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:40px 40px 80px;}
  .sl-hero{text-align:center;padding:100px 0 60px;}
  .sl-hero-eyebrow{font-size:11px;letter-spacing:0.3em;color:var(--accent);text-transform:uppercase;margin-bottom:24px;opacity:0.8;}
  .sl-hero-title{font-family:'Syne',sans-serif;font-weight:800;font-size:clamp(32px,5vw,52px);line-height:1.08;letter-spacing:-0.02em;margin-bottom:20px;background:linear-gradient(135deg,#e2e8f0 0%,#a0aec0 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
  .sl-hero-sub{font-size:14px;color:var(--muted);line-height:1.7;max-width:460px;margin:0 auto 40px;}
  .sl-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px;margin-bottom:16px;position:relative;overflow:hidden;transition:border-color 0.2s;}
  .sl-card:hover{border-color:var(--border2);}
  .sl-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(99,179,237,0.2),transparent);}
  .sl-card-label{font-size:10px;font-weight:700;letter-spacing:0.25em;color:var(--muted);text-transform:uppercase;margin-bottom:10px;}
  .sl-card-value{font-family:'Syne',sans-serif;font-size:26px;font-weight:700;color:var(--text);}
  .sl-grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px;}
  @media(max-width:700px){.sl-grid-3{grid-template-columns:1fr;}.sl-main{padding:24px 20px 60px;}.sl-header{padding:0 20px;}}
  .sl-section-title{font-size:10px;font-weight:700;letter-spacing:0.25em;color:var(--muted);text-transform:uppercase;margin-bottom:20px;display:flex;align-items:center;gap:10px;}
  .sl-section-title::after{content:'';flex:1;height:1px;background:var(--border);}
  .sl-row{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:13px;}
  .sl-row:last-of-type{border-bottom:none;}
  .sl-row-label{color:var(--muted);}
  .enc-tag{font-size:11px;color:var(--enc);background:var(--enc-bg);border:1px solid var(--enc-border);border-radius:4px;padding:2px 8px;font-family:'Space Mono',monospace;}
  .sl-btn{background:var(--accent);border:none;color:#05080f;border-radius:8px;padding:10px 20px;font-weight:700;cursor:pointer;font-size:12px;font-family:'Space Mono',monospace;letter-spacing:0.05em;transition:opacity 0.15s,transform 0.1s;}
  .sl-btn:hover:not(:disabled){opacity:0.88;transform:translateY(-1px);}
  .sl-btn:disabled{opacity:0.4;cursor:not-allowed;}
  .sl-btn-ghost{background:transparent;border:1px solid var(--border2);color:var(--accent);border-radius:8px;padding:10px 20px;font-weight:700;cursor:pointer;font-size:12px;font-family:'Space Mono',monospace;letter-spacing:0.05em;transition:background 0.15s,transform 0.1s;}
  .sl-btn-ghost:hover:not(:disabled){background:rgba(99,179,237,0.07);transform:translateY(-1px);}
  .sl-btn-ghost:disabled{opacity:0.4;cursor:not-allowed;}
  .sl-btn-danger{background:transparent;border:1px solid rgba(252,129,129,0.3);color:var(--danger);border-radius:8px;padding:8px 16px;font-weight:700;cursor:pointer;font-size:11px;font-family:'Space Mono',monospace;transition:background 0.15s;}
  .sl-btn-danger:hover:not(:disabled){background:rgba(252,129,129,0.08);}
  .sl-btn-danger:disabled{opacity:0.4;cursor:not-allowed;}
  .sl-btn-hero{background:transparent;border:1px solid var(--border2);color:var(--text);border-radius:10px;padding:14px 36px;font-weight:700;cursor:pointer;font-size:13px;font-family:'Space Mono',monospace;letter-spacing:0.08em;transition:background 0.2s,border-color 0.2s,transform 0.1s;position:relative;overflow:hidden;}
  .sl-btn-hero:hover{border-color:rgba(99,179,237,0.4);transform:translateY(-2px);background:rgba(99,179,237,0.05);}
  .sl-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:24px;}
  .sl-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.75);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;z-index:100;animation:fadeIn 0.15s ease;}
  @keyframes fadeIn{from{opacity:0}to{opacity:1}}
  @keyframes slideUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
  .sl-modal{background:var(--surface2);border:1px solid var(--border2);border-radius:20px;padding:36px;width:min(460px,92vw);box-shadow:0 40px 80px rgba(0,0,0,0.6);animation:slideUp 0.2s ease;position:relative;overflow:hidden;}
  .sl-modal::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent 10%,rgba(99,179,237,0.3) 50%,transparent 90%);}
  .sl-modal-title{font-family:'Syne',sans-serif;font-size:18px;font-weight:700;margin-bottom:8px;color:var(--text);}
  .sl-modal-sub{font-size:11px;color:var(--muted);margin-bottom:24px;line-height:1.6;}
  .sl-input{width:100%;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:12px 16px;color:var(--text);font-size:14px;font-family:'Space Mono',monospace;margin-bottom:16px;outline:none;transition:border-color 0.2s;}
  .sl-input:focus{border-color:rgba(99,179,237,0.4);}
  .sl-input::placeholder{color:var(--muted);}
  .sl-toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);border-radius:10px;padding:12px 22px;font-size:12px;font-weight:700;font-family:'Space Mono',monospace;z-index:300;display:flex;align-items:center;gap:10px;box-shadow:0 8px 32px rgba(0,0,0,0.4);animation:slideUp 0.2s ease;white-space:nowrap;max-width:90vw;}
  .sl-toast.success{background:#065f46;border:1px solid rgba(52,211,153,0.3);color:#6ee7b7;}
  .sl-toast.error{background:#7f1d1d;border:1px solid rgba(252,129,129,0.3);color:#fca5a5;}
  .sl-toast.info{background:#1e3a5f;border:1px solid rgba(99,179,237,0.3);color:#93c5fd;}
  .sl-toast-dot{width:6px;height:6px;border-radius:50%;background:currentColor;opacity:0.7;flex-shrink:0;}
  @keyframes spin{to{transform:rotate(360deg)}}
  .sl-spinner{width:14px;height:14px;border:2px solid rgba(99,179,237,0.3);border-top-color:var(--accent);border-radius:50%;animation:spin 0.7s linear infinite;display:inline-block;}
  .sl-borrower-item{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:10px;margin-bottom:8px;transition:border-color 0.2s;}
  .sl-borrower-item:hover{border-color:var(--border2);}
  .sl-fhe-status{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted);}
  .sl-fhe-dot{width:6px;height:6px;border-radius:50%;background:var(--enc);box-shadow:0 0 6px var(--enc);animation:pulse 2s infinite;}
  .sl-fhe-dot.offline{background:var(--muted);box-shadow:none;animation:none;}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
  .sl-result-pre{background:rgba(104,211,145,0.05);border:1px solid var(--enc-border);border-radius:10px;padding:18px;font-size:12px;color:var(--enc);white-space:pre-wrap;line-height:1.8;font-family:'Space Mono',monospace;}
  .sl-info-row{display:flex;align-items:center;justify-content:space-between;padding:13px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:13px;}
  .sl-info-row:last-child{border-bottom:none;}
  .sl-contract-link{color:var(--accent);font-size:12px;text-decoration:none;font-family:'Space Mono',monospace;opacity:0.8;transition:opacity 0.2s;}
  .sl-contract-link:hover{opacity:1;}
  .sl-empty{text-align:center;padding:40px 0;color:var(--muted);font-size:13px;}
  .sl-empty-icon{font-size:28px;margin-bottom:12px;opacity:0.5;}
`;

export default function ShieldLendApp() {
  const [account, setAccount]     = useState<string | null>(null);
  const [contract, setContract]   = useState<Contract | null>(null);
  const [fhevmInst, setFhevmInst] = useState<any>(null);
  const [role, setRole]           = useState<Role>(null);
  const [position, setPosition]   = useState<Position | null>(null);
  const [borrowers, setBorrowers] = useState<string[]>([]);
  const [modal, setModal]         = useState<ModalType>(null);
  const [loading, setLoading]     = useState(false);
  const [toast, setToast]         = useState<ToastType>(null);
  const [amount, setAmount]       = useState("");
  const [resultMsg, setResultMsg] = useState("");

  useEffect(() => {
    const id = "sl-styles";
    if (!document.getElementById(id)) {
      const el = document.createElement("style");
      el.id = id; el.textContent = STYLES;
      document.head.appendChild(el);
    }
  }, []);

  const showToast = useCallback((message: string, kind: "success" | "error" | "info" = "success") => {
    setToast({ message, kind });
    setTimeout(() => setToast(null), 4000);
  }, []);

  const encryptAmount = async (value: bigint) => {
    if (!fhevmInst || !account) throw new Error("FHE not initialized");
    const r = await fhevmInst.encryptUint({ value, type: "euint64", contractAddress: CONTRACT_ADDRESS, callerAddress: account });
    const { ethers } = await import("ethers");
    return { handle: ethers.hexlify(r.handles[0]), proof: ethers.hexlify(r.inputProof) };
  };

  const connect = async () => {
    const eth = (window as any).ethereum;
    if (!eth || typeof eth.request !== "function") { showToast("No wallet detected — install Rabby or MetaMask", "info"); return; }
    try {
      const provider = new BrowserProvider(eth);
      await provider.send("eth_requestAccounts", []);
      const signer = await provider.getSigner();
      const addr   = await signer.getAddress();
      setAccount(addr);
      let inst = null;
      try {
        inst = await Promise.race([
          createInstance({
            aclContractAddress: "0xf0Ffdc93b7E186bC2f8CB3dAA75D86d1930A433D",
            kmsContractAddress: "0xbE0E383937d564D7FF0BC3b46c51f0bF8d5C311A",
            inputVerifierContractAddress: "0xBBC1fFCdc7C316aAAd72E807D9b0272BE8F84DA0",
            verifyingContractAddressDecryption: "0x5D8BD78e2ea6bbE41f26dFe9fdaEAa349e077478",
            verifyingContractAddressInputVerification: "0x483b9dE06E4E4C7D35CCf5837A1668487406D955",
            chainId: 11155111, gatewayChainId: 10901,
            relayerUrl: "https://shieldlend.vercel.app/api/zama-relay",
            network: eth,
          }),
          new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 15000))
        ]);
      } catch (e) { console.warn("fhevmjs init failed:", e); }
      setFhevmInst(inst);
      const c = new Contract(CONTRACT_ADDRESS, ABI, signer);
      setContract(c);
      let isLiquidator = false;
      try {
        const LIQUIDATOR_ROLE = await c.LIQUIDATOR_ROLE();
        isLiquidator = await c.hasRole(LIQUIDATOR_ROLE, addr);
      } catch (e) { console.warn("Role check failed", e); }
      setRole(isLiquidator ? "liquidator" : "borrower");
      await loadPosition(c, addr);
      if (isLiquidator) {
        const count = Number(await c.getBorrowerCount());
        const list: string[] = [];
        for (let i = 0; i < count; i++) list.push(await c.borrowerList(i));
        setBorrowers(list);
      }
      showToast(`Connected: ${addr.slice(0,6)}…${addr.slice(-4)}`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
  };

  const loadPosition = async (c: Contract, addr: string) => {
    const active = await c.isActive(addr);
    if (!active) { setPosition(null); return; }
    setPosition({ address: addr, active: true, collateral: "🔒 encrypted", debt: "🔒 encrypted", interestRate: "🔒 encrypted", isLiquidatable: false });
  };

  const handleDeposit = async () => {
    if (!contract || !account || !amount) return;
    setLoading(true);
    try {
      const wei = parseEther(amount);
      if (!fhevmInst) throw new Error("FHE unavailable — relayer unreachable");
      const { handle, proof } = await encryptAmount(wei);
      const tx = await contract.deposit(handle, proof, { value: wei });
      await tx.wait(); await loadPosition(contract, account);
      setModal(null); setAmount(""); showToast("Collateral deposited ✓");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleBorrow = async () => {
    if (!contract || !account || !amount) return;
    setLoading(true);
    try {
      const wei = parseEther(amount);
      if (!fhevmInst) throw new Error("FHE unavailable — relayer unreachable");
      const { handle, proof } = await encryptAmount(wei);
      const tx = await contract.borrow(handle, proof);
      await tx.wait(); await loadPosition(contract, account);
      setModal(null); setAmount(""); showToast("Loan issued ✓ — debt encrypted on-chain");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleRepay = async () => {
    if (!contract || !account || !amount) return;
    setLoading(true);
    try {
      const wei = parseEther(amount);
      if (!fhevmInst) throw new Error("FHE unavailable — relayer unreachable");
      const { handle, proof } = await encryptAmount(wei);
      const tx = await contract.repay(handle, proof);
      await tx.wait(); await loadPosition(contract, account);
      setModal(null); setAmount(""); showToast("Repayment processed ✓");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleDecrypt = async () => {
    if (!contract || !account) return;
    if (!fhevmInst) { showToast("FHE decryption unavailable — Zama relayer unreachable", "error"); return; }
    setLoading(true);
    try {
      const [collHandle, debtHandle, rateHandle] = await Promise.all([
        contract.getEncryptedCollateral(account),
        contract.getEncryptedTotalDebt(account),
        contract.getEncryptedInterestRate(account),
      ]);
      const { publicKey, privateKey } = fhevmInst.generateKeypair();
      const eip712 = fhevmInst.createEIP712(publicKey, CONTRACT_ADDRESS);
      const provider = new BrowserProvider((window as any).ethereum);
      const signer = await provider.getSigner();
      const signature = await signer.signTypedData(eip712.domain, { Reencrypt: eip712.types.Reencrypt }, eip712.message);
      const [collateral, debt, rate] = await Promise.all([
        fhevmInst.reencrypt(collHandle, privateKey, publicKey, signature, CONTRACT_ADDRESS, account),
        fhevmInst.reencrypt(debtHandle, privateKey, publicKey, signature, CONTRACT_ADDRESS, account),
        fhevmInst.reencrypt(rateHandle, privateKey, publicKey, signature, CONTRACT_ADDRESS, account),
      ]);
      setResultMsg(`Collateral:    ${collateral} wei\nTotal Debt:    ${debt} wei\nInterest Rate: ${rate} bps`);
      setModal("result");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleLiquidate = async (addr: string) => {
    if (!contract) return;
    setLoading(true);
    try {
      const tx = await contract.liquidate(addr);
      await tx.wait();
      setBorrowers(prev => prev.filter(b => b !== addr));
      showToast(`Liquidated ${addr.slice(0,6)}…`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const modalTitle = modal === "deposit" ? "Deposit Collateral" : modal === "borrow" ? "Borrow Against Collateral" : "Repay Debt";
  const modalSub   = modal === "deposit"
    ? "Amount encrypted client-side via Zama FHE before submission. Contract never sees plaintext."
    : modal === "borrow"
    ? "Borrow up to 66% of collateral value. Health factor enforced via encrypted comparison."
    : "Partial or full repayment. Encrypted subtraction applied to your debt handle on-chain.";

  return (
    <div className="sl-app">
      <header className="sl-header">
        <div className="sl-logo">
          <div className="sl-logo-icon">⬡</div>
          SHIELDLEND
        </div>
        <div className="sl-header-right">
          {fhevmInst !== undefined && account && (
            <div className="sl-fhe-status">
              <div className={`sl-fhe-dot ${fhevmInst ? "" : "offline"}`} />
              <span>FHE {fhevmInst ? "online" : "offline"}</span>
            </div>
          )}
          {account && role && <span className="sl-role-badge">{role}</span>}
          {account
            ? <span className="sl-addr">{account.slice(0,6)}…{account.slice(-4)}</span>
            : <button className="sl-btn" onClick={connect}>Connect Wallet</button>
          }
        </div>
      </header>

      <div className="sl-main">
        {!account ? (
          <div className="sl-hero">
            <div className="sl-hero-eyebrow">Powered by Zama fhEVM · Sepolia Testnet</div>
            <h1 className="sl-hero-title">Confidential<br />On-Chain Lending</h1>
            <p className="sl-hero-sub">
              Collateral, debt, and interest rates stay encrypted at all times —
              even the contract cannot read them. Fully Homomorphic Encryption on Ethereum.
            </p>
            <button className="sl-btn-hero" onClick={connect}>Connect Wallet →</button>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12, marginTop:60, textAlign:"left" }}>
              {[
                { icon:"🔐", title:"Encrypted Positions", desc:"All amounts stored as euint64 ciphertexts on-chain" },
                { icon:"📊", title:"FHE Health Factor",   desc:"Liquidation triggered via ebool comparison — no plaintext leakage" },
                { icon:"🔑", title:"Re-encryption",       desc:"Decrypt your own data with a wallet-signed EIP-712 request" },
              ].map(f => (
                <div className="sl-card" key={f.title}>
                  <div style={{ fontSize:22, marginBottom:10 }}>{f.icon}</div>
                  <div style={{ fontSize:13, fontWeight:700, marginBottom:6, color:"var(--text)" }}>{f.title}</div>
                  <div style={{ fontSize:12, color:"var(--muted)", lineHeight:1.6 }}>{f.desc}</div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <>
            <div className="sl-grid-3">
              <div className="sl-card">
                <div className="sl-card-label">Total Borrowers</div>
                <div className="sl-card-value">{borrowers.length || (position ? 1 : 0)}</div>
              </div>
              <div className="sl-card">
                <div className="sl-card-label">Your Position</div>
                <div className="sl-card-value" style={{ color: position ? "var(--accent2)" : "var(--muted)", fontSize:20 }}>
                  {position ? "Active" : "None"}
                </div>
              </div>
              <div className="sl-card">
                <div className="sl-card-label">Protocol Reserves</div>
                <div className="sl-card-value" style={{ fontSize:16, paddingTop:4 }}>
                  <span className="enc-tag">🔒 euint64</span>
                </div>
              </div>
            </div>

            {role === "borrower" && (
              <div className="sl-card">
                <div className="sl-section-title">Your Position</div>
                {position ? (
                  <>
                    <div className="sl-row"><span className="sl-row-label">Collateral (ETH)</span><span className="enc-tag">🔒 euint64 cipher</span></div>
                    <div className="sl-row"><span className="sl-row-label">Total Debt</span><span className="enc-tag">🔒 euint64 cipher</span></div>
                    <div className="sl-row"><span className="sl-row-label">Interest Rate</span><span className="enc-tag">🔒 euint64 cipher</span></div>
                    <div className="sl-row"><span className="sl-row-label">Health Factor</span><span className="enc-tag">🔒 ebool cipher</span></div>
                    <div className="sl-actions">
                      <button className="sl-btn" onClick={() => setModal("deposit")} disabled={loading}>+ Deposit</button>
                      <button className="sl-btn" onClick={() => setModal("borrow")} disabled={loading}>Borrow</button>
                      <button className="sl-btn" onClick={() => setModal("repay")} disabled={loading}>Repay</button>
                      <button className="sl-btn-ghost" onClick={handleDecrypt} disabled={loading}>
                        {loading ? <span className="sl-spinner" /> : "🔓 Decrypt Position"}
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="sl-empty">
                    <div className="sl-empty-icon">🏦</div>
                    <div style={{ marginBottom:20 }}>No active position. Deposit ETH collateral to get started.</div>
                    <button className="sl-btn" onClick={() => setModal("deposit")}>Deposit Collateral →</button>
                  </div>
                )}
              </div>
            )}

            {role === "liquidator" && (
              <div className="sl-card">
                <div className="sl-section-title">Active Positions ({borrowers.length})</div>
                {borrowers.length === 0 ? (
                  <div className="sl-empty">
                    <div className="sl-empty-icon">✓</div>
                    No positions currently eligible for liquidation
                  </div>
                ) : (
                  borrowers.map(addr => (
                    <div className="sl-borrower-item" key={addr}>
                      <div>
                        <div style={{ fontSize:12, fontFamily:"Space Mono,monospace", marginBottom:4 }}>{addr.slice(0,10)}…{addr.slice(-6)}</div>
                        <span className="enc-tag">🔒 health factor encrypted</span>
                      </div>
                      <button className="sl-btn-danger" onClick={() => handleLiquidate(addr)} disabled={loading}>
                        {loading ? <span className="sl-spinner" /> : "Liquidate"}
                      </button>
                    </div>
                  ))
                )}
              </div>
            )}

            <div className="sl-card">
              <div className="sl-section-title">Protocol Parameters</div>
              <div className="sl-info-row"><span style={{ color:"var(--muted)",fontSize:13 }}>Collateral Ratio</span><span style={{ fontSize:13 }}>150%</span></div>
              <div className="sl-info-row"><span style={{ color:"var(--muted)",fontSize:13 }}>Base Interest Rate</span><span style={{ fontSize:13 }}>5% <span style={{ color:"var(--muted)" }}>(500 bps)</span></span></div>
              <div className="sl-info-row"><span style={{ color:"var(--muted)",fontSize:13 }}>Max Loan Ratio</span><span style={{ fontSize:13 }}>66% of collateral</span></div>
              <div className="sl-info-row">
                <span style={{ color:"var(--muted)",fontSize:13 }}>Liquidation Threshold</span>
                <span style={{ fontSize:13, display:"flex", alignItems:"center", gap:8 }}>110% health <span className="enc-tag">ebool</span></span>
              </div>
              <div className="sl-info-row"><span style={{ color:"var(--muted)",fontSize:13 }}>Network</span><span style={{ fontSize:13 }}>Sepolia Testnet</span></div>
              <div className="sl-info-row">
                <span style={{ color:"var(--muted)",fontSize:13 }}>Contract</span>
                <a href={`https://sepolia.etherscan.io/address/${CONTRACT_ADDRESS}`} target="_blank" rel="noreferrer" className="sl-contract-link">
                  {CONTRACT_ADDRESS.slice(0,10)}…{CONTRACT_ADDRESS.slice(-6)} ↗
                </a>
              </div>
            </div>
          </>
        )}
      </div>

      {(modal === "deposit" || modal === "borrow" || modal === "repay") && (
        <div className="sl-overlay" onClick={() => setModal(null)}>
          <div className="sl-modal" onClick={e => e.stopPropagation()}>
            <div className="sl-modal-title">{modalTitle}</div>
            <div className="sl-modal-sub">{modalSub}</div>
            <input className="sl-input" type="number" step="0.001" min="0" placeholder="Amount in ETH (e.g. 0.1)"
              value={amount} onChange={e => setAmount(e.target.value)} autoFocus />
            <div style={{ display:"flex", gap:8 }}>
              <button className="sl-btn" style={{ flex:1 }} disabled={loading || !amount}
                onClick={modal === "deposit" ? handleDeposit : modal === "borrow" ? handleBorrow : handleRepay}>
                {loading ? <span className="sl-spinner" /> : modal === "deposit" ? "Deposit →" : modal === "borrow" ? "Borrow →" : "Repay →"}
              </button>
              <button className="sl-btn-ghost" onClick={() => setModal(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {modal === "result" && (
        <div className="sl-overlay" onClick={() => setModal(null)}>
          <div className="sl-modal" onClick={e => e.stopPropagation()}>
            <div className="sl-modal-title">🔓 Decrypted Position</div>
            <div className="sl-modal-sub">Re-encrypted via Zama KMS and decrypted locally with your wallet keypair.</div>
            <pre className="sl-result-pre">{resultMsg}</pre>
            <button className="sl-btn" style={{ marginTop:20, width:"100%" }} onClick={() => setModal(null)}>Close</button>
          </div>
        </div>
      )}

      {toast && (
        <div className={`sl-toast ${toast.kind}`}>
          <span className="sl-toast-dot" />
          {toast.message}
        </div>
      )}
    </div>
  );
}
