import { BrowserProvider, Contract, parseEther, parseUnits } from "ethers";
import { initSDK, createInstance, SepoliaConfig } from "./vendor/relayer-sdk/web.js";
import { useCallback, useEffect, useRef, useState } from "react";
import ABI from "./abi.json";
import { CONTRACT_ADDRESS, SCORE_CONTRACT_ADDRESS, CHAIN_ID, TOKENS, type TokenSymbol } from "./config";
import ShieldScore from "./ShieldScore";

const ERC20_ABI = [
  "function approve(address spender, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function balanceOf(address account) view returns (uint256)",
];

// ─── Types ────────────────────────────────────────────────────────────────────
type Role = "borrower" | "liquidator" | "admin" | null;
type ModalType = "deposit" | "borrow" | "repay" | "result" | "score" | null;
type Toast = { message: string; kind: "success" | "error" | "info" } | null;
type CloseStep = "idle" | "pending" | "done";

interface BorrowerEntry {
  address: string;
  pendingReveal: boolean;
  confirmedLiq: boolean;
  pendingClose: boolean;
}

// ─── Styles ───────────────────────────────────────────────────────────────────
const STYLES = `
  @import url('https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syne:wght@400;600;700;800&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:#06080f; --surface:#0c1020; --surface2:#111827;
    --border:rgba(139,92,246,0.15); --border2:rgba(139,92,246,0.35);
    --accent:#a78bfa; --accent2:#34d399; --accent3:#38bdf8;
    --danger:#f87171; --warn:#fbbf24; --text:#f1f5f9; --muted:#64748b;
    --enc:#34d399; --enc-bg:rgba(52,211,153,0.08); --enc-border:rgba(52,211,153,0.25);
    --purple:#8b5cf6; --violet:#7c3aed; --teal:#0d9488;
    --glow-purple:rgba(139,92,246,0.2); --glow-teal:rgba(52,211,153,0.15);
  }
  html,body{background:var(--bg);color:var(--text);font-family:'Space Mono',monospace;}

  /* ── Animated background ── */
  .sl-app{min-height:100vh;background:var(--bg);position:relative;overflow-x:hidden;}
  .sl-app::before{content:'';position:fixed;top:-30%;left:-15%;width:70vw;height:70vw;background:radial-gradient(circle,rgba(124,58,237,0.07) 0%,transparent 60%);pointer-events:none;z-index:0;animation:bgdrift 18s ease-in-out infinite alternate;}
  .sl-app::after{content:'';position:fixed;bottom:-20%;right:-10%;width:55vw;height:55vw;background:radial-gradient(circle,rgba(13,148,136,0.06) 0%,transparent 60%);pointer-events:none;z-index:0;animation:bgdrift 22s ease-in-out infinite alternate-reverse;}
  @keyframes bgdrift{0%{transform:translate(0,0)}100%{transform:translate(3%,4%)}}

  /* ── Header ── */
  .sl-header{position:sticky;top:0;z-index:50;background:rgba(6,8,15,0.8);backdrop-filter:blur(24px);border-bottom:1px solid rgba(139,92,246,0.12);padding:0 40px;height:68px;display:flex;align-items:center;justify-content:space-between;}
  .sl-logo{font-family:'Syne',sans-serif;font-weight:800;font-size:18px;letter-spacing:0.12em;color:var(--text);display:flex;align-items:center;gap:12px;}
  .sl-logo-icon{width:32px;height:32px;background:linear-gradient(135deg,var(--purple),var(--teal));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;box-shadow:0 0 20px rgba(139,92,246,0.4);}
  .sl-logo-text{background:linear-gradient(90deg,#a78bfa,#34d399);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
  .sl-header-right{display:flex;align-items:center;gap:12px;}
  .sl-role-badge{font-size:10px;font-weight:700;letter-spacing:0.2em;color:var(--accent2);background:rgba(52,211,153,0.1);border:1px solid rgba(52,211,153,0.3);border-radius:20px;padding:4px 12px;text-transform:uppercase;}
  .sl-role-badge.admin{color:var(--warn);background:rgba(251,191,36,0.1);border-color:rgba(251,191,36,0.3);}
  .sl-addr{font-size:11px;color:var(--muted);background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:20px;padding:4px 12px;}
  .sl-main{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:40px 40px 80px;}
  @media(max-width:700px){.sl-grid-3{grid-template-columns:1fr!important;}.sl-main{padding:24px 16px 60px;}.sl-header{padding:0 16px;}}

  /* ── Hero ── */
  .sl-hero{text-align:center;padding:90px 0 60px;}
  .sl-hero-eyebrow{font-size:11px;letter-spacing:0.35em;background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;text-transform:uppercase;margin-bottom:24px;font-weight:700;}
  .sl-hero-title{font-family:'Syne',sans-serif;font-weight:800;font-size:clamp(36px,5.5vw,58px);line-height:1.06;letter-spacing:-0.03em;margin-bottom:20px;background:linear-gradient(135deg,#f1f5f9 0%,#a78bfa 50%,#34d399 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
  .sl-hero-sub{font-size:14px;color:var(--muted);line-height:1.75;max-width:480px;margin:0 auto 44px;}
  .sl-hero-cta{display:inline-flex;align-items:center;gap:10px;background:linear-gradient(135deg,var(--purple),var(--teal));border:none;color:#fff;border-radius:12px;padding:15px 38px;font-weight:700;cursor:pointer;font-size:13px;font-family:'Space Mono',monospace;letter-spacing:0.06em;transition:transform 0.15s,box-shadow 0.15s;box-shadow:0 0 30px rgba(139,92,246,0.35);}
  .sl-hero-cta:hover{transform:translateY(-2px);box-shadow:0 0 40px rgba(139,92,246,0.5);}

  /* ── Feature cards ── */
  .sl-feature-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:56px;}
  @media(max-width:700px){.sl-feature-grid{grid-template-columns:1fr;}}
  .sl-feature-card{background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:28px;position:relative;overflow:hidden;transition:border-color 0.2s,transform 0.2s;}
  .sl-feature-card:hover{border-color:var(--border2);transform:translateY(-3px);}
  .sl-feature-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.4),transparent);}
  .sl-feature-icon{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:16px;}
  .sl-feature-icon.purple{background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.25);}
  .sl-feature-icon.teal{background:rgba(52,211,153,0.12);border:1px solid rgba(52,211,153,0.25);}
  .sl-feature-icon.blue{background:rgba(56,189,248,0.12);border:1px solid rgba(56,189,248,0.25);}
  .sl-feature-title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:8px;}
  .sl-feature-desc{font-size:12px;color:var(--muted);line-height:1.65;}

  /* ── Stat cards ── */
  .sl-grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px;}
  .sl-card{background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:24px 28px;margin-bottom:16px;position:relative;overflow:hidden;transition:border-color 0.2s,box-shadow 0.2s;}
  .sl-card:hover{border-color:var(--border2);box-shadow:0 0 30px var(--glow-purple);}
  .sl-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.3),transparent);}
  .sl-card-label{font-size:10px;font-weight:700;letter-spacing:0.25em;color:var(--muted);text-transform:uppercase;margin-bottom:10px;}
  .sl-card-value{font-family:'Syne',sans-serif;font-size:28px;font-weight:800;background:linear-gradient(135deg,var(--text),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
  .sl-stat-active .sl-card-value{background:linear-gradient(135deg,var(--accent2),var(--accent3));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}

  /* ── Section titles ── */
  .sl-section-title{font-size:10px;font-weight:700;letter-spacing:0.25em;color:var(--muted);text-transform:uppercase;margin-bottom:20px;display:flex;align-items:center;gap:10px;}
  .sl-section-title::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent);}

  /* ── Table rows ── */
  .sl-row{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:13px;}
  .sl-row:last-of-type{border-bottom:none;}
  .sl-row-label{color:var(--muted);}

  /* ── Encrypted tag ── */
  .enc-tag{font-size:11px;color:var(--enc);background:var(--enc-bg);border:1px solid var(--enc-border);border-radius:6px;padding:2px 10px;font-family:'Space Mono',monospace;letter-spacing:0.04em;}

  /* ── Buttons ── */
  .sl-btn{background:linear-gradient(135deg,var(--purple),#6d28d9);border:none;color:#fff;border-radius:10px;padding:11px 22px;font-weight:700;cursor:pointer;font-size:12px;font-family:'Space Mono',monospace;letter-spacing:0.05em;transition:transform 0.15s,box-shadow 0.15s;box-shadow:0 0 20px rgba(139,92,246,0.25);}
  .sl-btn:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 0 28px rgba(139,92,246,0.45);}
  .sl-btn:disabled{opacity:0.4;cursor:not-allowed;}
  .sl-btn-ghost{background:rgba(139,92,246,0.08);border:1px solid var(--border2);color:var(--accent);border-radius:10px;padding:11px 22px;font-weight:700;cursor:pointer;font-size:12px;font-family:'Space Mono',monospace;letter-spacing:0.05em;transition:background 0.15s,transform 0.15s;}
  .sl-btn-ghost:hover:not(:disabled){background:rgba(139,92,246,0.15);transform:translateY(-1px);}
  .sl-btn-ghost:disabled{opacity:0.4;cursor:not-allowed;}
  .sl-btn-danger{background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.3);color:var(--danger);border-radius:10px;padding:9px 18px;font-weight:700;cursor:pointer;font-size:11px;font-family:'Space Mono',monospace;transition:background 0.15s,box-shadow 0.15s;}
  .sl-btn-danger:hover:not(:disabled){background:rgba(248,113,113,0.15);box-shadow:0 0 16px rgba(248,113,113,0.2);}
  .sl-btn-danger:disabled{opacity:0.4;cursor:not-allowed;}
  .sl-btn-warn{background:rgba(251,191,36,0.08);border:1px solid rgba(251,191,36,0.3);color:var(--warn);border-radius:10px;padding:9px 18px;font-weight:700;cursor:pointer;font-size:11px;font-family:'Space Mono',monospace;transition:background 0.15s,box-shadow 0.15s;}
  .sl-btn-warn:hover:not(:disabled){background:rgba(251,191,36,0.15);box-shadow:0 0 16px rgba(251,191,36,0.2);}
  .sl-btn-warn:disabled{opacity:0.4;cursor:not-allowed;}
  .sl-btn-hero{background:linear-gradient(135deg,var(--purple),var(--teal));border:none;color:#fff;border-radius:12px;padding:15px 38px;font-weight:700;cursor:pointer;font-size:13px;font-family:'Space Mono',monospace;letter-spacing:0.08em;transition:transform 0.15s,box-shadow 0.15s;box-shadow:0 0 30px rgba(139,92,246,0.35);}
  .sl-btn-hero:hover{transform:translateY(-2px);box-shadow:0 0 44px rgba(139,92,246,0.5);}
  .sl-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:24px;}

  /* ── Connect button in header ── */
  .sl-connect-btn{background:linear-gradient(135deg,var(--purple),var(--teal));border:none;color:#fff;border-radius:10px;padding:9px 20px;font-weight:700;cursor:pointer;font-size:12px;font-family:'Space Mono',monospace;letter-spacing:0.04em;transition:transform 0.15s,box-shadow 0.15s;box-shadow:0 0 18px rgba(139,92,246,0.3);}
  .sl-connect-btn:hover{transform:translateY(-1px);box-shadow:0 0 26px rgba(139,92,246,0.45);}

  /* ── Overlay / Modal ── */
  .sl-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.8);backdrop-filter:blur(12px);display:flex;align-items:center;justify-content:center;z-index:100;animation:fadeIn 0.15s ease;}
  @keyframes fadeIn{from{opacity:0}to{opacity:1}}
  @keyframes slideUp{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}
  .sl-modal{background:var(--surface2);border:1px solid rgba(139,92,246,0.3);border-radius:22px;padding:36px;width:min(460px,92vw);box-shadow:0 40px 80px rgba(0,0,0,0.7),0 0 60px rgba(139,92,246,0.1);animation:slideUp 0.2s ease;position:relative;overflow:hidden;}
  .sl-modal::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.5),rgba(52,211,153,0.3),transparent);}
  .sl-modal-title{font-family:'Syne',sans-serif;font-size:20px;font-weight:800;margin-bottom:8px;background:linear-gradient(135deg,var(--text),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
  .sl-modal-sub{font-size:11px;color:var(--muted);margin-bottom:24px;line-height:1.65;}
  .sl-input{width:100%;background:rgba(255,255,255,0.04);border:1px solid rgba(139,92,246,0.2);border-radius:12px;padding:13px 16px;color:var(--text);font-size:14px;font-family:'Space Mono',monospace;margin-bottom:16px;outline:none;transition:border-color 0.2s,box-shadow 0.2s;}
  .sl-input:focus{border-color:rgba(139,92,246,0.5);box-shadow:0 0 16px rgba(139,92,246,0.15);}
  .sl-input::placeholder{color:var(--muted);}

  /* ── Toast ── */
  .sl-toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);border-radius:12px;padding:13px 24px;font-size:12px;font-weight:700;font-family:'Space Mono',monospace;z-index:300;display:flex;align-items:center;gap:10px;box-shadow:0 8px 40px rgba(0,0,0,0.5);animation:slideUp 0.2s ease;white-space:nowrap;max-width:90vw;}
  .sl-toast.success{background:rgba(6,78,59,0.95);border:1px solid rgba(52,211,153,0.4);color:#6ee7b7;box-shadow:0 8px 40px rgba(0,0,0,0.5),0 0 20px rgba(52,211,153,0.15);}
  .sl-toast.error{background:rgba(127,29,29,0.95);border:1px solid rgba(248,113,113,0.4);color:#fca5a5;box-shadow:0 8px 40px rgba(0,0,0,0.5),0 0 20px rgba(248,113,113,0.15);}
  .sl-toast.info{background:rgba(30,58,95,0.95);border:1px solid rgba(139,92,246,0.4);color:#c4b5fd;box-shadow:0 8px 40px rgba(0,0,0,0.5),0 0 20px rgba(139,92,246,0.15);}
  .sl-toast-dot{width:6px;height:6px;border-radius:50%;background:currentColor;opacity:0.8;flex-shrink:0;}

  /* ── Spinner ── */
  @keyframes spin{to{transform:rotate(360deg)}}
  .sl-spinner{width:14px;height:14px;border:2px solid rgba(167,139,250,0.3);border-top-color:var(--accent);border-radius:50%;animation:spin 0.7s linear infinite;display:inline-block;}

  /* ── Borrower items ── */
  .sl-borrower-item{padding:16px 18px;background:rgba(139,92,246,0.04);border:1px solid var(--border);border-radius:14px;margin-bottom:8px;transition:border-color 0.2s,background 0.2s;}
  .sl-borrower-item:hover{border-color:var(--border2);background:rgba(139,92,246,0.07);}
  .sl-borrower-row{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;}

  /* ── FHE status ── */
  .sl-fhe-status{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted);background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:20px;padding:4px 10px;}
  .sl-fhe-dot{width:7px;height:7px;border-radius:50%;background:var(--enc);box-shadow:0 0 8px var(--enc);animation:pulse 2s infinite;}
  .sl-fhe-dot.offline{background:var(--muted);box-shadow:none;animation:none;}
  @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.5;transform:scale(0.85)}}

  /* ── Result / decrypt ── */
  .sl-result-pre{background:rgba(52,211,153,0.05);border:1px solid var(--enc-border);border-radius:12px;padding:20px;font-size:12px;color:var(--enc);white-space:pre-wrap;line-height:1.9;box-shadow:inset 0 0 30px rgba(52,211,153,0.04);}

  /* ── Protocol info ── */
  .sl-info-row{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:13px;}
  .sl-info-row:last-child{border-bottom:none;}
  .sl-contract-link{color:var(--accent);font-size:12px;text-decoration:none;opacity:0.8;transition:opacity 0.2s;}
  .sl-contract-link:hover{opacity:1;}

  /* ── Empty state ── */
  .sl-empty{text-align:center;padding:44px 0;color:var(--muted);font-size:13px;}
  .sl-empty-icon{font-size:32px;margin-bottom:14px;opacity:0.45;}

  /* ── Pills ── */
  .sl-step-pill{display:inline-flex;align-items:center;gap:6px;font-size:10px;font-weight:700;letter-spacing:0.15em;padding:4px 12px;border-radius:20px;text-transform:uppercase;}
  .sl-step-pill.pending{color:var(--warn);background:rgba(251,191,36,0.1);border:1px solid rgba(251,191,36,0.3);}
  .sl-step-pill.confirmed{color:var(--enc);background:var(--enc-bg);border:1px solid var(--enc-border);}
  .sl-step-pill.danger{color:var(--danger);background:rgba(248,113,113,0.1);border:1px solid rgba(248,113,113,0.3);}

  /* ── Divider / tabs ── */
  .sl-divider{height:1px;background:linear-gradient(90deg,transparent,var(--border),transparent);margin:20px 0;}
  .sl-tab-row{display:flex;gap:4px;margin-bottom:24px;background:rgba(255,255,255,0.03);border-radius:12px;padding:4px;border:1px solid var(--border);}
  .sl-tab{flex:1;padding:9px;font-size:11px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;border:none;background:transparent;color:var(--muted);cursor:pointer;border-radius:9px;font-family:'Space Mono',monospace;transition:all 0.15s;}
  .sl-tab.active{background:linear-gradient(135deg,rgba(139,92,246,0.2),rgba(52,211,153,0.1));color:var(--accent);border:1px solid var(--border2);}

  /* ── Network badge ── */
  .sl-network-badge{font-size:10px;color:var(--accent2);background:rgba(52,211,153,0.08);border:1px solid rgba(52,211,153,0.2);border-radius:20px;padding:3px 10px;letter-spacing:0.1em;}

  /* ── Token selector ── */
  .sl-token-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px;}
  .sl-token-btn{display:flex;flex-direction:column;align-items:center;gap:6px;padding:12px 8px;border-radius:12px;border:1px solid var(--border);background:transparent;cursor:pointer;transition:all 0.15s;font-family:'Space Mono',monospace;}
  .sl-token-btn:hover{border-color:var(--border2);background:rgba(139,92,246,0.06);}
  .sl-token-btn.active{border-color:var(--purple);background:rgba(139,92,246,0.12);box-shadow:0 0 16px rgba(139,92,246,0.2);}
  .sl-token-icon{width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;color:#fff;}
  .sl-token-symbol{font-size:11px;font-weight:700;color:var(--text);}
  .sl-token-name{font-size:9px;color:var(--muted);letter-spacing:0.08em;}

  /* ── Wallet dropdown ── */
  .sl-wallet-wrap{position:relative;}
  .sl-wallet-btn{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:20px;padding:5px 14px;cursor:pointer;font-size:11px;font-family:'Space Mono',monospace;color:var(--text);transition:border-color 0.2s,background 0.2s;}
  .sl-wallet-btn:hover{border-color:var(--border2);background:rgba(139,92,246,0.08);}
  .sl-wallet-dot{width:7px;height:7px;border-radius:50%;background:var(--accent2);box-shadow:0 0 6px var(--accent2);flex-shrink:0;}
  .sl-wallet-chevron{font-size:9px;color:var(--muted);margin-left:2px;}
  .sl-wallet-menu{position:absolute;top:calc(100% + 8px);right:0;background:var(--surface2);border:1px solid rgba(139,92,246,0.25);border-radius:14px;padding:6px;min-width:200px;box-shadow:0 16px 48px rgba(0,0,0,0.5),0 0 30px rgba(139,92,246,0.1);z-index:200;animation:slideUp 0.15s ease;}
  .sl-wallet-menu-item{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;font-size:12px;color:var(--text);cursor:pointer;transition:background 0.15s;font-family:'Space Mono',monospace;text-decoration:none;white-space:nowrap;}
  .sl-wallet-menu-item:hover{background:rgba(139,92,246,0.1);}
  .sl-wallet-menu-item.danger{color:var(--danger);}
  .sl-wallet-menu-item.danger:hover{background:rgba(248,113,113,0.08);}
  .sl-wallet-divider{height:1px;background:var(--border);margin:4px 0;}
`;

export default function ShieldLendApp() {
  const [account, setAccount]       = useState<string | null>(null);
  const [ethProvider, setEthProvider] = useState<BrowserProvider | null>(null);
  const [contract, setContract]     = useState<Contract | null>(null);
  const [fhevmInst, setFhevmInst]   = useState<any>(null);
  const [role, setRole]             = useState<Role>(null);
  const [isAdmin, setIsAdmin]       = useState(false);
  const [hasPosition, setHasPosition] = useState(false);
  const [borrowers, setBorrowers]   = useState<BorrowerEntry[]>([]);
  const [modal, setModal]           = useState<ModalType>(null);
  const [loading, setLoading]       = useState(false);
  const [toast, setToast]           = useState<Toast>(null);
  const [amount, setAmount]         = useState("");
  const [scoreTarget, setScoreTarget] = useState("");
  const [scoreAddr, setScoreAddr]   = useState("");
  const [resultMsg, setResultMsg]   = useState("");
  const [closeStep, setCloseStep]   = useState<CloseStep>("idle");
  const [activeTab, setActiveTab]   = useState<"position" | "protocol">("position");
  const [walletMenu, setWalletMenu]     = useState(false);
  const [selectedToken, setSelectedToken] = useState<TokenSymbol>("ETH");
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

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
    setTimeout(() => setToast(null), 4500);
  }, []);

  const encryptAmount = async (value: bigint) => {
    if (!fhevmInst || !account) throw new Error("FHE not initialized");
    const r = await fhevmInst.encryptUint({ value, type: "euint64", contractAddress: CONTRACT_ADDRESS, callerAddress: account });
    const { ethers } = await import("ethers");
    return { handle: ethers.hexlify(r.handles[0]), proof: ethers.hexlify(r.inputProof) };
  };

  // Returns ETH-wei equivalent for any token amount
  const toEthWei = (humanAmount: string, token: typeof TOKENS[number]): bigint => {
    const raw = parseUnits(humanAmount, token.decimals); // raw token units
    if (token.symbol === "ETH") return raw;
    // ethWeiEquiv = rawUnits * ethWeiPerToken / 10^decimals
    return raw * token.ethWeiPerToken / (10n ** BigInt(token.decimals));
  };

  // ─── Connection ─────────────────────────────────────────────────────────────
  const connect = async () => {
    const eth = (window as any).ethereum;
    if (!eth) { showToast("No wallet — install Rabby or MetaMask", "info"); return; }
    try {
      const provider  = new BrowserProvider(eth);
      await provider.send("eth_requestAccounts", []);

      // Enforce Sepolia
      const network = await provider.getNetwork();
      if (Number(network.chainId) !== CHAIN_ID) {
        try {
          await provider.send("wallet_switchEthereumChain", [{ chainId: `0x${CHAIN_ID.toString(16)}` }]);
        } catch {
          showToast("Please switch to Sepolia testnet", "error");
          return;
        }
      }
      setEthProvider(provider);
      const signer    = await provider.getSigner();
      const addr      = await signer.getAddress();
      setAccount(addr);

      let inst: any = null;
      try {
        await initSDK(); // ✅ load WASM (TFHE + KMS) before createInstance
        showToast("Connecting to FHE relayer…", "info");
        inst = await Promise.race([
          createInstance({ ...SepoliaConfig, network: eth, relayerUrl: `${window.location.origin}/api/zama-relay` }),
          new Promise((_, rej) => setTimeout(() => rej(new Error("FHE relayer timeout (60s)")), 60000))
        ]);
        console.log("fhevmjs: instance ready");
      } catch (e: any) {
        console.error("fhevmjs init failed:", e);
        // Fallback: try without custom relayerUrl (SepoliaConfig has its own)
        try {
          inst = await Promise.race([
            createInstance({ ...SepoliaConfig, network: eth }),
            new Promise((_, rej) => setTimeout(() => rej(new Error("FHE fallback timeout")), 30000))
          ]);
          console.log("fhevmjs: instance ready (fallback)");
        } catch (e2) {
          console.error("fhevmjs fallback failed:", e2);
          showToast("FHE relayer unreachable — encrypt/decrypt unavailable", "error");
        }
      }
      setFhevmInst(inst);

      const c = new Contract(CONTRACT_ADDRESS, ABI, signer);
      setContract(c);

      const [LIQUIDATOR, ADMIN] = await Promise.all([c.LIQUIDATOR_ROLE(), c.ADMIN_ROLE()]);
      const [isLiq, isAdm]     = await Promise.all([
        c.hasRole(LIQUIDATOR, addr), c.hasRole(ADMIN, addr)
      ]);
      setIsAdmin(isAdm);
      setRole(isAdm ? "admin" : isLiq ? "liquidator" : "borrower");

      const active = await c.isActive(addr);
      setHasPosition(active);

      const pendingClose = await c.isPendingClose(addr);
      setCloseStep(pendingClose ? "pending" : "idle");

      if (isLiq || isAdm) await loadBorrowers(c);

      showToast(`Connected: ${addr.slice(0,6)}...${addr.slice(-4)}`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
  };

  const disconnect = () => {
    setAccount(null); setEthProvider(null); setContract(null);
    setFhevmInst(null); setRole(null); setIsAdmin(false);
    setHasPosition(false); setBorrowers([]); setWalletMenu(false);
    setCloseStep("idle");
    if (pollRef.current) clearInterval(pollRef.current);
  };

  const loadBorrowers = async (c: Contract) => {
    const count = Number(await c.getBorrowerCount());
    const entries: BorrowerEntry[] = [];
    for (let i = 0; i < count; i++) {
      const addr = await c.borrowerList(i);
      const [pendingReveal, confirmedLiq, pendingClose] = await Promise.all([
        c.isPendingReveal(addr),
        c.isConfirmedLiquidatable(addr),
        c.isPendingClose(addr),
      ]);
      entries.push({ address: addr, pendingReveal, confirmedLiq, pendingClose });
    }
    setBorrowers(entries);
  };

  // Poll for state changes while operations are pending
  const startPolling = useCallback((c: Contract) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try { await loadBorrowers(c); } catch {}
    }, 6000);
    setTimeout(() => { if (pollRef.current) clearInterval(pollRef.current); }, 120000);
  }, []);

  // ─── Borrower actions ────────────────────────────────────────────────────────
  const handleDeposit = async () => {
    if (!contract || !account || !amount || !ethProvider) return;
    setLoading(true);
    try {
      if (!fhevmInst) throw new Error("FHE unavailable — wait for FHE online");
      const token = TOKENS.find(t => t.symbol === selectedToken)!;
      const ethWeiEquiv = toEthWei(amount, token);
      const { handle, proof } = await encryptAmount(ethWeiEquiv);

      if (token.symbol === "ETH") {
        const ethValue = parseEther(amount);
        const tx = await contract.deposit(handle, proof, { value: ethValue });
        await tx.wait();
      } else {
        // ERC20: approve then depositToken
        const signer = await ethProvider.getSigner();
        const tokenContract = new Contract(token.address, ERC20_ABI, signer);
        const rawAmount = parseUnits(amount, token.decimals);

        const allowance = await tokenContract.allowance(account, CONTRACT_ADDRESS);
        if (allowance < rawAmount) {
          showToast(`Approving ${token.symbol}...`, "info");
          const approveTx = await tokenContract.approve(CONTRACT_ADDRESS, rawAmount);
          await approveTx.wait();
        }

        const tx = await contract.depositToken(token.address, rawAmount, handle, proof);
        await tx.wait();
      }

      setHasPosition(true);
      setModal(null); setAmount("");
      showToast(`${amount} ${token.symbol} deposited as collateral`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleBorrow = async () => {
    if (!contract || !account || !amount) return;
    setLoading(true);
    try {
      if (!fhevmInst) throw new Error("FHE unavailable");
      const { handle, proof } = await encryptAmount(parseEther(amount));
      const tx = await contract.borrow(handle, proof);
      await tx.wait();
      setModal(null); setAmount("");
      showToast("Borrow recorded — debt encrypted on-chain");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleRepay = async () => {
    if (!contract || !account || !amount) return;
    setLoading(true);
    try {
      if (!fhevmInst) throw new Error("FHE unavailable");
      const { handle, proof } = await encryptAmount(parseEther(amount));
      const tx = await contract.repay(handle, proof);
      await tx.wait();
      setModal(null); setAmount("");
      showToast("Repayment applied");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  // Close position: Step 1 — mark totalDebt for public decryption
  const handleRequestClose = async () => {
    if (!contract || !account) return;
    setLoading(true);
    try {
      const tx = await contract.requestClosePosition();
      await tx.wait();
      setCloseStep("pending");
      showToast("Close requested — Zama relayer decrypting debt...", "info");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  // Decrypt my own position via re-encryption
  const handleDecrypt = async () => {
    if (!contract || !account) return;
    if (!fhevmInst) { showToast("FHE offline — relayer unreachable", "error"); return; }
    setLoading(true);
    try {
      const [collHandle, debtHandle, rateHandle, scoreHandle] = await Promise.all([
        contract.getEncryptedCollateral(account),
        contract.getEncryptedTotalDebt(account),
        contract.getEncryptedInterestRate(account),
        contract.getEncryptedCreditScore(account),
      ]);
      const { publicKey, privateKey } = fhevmInst.generateKeypair();
      const eip712   = fhevmInst.createEIP712(publicKey, CONTRACT_ADDRESS);
      const provider = new BrowserProvider((window as any).ethereum);
      const signer   = await provider.getSigner();
      const sig      = await signer.signTypedData(eip712.domain, { Reencrypt: eip712.types.Reencrypt }, eip712.message);

      const [collateral, debt, rate, score] = await Promise.all([
        fhevmInst.reencrypt(collHandle, privateKey, publicKey, sig, CONTRACT_ADDRESS, account),
        fhevmInst.reencrypt(debtHandle, privateKey, publicKey, sig, CONTRACT_ADDRESS, account),
        fhevmInst.reencrypt(rateHandle, privateKey, publicKey, sig, CONTRACT_ADDRESS, account),
        fhevmInst.reencrypt(scoreHandle, privateKey, publicKey, sig, CONTRACT_ADDRESS, account),
      ]);

      const fmtWei = (v: bigint) => `${v} wei  (${(Number(v) / 1e18).toFixed(6)} ETH)`;
      setResultMsg(
        `Collateral:    ${fmtWei(collateral)}\n` +
        `Total Debt:    ${fmtWei(debt)}\n` +
        `Interest Rate: ${rate} bps  (${Number(rate) / 100}%)\n` +
        `Credit Score:  ${score} / 1000`
      );
      setModal("result");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  // ─── Liquidator actions ──────────────────────────────────────────────────────
  const handleRequestReveal = async (addr: string) => {
    if (!contract) return;
    setLoading(true);
    try {
      const tx = await contract.requestLiquidationReveal(addr);
      await tx.wait();
      setBorrowers(prev => prev.map(b => b.address === addr ? { ...b, pendingReveal: true } : b));
      showToast(`Reveal requested — Zama relayer decrypting...`, "info");
      if (contract) startPolling(contract);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleLiquidate = async (addr: string) => {
    if (!contract) return;
    setLoading(true);
    try {
      const tx = await contract.liquidate(addr);
      await tx.wait();
      setBorrowers(prev => prev.filter(b => b.address !== addr));
      showToast(`Liquidated ${addr.slice(0,6)}... — ETH received`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  // ─── Admin actions ───────────────────────────────────────────────────────────
  const handleAccrueInterest = async (addr: string) => {
    if (!contract) return;
    setLoading(true);
    try {
      const tx = await contract.accrueInterest(addr);
      await tx.wait();
      showToast(`Interest accrued for ${addr.slice(0,6)}...`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleUpdateScore = async () => {
    if (!contract || !scoreAddr || !scoreTarget) return;
    setLoading(true);
    try {
      if (!fhevmInst) throw new Error("FHE unavailable");
      const r = await fhevmInst.encryptUint({ value: BigInt(scoreTarget), type: "euint64", contractAddress: CONTRACT_ADDRESS, callerAddress: account });
      const { ethers } = await import("ethers");
      const handle = ethers.hexlify(r.handles[0]);
      const proof  = ethers.hexlify(r.inputProof);
      const tx     = await contract.updateCreditScore(scoreAddr, handle, proof);
      await tx.wait();
      setModal(null); setScoreAddr(""); setScoreTarget("");
      showToast(`Credit score updated for ${scoreAddr.slice(0,6)}...`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  // ─── Render helpers ──────────────────────────────────────────────────────────
  const modalTitle = modal === "deposit" ? "Deposit Collateral"
    : modal === "borrow"  ? "Borrow Against Collateral"
    : modal === "repay"   ? "Repay Debt"
    : modal === "score"   ? "Update Credit Score"
    : "";
  const modalSub = modal === "deposit"
    ? "Amount encrypted client-side via Zama FHE before submission. Contract never sees plaintext."
    : modal === "borrow"
    ? "Borrow up to 66% of collateral value. Health factor enforced via encrypted comparison."
    : modal === "repay"
    ? "Partial or full repayment. Encrypted subtraction with floor-at-zero applied on-chain."
    : "Admin only. Score encrypted before submission. Higher score = lower interest rate.";

  const renderCloseSection = () => {
    if (closeStep === "pending") return (
      <div style={{ display:"flex", alignItems:"center", gap:12, padding:"14px 0", borderTop:"1px solid var(--border)" }}>
        <span className="sl-step-pill pending">⏳ Close Pending</span>
        <span style={{ fontSize:12, color:"var(--muted)" }}>Zama relayer is verifying zero-debt — position will close automatically</span>
      </div>
    );
    return (
      <div style={{ padding:"14px 0", borderTop:"1px solid var(--border)" }}>
        <div style={{ fontSize:12, color:"var(--muted)", marginBottom:10 }}>
          Withdraw your collateral ETH — requires zero debt. Relayer verifies on-chain.
        </div>
        <button className="sl-btn-warn" onClick={handleRequestClose} disabled={loading}>
          {loading ? <span className="sl-spinner" /> : "Request Close Position"}
        </button>
      </div>
    );
  };

  const renderBorrowerCard = () => (
    <div className="sl-card">
      <div className="sl-tab-row">
        <button className={`sl-tab ${activeTab === "position" ? "active" : ""}`} onClick={() => setActiveTab("position")}>Position</button>
        <button className={`sl-tab ${activeTab === "protocol" ? "active" : ""}`} onClick={() => setActiveTab("protocol")}>Protocol</button>
      </div>
      {activeTab === "position" ? (
        hasPosition ? (
          <>
            <div className="sl-row"><span className="sl-row-label">Collateral (ETH)</span><span className="enc-tag">🔒 euint64</span></div>
            <div className="sl-row"><span className="sl-row-label">Total Debt</span><span className="enc-tag">🔒 euint64</span></div>
            <div className="sl-row"><span className="sl-row-label">Interest Rate</span><span className="enc-tag">🔒 euint64</span></div>
            <div className="sl-row"><span className="sl-row-label">Credit Score</span><span className="enc-tag">🔒 euint64</span></div>
            <div className="sl-row"><span className="sl-row-label">Health Factor</span><span className="enc-tag">🔒 ebool</span></div>
            <div className="sl-actions">
              <button className="sl-btn"       onClick={() => setModal("deposit")} disabled={loading}>+ Deposit</button>
              <button className="sl-btn"       onClick={() => setModal("borrow")}  disabled={loading}>Borrow</button>
              <button className="sl-btn"       onClick={() => setModal("repay")}   disabled={loading}>Repay</button>
              <button className="sl-btn-ghost" onClick={handleDecrypt}             disabled={loading || !fhevmInst}>
                {loading ? <span className="sl-spinner" /> : "🔓 Decrypt Position"}
              </button>
            </div>
            {renderCloseSection()}
          </>
        ) : (
          <div className="sl-empty">
            <div className="sl-empty-icon">🏦</div>
            <div style={{ marginBottom:20 }}>No active position. Deposit ETH collateral to get started.</div>
            <button className="sl-btn" onClick={() => setModal("deposit")}>Deposit Collateral →</button>
          </div>
        )
      ) : (
        <>
          <div className="sl-info-row"><span style={{ color:"var(--muted)",fontSize:13 }}>Collateral Ratio</span><span style={{ fontSize:13 }}>150%</span></div>
          <div className="sl-info-row"><span style={{ color:"var(--muted)",fontSize:13 }}>Base Interest Rate</span><span style={{ fontSize:13 }}>5% <span style={{ color:"var(--muted)" }}>(500 bps)</span></span></div>
          <div className="sl-info-row"><span style={{ color:"var(--muted)",fontSize:13 }}>Max Loan Ratio</span><span style={{ fontSize:13 }}>66% of collateral</span></div>
          <div className="sl-info-row"><span style={{ color:"var(--muted)",fontSize:13 }}>Liquidation Threshold</span><span style={{ fontSize:13 }}>110% <span className="enc-tag">ebool</span></span></div>
          <div className="sl-info-row"><span style={{ color:"var(--muted)",fontSize:13 }}>Network</span><span style={{ fontSize:13 }}>Sepolia Testnet</span></div>
          <div className="sl-info-row">
            <span style={{ color:"var(--muted)",fontSize:13 }}>Lending Contract</span>
            <a href={`https://sepolia.etherscan.io/address/${CONTRACT_ADDRESS}`} target="_blank" rel="noreferrer" className="sl-contract-link">
              {CONTRACT_ADDRESS.slice(0,10)}...{CONTRACT_ADDRESS.slice(-6)} ↗
            </a>
          </div>
          {SCORE_CONTRACT_ADDRESS && (
            <div className="sl-info-row">
              <span style={{ color:"var(--muted)",fontSize:13 }}>ShieldScore Contract</span>
              <a href={`https://sepolia.etherscan.io/address/${SCORE_CONTRACT_ADDRESS}`} target="_blank" rel="noreferrer" className="sl-contract-link">
                {SCORE_CONTRACT_ADDRESS.slice(0,10)}...{SCORE_CONTRACT_ADDRESS.slice(-6)} ↗
              </a>
            </div>
          )}
        </>
      )}
    </div>
  );

  const renderLiqEntry = (b: BorrowerEntry) => (
    <div className="sl-borrower-item" key={b.address}>
      <div className="sl-borrower-row">
        <div>
          <div style={{ fontSize:12, fontFamily:"Space Mono,monospace", marginBottom:6 }}>
            {b.address.slice(0,10)}...{b.address.slice(-6)}
          </div>
          <div style={{ display:"flex", gap:6, flexWrap:"wrap" }}>
            <span className="enc-tag">🔒 health factor encrypted</span>
            {b.pendingReveal  && <span className="sl-step-pill pending">reveal pending</span>}
            {b.confirmedLiq   && <span className="sl-step-pill danger">confirmed liq</span>}
            {b.pendingClose   && <span className="sl-step-pill pending">close pending</span>}
          </div>
        </div>
        <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
          {!b.pendingReveal && !b.confirmedLiq && (
            <button className="sl-btn-ghost" onClick={() => handleRequestReveal(b.address)} disabled={loading} style={{ fontSize:11 }}>
              🔍 Request Reveal
            </button>
          )}
          {b.pendingReveal && !b.confirmedLiq && (
            <span style={{ fontSize:11, color:"var(--muted)", padding:"8px 0" }}>Awaiting relayer...</span>
          )}
          {b.confirmedLiq && (
            <button className="sl-btn-danger" onClick={() => handleLiquidate(b.address)} disabled={loading}>
              {loading ? <span className="sl-spinner" /> : "Liquidate ↯"}
            </button>
          )}
          {isAdmin && (
            <button className="sl-btn-warn" onClick={() => handleAccrueInterest(b.address)} disabled={loading} style={{ fontSize:11 }}>
              + Interest
            </button>
          )}
        </div>
      </div>
    </div>
  );

  const renderLiquidatorCard = () => (
    <div className="sl-card">
      <div className="sl-section-title">Active Positions ({borrowers.length})</div>
      {isAdmin && (
        <div style={{ display:"flex", justifyContent:"flex-end", marginBottom:16 }}>
          <button className="sl-btn-warn" onClick={() => setModal("score")} disabled={loading} style={{ fontSize:11 }}>
            Update Credit Score
          </button>
        </div>
      )}
      {borrowers.length === 0
        ? <div className="sl-empty"><div className="sl-empty-icon">✓</div>No active positions</div>
        : borrowers.map(renderLiqEntry)
      }
    </div>
  );

  // ─── Render ──────────────────────────────────────────────────────────────────
  return (
    <div className="sl-app">
      <header className="sl-header">
        <div className="sl-logo">
          <div className="sl-logo-icon">⬡</div>
          <span className="sl-logo-text">SHIELDLEND</span>
        </div>
        <div className="sl-header-right">
          <span className="sl-network-badge">Sepolia</span>
          {account && (
            <div className="sl-fhe-status">
              <div className={`sl-fhe-dot ${fhevmInst ? "" : "offline"}`} />
              <span>FHE {fhevmInst ? "online" : "offline"}</span>
            </div>
          )}
          {account && role && (
            <span className={`sl-role-badge ${isAdmin ? "admin" : ""}`}>{isAdmin ? "admin" : role}</span>
          )}
          {account ? (
            <div className="sl-wallet-wrap">
              <div className="sl-wallet-btn" onClick={() => setWalletMenu(v => !v)}>
                <span className="sl-wallet-dot" />
                {account.slice(0,6)}...{account.slice(-4)}
                <span className="sl-wallet-chevron">{walletMenu ? "▲" : "▼"}</span>
              </div>
              {walletMenu && (
                <div className="sl-wallet-menu" onClick={() => setWalletMenu(false)}>
                  <a
                    className="sl-wallet-menu-item"
                    href={`https://sepolia.etherscan.io/address/${account}`}
                    target="_blank" rel="noreferrer"
                  >
                    <span>↗</span> View on Etherscan
                  </a>
                  <div className="sl-wallet-divider" />
                  <div className="sl-wallet-menu-item" onClick={connect}>
                    <span>⇄</span> Change Wallet
                  </div>
                  <div className="sl-wallet-menu-item danger" onClick={disconnect}>
                    <span>⏻</span> Disconnect
                  </div>
                </div>
              )}
            </div>
          ) : (
            <button className="sl-connect-btn" onClick={connect}>Connect Wallet</button>
          )}
        </div>
      </header>

      <div className="sl-main">
        {!account ? (
          <div className="sl-hero">
            <div className="sl-hero-eyebrow">Powered by Zama fhEVM · Sepolia Testnet</div>
            <h1 className="sl-hero-title">Confidential<br />On-Chain Lending</h1>
            <p className="sl-hero-sub">
              Collateral, debt, credit scores and interest rates stay encrypted at all times —
              even the contract cannot read them. Fully Homomorphic Encryption on Ethereum.
            </p>
            <button className="sl-btn-hero" onClick={connect}>Launch App →</button>
            <div className="sl-feature-grid">
              {[
                { icon:"🔐", color:"purple", title:"Encrypted Positions",    desc:"All amounts stored as euint64 ciphertexts. No plaintext leaks on-chain." },
                { icon:"📊", color:"teal",   title:"FHE Health Factor",      desc:"Liquidation enforced via ebool — the protocol never sees your ratio." },
                { icon:"🎯", color:"blue",   title:"Credit-Gated Rates",     desc:"ShieldScore gates your interest rate and collateral ratio privately." },
              ].map(f => (
                <div className="sl-feature-card" key={f.title}>
                  <div className={`sl-feature-icon ${f.color}`}>{f.icon}</div>
                  <div className="sl-feature-title">{f.title}</div>
                  <div className="sl-feature-desc">{f.desc}</div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <>
            <div className="sl-grid-3">
              <div className="sl-card">
                <div className="sl-card-label">Active Borrowers</div>
                <div className="sl-card-value">{borrowers.length}</div>
              </div>
              <div className={`sl-card ${hasPosition ? "sl-stat-active" : ""}`}>
                <div className="sl-card-label">Your Position</div>
                <div className="sl-card-value">
                  {hasPosition ? "Active" : <span style={{ color:"var(--muted)", fontSize:20, WebkitTextFillColor:"var(--muted)" }}>None</span>}
                </div>
              </div>
              <div className="sl-card">
                <div className="sl-card-label">Protocol Reserves</div>
                <div style={{ paddingTop:6 }}>
                  <span className="enc-tag">🔒 euint64</span>
                </div>
              </div>
            </div>

            {(role === "borrower" || isAdmin) && renderBorrowerCard()}
            {(role === "liquidator" || isAdmin) && renderLiquidatorCard()}
            {account && ethProvider && SCORE_CONTRACT_ADDRESS && (
              <ShieldScore
                account={account}
                provider={ethProvider}
                fhevmInst={fhevmInst}
                isOracle={isAdmin}
                onToast={showToast}
              />
            )}
          </>
        )}
      </div>

      {/* Deposit modal */}
      {modal === "deposit" && (
        <div className="sl-overlay" onClick={() => setModal(null)}>
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
              <div style={{ fontSize:11, color:"var(--muted)", marginBottom:12, marginTop:-8 }}>
                ≈ {amount ? (Number(amount) * (selectedToken === "USDC" ? 1/3000 : 1/100)).toFixed(4) : "0"} ETH equivalent · Approve + deposit in 2 txns
              </div>
            )}
            <div style={{ display:"flex", gap:8 }}>
              <button className="sl-btn" style={{ flex:1 }} disabled={loading || !amount} onClick={handleDeposit}>
                {loading ? <span className="sl-spinner" /> : `Deposit ${selectedToken} →`}
              </button>
              <button className="sl-btn-ghost" onClick={() => setModal(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Borrow / Repay modal */}
      {(modal === "borrow" || modal === "repay") && (
        <div className="sl-overlay" onClick={() => setModal(null)}>
          <div className="sl-modal" onClick={e => e.stopPropagation()}>
            <div className="sl-modal-title">{modalTitle}</div>
            <div className="sl-modal-sub">{modalSub}</div>
            <input className="sl-input" type="number" step="0.001" min="0" placeholder="Amount in ETH (e.g. 0.1)"
              value={amount} onChange={e => setAmount(e.target.value)} autoFocus />
            <div style={{ display:"flex", gap:8 }}>
              <button className="sl-btn" style={{ flex:1 }} disabled={loading || !amount}
                onClick={modal === "borrow" ? handleBorrow : handleRepay}>
                {loading ? <span className="sl-spinner" /> : modal === "borrow" ? "Borrow →" : "Repay →"}
              </button>
              <button className="sl-btn-ghost" onClick={() => setModal(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Credit score modal */}
      {modal === "score" && (
        <div className="sl-overlay" onClick={() => setModal(null)}>
          <div className="sl-modal" onClick={e => e.stopPropagation()}>
            <div className="sl-modal-title">Update Credit Score</div>
            <div className="sl-modal-sub">Score encrypted before submission (0–1000). Higher score reduces interest rate. Admin only.</div>
            <input className="sl-input" type="text" placeholder="Borrower address (0x...)"
              value={scoreAddr} onChange={e => setScoreAddr(e.target.value)} />
            <input className="sl-input" type="number" min="0" max="1000" placeholder="Score (0-1000)"
              value={scoreTarget} onChange={e => setScoreTarget(e.target.value)} autoFocus />
            <div style={{ display:"flex", gap:8 }}>
              <button className="sl-btn" style={{ flex:1 }} disabled={loading || !scoreAddr || !scoreTarget} onClick={handleUpdateScore}>
                {loading ? <span className="sl-spinner" /> : "Set Score →"}
              </button>
              <button className="sl-btn-ghost" onClick={() => setModal(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Decrypt result modal */}
      {modal === "result" && (
        <div className="sl-overlay" onClick={() => setModal(null)}>
          <div className="sl-modal" onClick={e => e.stopPropagation()}>
            <div className="sl-modal-title">🔓 Decrypted Position</div>
            <div className="sl-modal-sub">Re-encrypted via Zama KMS — decrypted locally with your wallet keypair.</div>
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
