export const STYLES = `
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

  /* ── Encrypted shimmer (FHE state: data hidden) ── */
  @keyframes enc-shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
  .enc-shimmer{display:inline-block;min-width:80px;height:18px;border-radius:4px;background:linear-gradient(110deg,rgba(139,92,246,0.12) 25%,rgba(139,92,246,0.25) 37%,rgba(139,92,246,0.12) 63%);background-size:200% 100%;animation:enc-shimmer 1.5s ease-in-out infinite;vertical-align:middle;}
  .enc-shimmer.wide{min-width:120px;}

  /* ── Glassmorphism card variant ── */
  .sl-card-glass{background:rgba(12,16,32,0.55);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid rgba(139,92,246,0.18);border-radius:18px;padding:24px 28px;margin-bottom:16px;position:relative;overflow:hidden;transition:border-color 0.3s,box-shadow 0.3s;}
  .sl-card-glass:hover{border-color:rgba(139,92,246,0.35);box-shadow:0 0 40px rgba(139,92,246,0.15),0 0 80px rgba(139,92,246,0.05);}
  .sl-card-glass::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.45),rgba(52,211,153,0.2),transparent);}

  /* ── Decrypt reveal animation ── */
  @keyframes decrypt-reveal{from{opacity:0;filter:blur(8px);transform:translateY(6px)}to{opacity:1;filter:blur(0);transform:translateY(0)}}
  .decrypt-reveal{animation:decrypt-reveal 0.4s ease-out forwards;opacity:0;}

  /* ── FHE computation pipeline bar ── */
  .sl-pipeline{display:flex;align-items:center;gap:12px;padding:14px 18px;background:rgba(139,92,246,0.04);border:1px solid rgba(139,92,246,0.12);border-radius:12px;margin-bottom:16px;font-size:11px;color:var(--muted);}
  .sl-pipeline-step{display:flex;align-items:center;gap:6px;transition:color 0.3s,opacity 0.3s;}
  .sl-pipeline-step.active{color:var(--accent);}
  .sl-pipeline-step.done{color:var(--enc);}
  .sl-pipeline-arrow{color:rgba(139,92,246,0.3);font-size:10px;}
  .sl-pipeline-bar{flex:1;height:3px;background:rgba(139,92,246,0.1);border-radius:99px;overflow:hidden;}
  .sl-pipeline-fill{height:100%;background:linear-gradient(90deg,var(--purple),var(--enc));border-radius:99px;transition:width 0.6s ease-out;}

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

  /* ── Admin panel ── */
  .sl-admin-card{border-color:rgba(251,191,36,0.2)!important;}
  .sl-admin-card:hover{border-color:rgba(251,191,36,0.4)!important;box-shadow:0 0 30px rgba(251,191,36,0.08)!important;}
  .sl-admin-card::before{background:linear-gradient(90deg,transparent,rgba(251,191,36,0.3),transparent)!important;}
  .sl-admin-card .sl-tab.active{background:linear-gradient(135deg,rgba(251,191,36,0.15),rgba(251,191,36,0.05));color:var(--warn);border-color:rgba(251,191,36,0.3);}

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

export function injectStyles() {
  const id = "sl-styles";
  if (!document.getElementById(id)) {
    const el = document.createElement("style");
    el.id = id;
    el.textContent = STYLES;
    document.head.appendChild(el);
  }
}
