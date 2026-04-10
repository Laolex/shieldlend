import type { Role } from "../types";

interface HeaderProps {
  account: string | null;
  role: Role;
  isAdmin: boolean;
  fhevmInst: any;
  walletMenu: boolean;
  setWalletMenu: (v: boolean | ((prev: boolean) => boolean)) => void;
  onConnect: () => void;
  onDisconnect: () => void;
}

export default function Header({
  account, role, isAdmin, fhevmInst,
  walletMenu, setWalletMenu, onConnect, onDisconnect,
}: HeaderProps) {
  return (
    <header className="sl-header">
      <div className="sl-logo">
        <div className="sl-logo-icon">&#x2B21;</div>
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
          <span className={`sl-role-badge ${isAdmin ? "admin" : ""}`}>
            {isAdmin ? "admin" : role}
          </span>
        )}
        {account ? (
          <div className="sl-wallet-wrap">
            <div className="sl-wallet-btn" onClick={() => setWalletMenu((v: boolean) => !v)}>
              <span className="sl-wallet-dot" />
              {account.slice(0, 6)}...{account.slice(-4)}
              <span className="sl-wallet-chevron">{walletMenu ? "\u25B2" : "\u25BC"}</span>
            </div>
            {walletMenu && (
              <div className="sl-wallet-menu" onClick={() => setWalletMenu(false)}>
                <a
                  className="sl-wallet-menu-item"
                  href={`https://sepolia.etherscan.io/address/${account}`}
                  target="_blank" rel="noreferrer"
                >
                  <span>&nearr;</span> View on Etherscan
                </a>
                <div className="sl-wallet-divider" />
                <div className="sl-wallet-menu-item" onClick={onConnect}>
                  <span>&xharr;</span> Change Wallet
                </div>
                <div className="sl-wallet-menu-item danger" onClick={onDisconnect}>
                  <span>&#x23FB;</span> Disconnect
                </div>
              </div>
            )}
          </div>
        ) : (
          <button className="sl-connect-btn" onClick={onConnect}>Connect Wallet</button>
        )}
      </div>
    </header>
  );
}
