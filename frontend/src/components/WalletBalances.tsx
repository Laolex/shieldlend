import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { BrowserProvider, Contract, formatEther, formatUnits } from "ethers";
import { TOKENS } from "../config";

const ERC20_ABI = [
  "function balanceOf(address) view returns (uint256)",
];
const FAUCET_ABI = [
  "function faucet() external",
];

interface WalletBalancesProps {
  account: string;
  provider: BrowserProvider;
  showToast: (msg: string, kind?: "success" | "error" | "info") => void;
}

export default function WalletBalances({ account, provider, showToast }: WalletBalancesProps) {
  const [balances, setBalances] = useState<Record<string, string>>({});
  const [minting, setMinting] = useState(false);

  const loadBalances = async () => {
    try {
      const ethBal = await provider.getBalance(account);
      const bals: Record<string, string> = { ETH: formatEther(ethBal) };

      for (const token of TOKENS) {
        if (token.address === "native") continue;
        try {
          const c = new Contract(token.address, ERC20_ABI, provider);
          const bal = await c.balanceOf(account);
          bals[token.symbol] = formatUnits(bal, token.decimals);
        } catch {
          bals[token.symbol] = "0";
        }
      }
      setBalances(bals);
    } catch {}
  };

  useEffect(() => { loadBalances(); }, [account]);

  const handleMintZama = async () => {
    setMinting(true);
    try {
      const zamaToken = TOKENS.find(t => t.symbol === "ZAMA")!;
      const signer = await provider.getSigner();
      const c = new Contract(zamaToken.address, FAUCET_ABI, signer);
      const tx = await c.faucet();
      showToast("Minting 10,000 ZAMA...", "info");
      await tx.wait();
      showToast("10,000 ZAMA minted");
      await loadBalances();
    } catch (e: any) {
      showToast(e.message?.slice(0, 80), "error");
    }
    setMinting(false);
  };

  const tokens = TOKENS.map(t => ({
    symbol: t.symbol,
    icon: t.icon,
    color: t.color,
    balance: balances[t.symbol] ?? "...",
    mintable: t.symbol === "ZAMA",
  }));

  return (
    <motion.div
      className="sl-card-glass"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: 0.25 }}
      style={{ marginBottom: 16 }}
    >
      <div className="sl-card-label">Wallet Balances</div>
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 12 }}>
        {tokens.map(t => (
          <div key={t.symbol} style={{
            display: "flex", alignItems: "center", gap: 10,
            background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)",
            borderRadius: 12, padding: "10px 16px", flex: "1 1 auto", minWidth: 160,
          }}>
            <div style={{
              width: 32, height: 32, borderRadius: "50%", background: t.color,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 14, fontWeight: 700, color: "#fff", flexShrink: 0,
            }}>
              {t.icon}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 11, color: "var(--muted)", letterSpacing: "0.08em" }}>{t.symbol}</div>
              <div style={{ fontSize: 14, fontWeight: 700 }}>
                {t.balance === "..." ? "..." : Number(t.balance).toFixed(t.symbol === "USDC" ? 2 : 4)}
              </div>
            </div>
            {t.mintable && (
              <button
                onClick={handleMintZama}
                disabled={minting}
                style={{
                  background: "rgba(245,200,66,0.1)", border: "1px solid rgba(245,200,66,0.3)",
                  color: "#f5c842", borderRadius: 8, padding: "5px 10px",
                  fontSize: 10, fontWeight: 700, cursor: "pointer",
                  fontFamily: "'Space Mono', monospace", letterSpacing: "0.06em",
                  opacity: minting ? 0.5 : 1,
                }}
              >
                {minting ? "..." : "Faucet"}
              </button>
            )}
          </div>
        ))}
      </div>
    </motion.div>
  );
}
