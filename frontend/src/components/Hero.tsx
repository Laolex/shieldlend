import { motion } from "framer-motion";

interface HeroProps {
  onConnect: () => void;
}

export default function Hero({ onConnect }: HeroProps) {
  const features = [
    { icon: "\uD83D\uDD10", color: "purple", title: "Encrypted Positions", desc: "All amounts stored as euint64 ciphertexts. No plaintext leaks on-chain." },
    { icon: "\uD83D\uDCCA", color: "teal",   title: "FHE Health Factor",   desc: "Liquidation enforced via ebool \u2014 the protocol never sees your ratio." },
    { icon: "\uD83C\uDFAF", color: "blue",   title: "Credit-Gated Rates",  desc: "ShieldScore gates your interest rate and collateral ratio privately." },
  ];

  return (
    <div className="sl-hero">
      <motion.div
        className="sl-hero-eyebrow"
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        Powered by Zama fhEVM &middot; Sepolia Testnet
      </motion.div>
      <motion.h1
        className="sl-hero-title"
        initial={{ opacity: 0, y: 20, filter: "blur(8px)" }}
        animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
        transition={{ duration: 0.6, delay: 0.1 }}
      >
        Confidential<br />On-Chain Lending
      </motion.h1>
      <motion.p
        className="sl-hero-sub"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.5, delay: 0.3 }}
      >
        Collateral, debt, credit scores and interest rates stay encrypted at all times &mdash;
        even the contract cannot read them. Fully Homomorphic Encryption on Ethereum.
      </motion.p>
      <motion.button
        className="sl-btn-hero"
        onClick={onConnect}
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.4, delay: 0.45 }}
        whileHover={{ scale: 1.03 }}
        whileTap={{ scale: 0.97 }}
      >
        Launch App &rarr;
      </motion.button>
      <div className="sl-feature-grid">
        {features.map((f, i) => (
          <motion.div
            className="sl-feature-card"
            key={f.title}
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.55 + i * 0.1 }}
            whileHover={{ y: -3, borderColor: "rgba(139,92,246,0.35)" }}
          >
            <div className={`sl-feature-icon ${f.color}`}>{f.icon}</div>
            <div className="sl-feature-title">{f.title}</div>
            <div className="sl-feature-desc">{f.desc}</div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
