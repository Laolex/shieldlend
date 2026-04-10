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
      <div className="sl-hero-eyebrow">Powered by Zama fhEVM &middot; Sepolia Testnet</div>
      <h1 className="sl-hero-title">Confidential<br />On-Chain Lending</h1>
      <p className="sl-hero-sub">
        Collateral, debt, credit scores and interest rates stay encrypted at all times &mdash;
        even the contract cannot read them. Fully Homomorphic Encryption on Ethereum.
      </p>
      <button className="sl-btn-hero" onClick={onConnect}>Launch App &rarr;</button>
      <div className="sl-feature-grid">
        {features.map(f => (
          <div className="sl-feature-card" key={f.title}>
            <div className={`sl-feature-icon ${f.color}`}>{f.icon}</div>
            <div className="sl-feature-title">{f.title}</div>
            <div className="sl-feature-desc">{f.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
