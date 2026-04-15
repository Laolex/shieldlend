export const CONTRACT_ADDRESS   = "0xF9d0f6910f054b4ba36d796475Ae581b7Caad60F";
export const SCORE_CONTRACT_ADDRESS = (import.meta.env.VITE_SCORE_CONTRACT_ADDRESS ?? "").trim();
export const NETWORK_NAME       = "Sepolia";
export const CHAIN_ID           = 11155111;

// Supported collateral tokens
export const TOKENS = [
  {
    symbol:   "ETH",
    name:     "Ether",
    address:  "native",
    decimals: 18,
    // 1 ETH = 1e18 wei — no conversion needed
    ethWeiPerToken: 1n * (10n ** 18n),
    color:    "#627eea",
    icon:     "Ξ",
  },
  {
    symbol:   "USDC",
    name:     "USD Coin",
    address:  "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    decimals: 6,
    // 1 USDC = 1/3000 ETH = 333333333333333 wei
    ethWeiPerToken: 333333333333333n,
    color:    "#2775ca",
    icon:     "$",
  },
  {
    symbol:   "ZAMA",
    name:     "Mock ZAMA",
    address:  "0x8a618d072fF0AA818bC92e2408C5305000477cA7",
    decimals: 18,
    // 1 ZAMA = 1/100 ETH = 10000000000000000 wei
    ethWeiPerToken: 10000000000000000n,
    color:    "#f5c842",
    icon:     "Z",
  },
] as const;

export type TokenSymbol = "ETH" | "USDC" | "ZAMA";
