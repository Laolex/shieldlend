import { BrowserProvider, Contract, parseEther, parseUnits } from "ethers";
import { initSDK, createInstance, SepoliaConfig } from "./vendor/relayer-sdk/web.js";
import { useCallback, useEffect, useRef, useState } from "react";
import ABI from "./abi.json";
import { CONTRACT_ADDRESS, SCORE_CONTRACT_ADDRESS, CHAIN_ID, TOKENS, type TokenSymbol } from "./config";
import { injectStyles } from "./styles";
import type { Role, ModalType, Toast as ToastType, CloseStep, BorrowerEntry, ProtocolStats } from "./types";

import Header from "./components/Header";
import Hero from "./components/Hero";
import StatsBar from "./components/StatsBar";
import BorrowerCard from "./components/BorrowerCard";
import LiquidatorCard from "./components/LiquidatorCard";
import AdminPanel from "./components/AdminPanel";
import { DepositModal, AmountModal, ScoreModal, ResultModal } from "./components/Modals";
import Toast from "./components/Toast";
import ShieldScore from "./ShieldScore";

const ERC20_ABI = [
  "function approve(address spender, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function balanceOf(address account) view returns (uint256)",
];

export default function ShieldLendApp() {
  const [account, setAccount]         = useState<string | null>(null);
  const [ethProvider, setEthProvider]  = useState<BrowserProvider | null>(null);
  const [contract, setContract]       = useState<Contract | null>(null);
  const [fhevmInst, setFhevmInst]     = useState<any>(null);
  const [role, setRole]               = useState<Role>(null);
  const [isAdmin, setIsAdmin]         = useState(false);
  const [hasPosition, setHasPosition] = useState(false);
  const [borrowers, setBorrowers]     = useState<BorrowerEntry[]>([]);
  const [modal, setModal]             = useState<ModalType>(null);
  const [loading, setLoading]         = useState(false);
  const [toast, setToast]             = useState<ToastType>(null);
  const [resultMsg, setResultMsg]     = useState("");
  const [closeStep, setCloseStep]     = useState<CloseStep>("idle");
  const [activeTab, setActiveTab]     = useState<"position" | "protocol">("position");
  const [walletMenu, setWalletMenu]   = useState(false);
  const [protocolStats, setProtocolStats] = useState<ProtocolStats | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => { injectStyles(); }, []);

  const showToast = useCallback((message: string, kind: "success" | "error" | "info" = "success") => {
    setToast({ message, kind });
    setTimeout(() => setToast(null), 4500);
  }, []);

  // ─── FHE encryption helper ─────────────────────────────────────────────────
  const encryptAmount = async (value: bigint) => {
    if (!fhevmInst || !account) throw new Error("FHE not initialized");
    const input = fhevmInst.createEncryptedInput(CONTRACT_ADDRESS, account);
    input.add64(value);
    const r = await input.encrypt();
    const { ethers } = await import("ethers");
    return { handle: ethers.hexlify(r.handles[0]), proof: ethers.hexlify(r.inputProof) };
  };

  const toEthWei = (humanAmount: string, token: typeof TOKENS[number]): bigint => {
    const raw = parseUnits(humanAmount, token.decimals);
    if (token.symbol === "ETH") return raw;
    return raw * token.ethWeiPerToken / (10n ** BigInt(token.decimals));
  };

  // ─── Data loaders ──────────────────────────────────────────────────────────
  const loadProtocolStats = async (c: Contract) => {
    try {
      const [pr, tr, erb, esc, mbp, rfb, mrr] = await Promise.all([
        c.protocolReserve(), c.totalReserves(), c.effectiveRateBps(),
        c.ethSupplyCap(), c.maxBorrowPerPosition(),
        c.reserveFactorBps(), c.minReserveRatioBps(),
      ]);
      setProtocolStats({
        protocolReserve: BigInt(pr), totalReserves: BigInt(tr),
        effectiveRateBps: BigInt(erb), ethSupplyCap: BigInt(esc),
        maxBorrowPerPosition: BigInt(mbp), reserveFactorBps: BigInt(rfb),
        minReserveRatioBps: BigInt(mrr),
      });
    } catch {}
  };

  const loadBorrowers = async (c: Contract) => {
    const count = Number(await c.getBorrowerCount());
    const entries: BorrowerEntry[] = [];
    for (let i = 0; i < count; i++) {
      const addr = await c.borrowerList(i);
      const [pendingReveal, confirmedLiq, pendingClose] = await Promise.all([
        c.isPendingReveal(addr), c.isConfirmedLiquidatable(addr), c.isPendingClose(addr),
      ]);
      entries.push({ address: addr, pendingReveal, confirmedLiq, pendingClose });
    }
    setBorrowers(entries);
  };

  const startPolling = useCallback((c: Contract) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try { await loadBorrowers(c); } catch {}
    }, 6000);
    setTimeout(() => { if (pollRef.current) clearInterval(pollRef.current); }, 120000);
  }, []);

  // ─── Connection ────────────────────────────────────────────────────────────
  const connect = async () => {
    const eth = (window as any).ethereum;
    if (!eth) { showToast("No wallet \u2014 install Rabby or MetaMask", "info"); return; }
    try {
      const provider = new BrowserProvider(eth);
      await provider.send("eth_requestAccounts", []);

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
      const signer = await provider.getSigner();
      const addr = await signer.getAddress();
      setAccount(addr);

      let inst: any = null;
      try {
        await initSDK();
        showToast("Connecting to FHE relayer\u2026", "info");
        inst = await Promise.race([
          createInstance({ ...SepoliaConfig, network: eth, relayerUrl: `${window.location.origin}/api/zama-relay` }),
          new Promise((_, rej) => setTimeout(() => rej(new Error("FHE relayer timeout (60s)")), 60000))
        ]);
      } catch (e: any) {
        try {
          inst = await Promise.race([
            createInstance({ ...SepoliaConfig, network: eth }),
            new Promise((_, rej) => setTimeout(() => rej(new Error("FHE fallback timeout")), 30000))
          ]);
        } catch {
          showToast("FHE relayer unreachable \u2014 encrypt/decrypt unavailable", "error");
        }
      }
      setFhevmInst(inst);

      const c = new Contract(CONTRACT_ADDRESS, ABI, signer);
      setContract(c);

      const [LIQUIDATOR, ADMIN] = await Promise.all([c.LIQUIDATOR_ROLE(), c.ADMIN_ROLE()]);
      const [isLiq, isAdm] = await Promise.all([c.hasRole(LIQUIDATOR, addr), c.hasRole(ADMIN, addr)]);
      setIsAdmin(isAdm);
      setRole(isAdm ? "admin" : isLiq ? "liquidator" : "borrower");

      const active = await c.isActive(addr);
      setHasPosition(active);

      const pendingClose = await c.isPendingClose(addr);
      setCloseStep(pendingClose ? "pending" : "idle");

      if (isLiq || isAdm) await loadBorrowers(c);
      await loadProtocolStats(c);

      showToast(`Connected: ${addr.slice(0, 6)}...${addr.slice(-4)}`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
  };

  const disconnect = () => {
    setAccount(null); setEthProvider(null); setContract(null);
    setFhevmInst(null); setRole(null); setIsAdmin(false);
    setHasPosition(false); setBorrowers([]); setWalletMenu(false);
    setCloseStep("idle");
    if (pollRef.current) clearInterval(pollRef.current);
  };

  // ─── Borrower actions ──────────────────────────────────────────────────────
  const handleDeposit = async (amount: string, selectedToken: TokenSymbol) => {
    if (!contract || !account || !amount || !ethProvider) return;
    setLoading(true);
    try {
      if (!fhevmInst) throw new Error("FHE unavailable \u2014 wait for FHE online");
      const token = TOKENS.find(t => t.symbol === selectedToken)!;
      const ethWeiEquiv = toEthWei(amount, token);
      const { handle, proof } = await encryptAmount(ethWeiEquiv);

      if (token.symbol === "ETH") {
        const ethValue = parseEther(amount);
        const tx = await contract.deposit(handle, proof, { value: ethValue });
        await tx.wait();
      } else {
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
      setModal(null);
      showToast(`${amount} ${selectedToken} deposited as collateral`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleBorrow = async (amount: string) => {
    if (!contract || !account || !amount) return;
    setLoading(true);
    try {
      if (!fhevmInst) throw new Error("FHE unavailable");
      const { handle, proof } = await encryptAmount(parseEther(amount));
      const tx = await contract.borrow(handle, proof);
      await tx.wait();
      setModal(null);
      showToast("Borrow recorded \u2014 debt encrypted on-chain");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleRepay = async (amount: string) => {
    if (!contract || !account || !amount) return;
    setLoading(true);
    try {
      if (!fhevmInst) throw new Error("FHE unavailable");
      const { handle, proof } = await encryptAmount(parseEther(amount));
      const tx = await contract.repay(handle, proof);
      await tx.wait();
      setModal(null);
      showToast("Repayment applied");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleRequestClose = async () => {
    if (!contract || !account) return;
    setLoading(true);
    try {
      const tx = await contract.requestClosePosition();
      await tx.wait();
      setCloseStep("pending");
      showToast("Close requested \u2014 Zama relayer decrypting debt...", "info");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleDecrypt = async () => {
    if (!contract || !account) return;
    if (!fhevmInst) { showToast("FHE offline \u2014 relayer unreachable", "error"); return; }
    setLoading(true);
    try {
      const [collHandle, debtHandle, rateHandle, scoreHandle] = await Promise.all([
        contract.getEncryptedCollateral(account),
        contract.getEncryptedTotalDebt(account),
        contract.getEncryptedInterestRate(account),
        contract.getEncryptedCreditScore(account),
      ]);
      const { publicKey, privateKey } = fhevmInst.generateKeypair();
      const eip712 = fhevmInst.createEIP712(publicKey, CONTRACT_ADDRESS);
      const provider = new BrowserProvider((window as any).ethereum);
      const signer = await provider.getSigner();
      const sig = await signer.signTypedData(eip712.domain, { Reencrypt: eip712.types.Reencrypt }, eip712.message);

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

  // ─── Liquidator actions ────────────────────────────────────────────────────
  const handleRequestReveal = async (addr: string) => {
    if (!contract) return;
    setLoading(true);
    try {
      const tx = await contract.requestLiquidationReveal(addr);
      await tx.wait();
      setBorrowers(prev => prev.map(b => b.address === addr ? { ...b, pendingReveal: true } : b));
      showToast("Reveal requested \u2014 Zama relayer decrypting...", "info");
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
      showToast(`Liquidated ${addr.slice(0, 6)}... \u2014 ETH received`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleAccrueInterest = async (addr: string) => {
    if (!contract) return;
    setLoading(true);
    try {
      const tx = await contract.accrueInterest(addr);
      await tx.wait();
      showToast(`Interest accrued for ${addr.slice(0, 6)}...`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleUpdateScore = async (scoreAddr: string, scoreTarget: string) => {
    if (!contract) return;
    setLoading(true);
    try {
      if (!fhevmInst) throw new Error("FHE unavailable");
      const input = fhevmInst.createEncryptedInput(CONTRACT_ADDRESS, account!);
      input.add64(BigInt(scoreTarget));
      const r = await input.encrypt();
      const { ethers } = await import("ethers");
      const handle = ethers.hexlify(r.handles[0]);
      const proof = ethers.hexlify(r.inputProof);
      const tx = await contract.updateCreditScore(scoreAddr, handle, proof);
      await tx.wait();
      setModal(null);
      showToast(`Credit score updated for ${scoreAddr.slice(0, 6)}...`);
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  const handleEmergencyLiquidate = async (addr: string) => {
    if (!contract) return;
    setLoading(true);
    try {
      const tx = await contract.emergencyLiquidate(addr);
      await tx.wait();
      setBorrowers(prev => prev.filter(b => b.address !== addr));
      showToast(`Emergency liquidated ${addr.slice(0, 6)}...`, "info");
    } catch (e: any) { showToast(e.message?.slice(0, 80), "error"); }
    setLoading(false);
  };

  // ─── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="sl-app">
      <Header
        account={account} role={role} isAdmin={isAdmin} fhevmInst={fhevmInst}
        walletMenu={walletMenu} setWalletMenu={setWalletMenu}
        onConnect={connect} onDisconnect={disconnect}
      />

      <div className="sl-main">
        {!account ? (
          <Hero onConnect={connect} />
        ) : (
          <>
            <StatsBar
              borrowerCount={borrowers.length}
              hasPosition={hasPosition}
              protocolStats={protocolStats}
            />

            {(role === "borrower" || isAdmin) && (
              <BorrowerCard
                hasPosition={hasPosition}
                activeTab={activeTab} setActiveTab={setActiveTab}
                closeStep={closeStep} loading={loading}
                fhevmInst={fhevmInst} protocolStats={protocolStats}
                setModal={setModal} onDecrypt={handleDecrypt}
                onRequestClose={handleRequestClose}
              />
            )}

            {(role === "liquidator" || isAdmin) && (
              <LiquidatorCard
                borrowers={borrowers} isAdmin={isAdmin} loading={loading}
                setModal={setModal}
                onRequestReveal={handleRequestReveal}
                onLiquidate={handleLiquidate}
                onAccrueInterest={handleAccrueInterest}
                onEmergencyLiquidate={handleEmergencyLiquidate}
              />
            )}

            {isAdmin && contract && (
              <AdminPanel
                contract={contract} borrowers={borrowers}
                protocolStats={protocolStats} loading={loading}
                setLoading={setLoading} showToast={showToast}
                onRefreshStats={() => loadProtocolStats(contract)}
                onEmergencyLiquidate={handleEmergencyLiquidate}
              />
            )}

            {account && ethProvider && SCORE_CONTRACT_ADDRESS && (
              <ShieldScore
                account={account} provider={ethProvider}
                fhevmInst={fhevmInst} isOracle={isAdmin}
                onToast={showToast}
              />
            )}
          </>
        )}
      </div>

      {modal === "deposit" && (
        <DepositModal loading={loading} onDeposit={handleDeposit} onClose={() => setModal(null)} />
      )}
      {(modal === "borrow" || modal === "repay") && (
        <AmountModal type={modal} loading={loading}
          onSubmit={modal === "borrow" ? handleBorrow : handleRepay}
          onClose={() => setModal(null)} />
      )}
      {modal === "score" && (
        <ScoreModal loading={loading} onSubmit={handleUpdateScore} onClose={() => setModal(null)} />
      )}
      {modal === "result" && (
        <ResultModal resultMsg={resultMsg} onClose={() => setModal(null)} />
      )}

      <Toast toast={toast} />
    </div>
  );
}
