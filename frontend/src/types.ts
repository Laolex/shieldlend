export type Role = "borrower" | "liquidator" | "admin" | null;
export type ModalType = "deposit" | "borrow" | "repay" | "result" | "score" | null;
export type Toast = { message: string; kind: "success" | "error" | "info" } | null;
export type CloseStep = "idle" | "pending" | "done";

export interface BorrowerEntry {
  address: string;
  pendingReveal: boolean;
  confirmedLiq: boolean;
  pendingClose: boolean;
}

export interface ProtocolStats {
  protocolReserve: bigint;
  totalReserves: bigint;
  effectiveRateBps: bigint;
  ethSupplyCap: bigint;
  maxBorrowPerPosition: bigint;
  reserveFactorBps: bigint;
  minReserveRatioBps: bigint;
}
