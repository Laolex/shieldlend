import { create } from "zustand";

export type UiPhase =
  | "disconnected"
  | "connecting"
  | "connected"
  | "encrypting"
  | "computing"
  | "decrypted";

type State = {
  phase: UiPhase;
  setPhase: (p: UiPhase) => void;
};

export const useUiPhase = create<State>((set) => ({
  phase: "disconnected",
  setPhase: (p) => set({ phase: p }),
}));
