import { motion, AnimatePresence } from "framer-motion";
import { useUiPhase } from "./useUiPhase";

export default function ComputationOverlay() {
  const { phase } = useUiPhase();
  const show = phase === "encrypting" || phase === "computing";

  const label =
    phase === "encrypting" ? "Encrypting via FHE relayer..." :
    phase === "computing" ? "Running encrypted computation via fhEVM..." :
    "";

  return (
    <AnimatePresence>
      {show && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
          style={{
            position: "fixed", inset: 0, zIndex: 200,
            background: "rgba(0,0,0,0.65)", backdropFilter: "blur(6px)",
            display: "flex", flexDirection: "column",
            alignItems: "center", justifyContent: "center", gap: 16,
          }}
        >
          <motion.div
            animate={{ opacity: [0.3, 1, 0.3] }}
            transition={{ repeat: Infinity, duration: 1.2 }}
            style={{
              fontSize: 13, fontFamily: "'Space Mono', monospace",
              color: "#a78bfa", letterSpacing: "0.12em",
            }}
          >
            {label}
          </motion.div>
          <div style={{
            width: 200, height: 3, borderRadius: 99,
            background: "rgba(139,92,246,0.15)", overflow: "hidden",
          }}>
            <motion.div
              style={{
                height: "100%", borderRadius: 99,
                background: "linear-gradient(90deg, #8b5cf6, #34d399)",
              }}
              animate={{ width: ["0%", "80%", "40%", "100%"] }}
              transition={{ repeat: Infinity, duration: 2, ease: "easeInOut" }}
            />
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
