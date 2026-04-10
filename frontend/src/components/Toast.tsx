import type { Toast as ToastType } from "../types";

interface ToastProps {
  toast: ToastType;
}

export default function Toast({ toast }: ToastProps) {
  if (!toast) return null;
  return (
    <div className={`sl-toast ${toast.kind}`}>
      <span className="sl-toast-dot" />
      {toast.message}
    </div>
  );
}
