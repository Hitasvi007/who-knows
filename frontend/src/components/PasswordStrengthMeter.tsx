import { motion } from "framer-motion";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import type { PasswordAnalysis } from "../utils/password";

interface PasswordStrengthMeterProps {
  analysis: PasswordAnalysis;
  visible: boolean;
}

export function PasswordStrengthMeter({ analysis, visible }: PasswordStrengthMeterProps) {
  if (!visible) return null;

  const activeColor =
    analysis.score >= 3
      ? "bg-gold"
      : analysis.score === 2
      ? "bg-amber-500"
      : "bg-red-500";

  const textColor =
    analysis.score >= 3
      ? "text-gold"
      : analysis.score === 2
      ? "text-amber-400"
      : "text-red-400";

  return (
    <div className="mt-2 space-y-1.5">
      <div className="grid grid-cols-4 gap-1">
        {[1, 2, 3, 4].map((seg) => (
          <div key={seg} className="h-1 overflow-hidden rounded-full bg-hairline">
            <motion.div
              initial={false}
              animate={{ width: analysis.score >= seg ? "100%" : "0%" }}
              transition={{ duration: 0.2 }}
              className={`h-full ${activeColor}`}
            />
          </div>
        ))}
      </div>

      <div className="flex items-center justify-between font-mono text-[11px]">
        <span className={`flex items-center gap-1 ${textColor}`}>
          {analysis.isSafe ? (
            <ShieldCheck className="h-3.5 w-3.5" />
          ) : (
            <ShieldAlert className="h-3.5 w-3.5" />
          )}
          {analysis.label.toUpperCase()}
          {!analysis.isSafe && " · NOT RECOMMENDED"}
        </span>
        <span className="text-zinc-500">~{analysis.entropyBits} bits</span>
      </div>

      {analysis.warnings.length > 0 && (
        <p className="text-[11px] text-zinc-500">{analysis.warnings.join(" · ")}</p>
      )}
    </div>
  );
}