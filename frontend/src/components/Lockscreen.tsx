import { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Lock, KeyRound, AlertTriangle, ArrowRight } from "lucide-react";
import { api, ApiError } from "../api";
import { analyzePassword } from "../utils/password";
import { PasswordStrengthMeter } from "./PasswordStrengthMeter";

interface LockScreenProps {
  vaultExists: boolean;
  onUnlocked: (mode: "real" | "decoy", seqNum: number, unlockMs?: number) => void;
}

export function LockScreen({ vaultExists, onUnlocked }: LockScreenProps) {
  const [password, setPassword] = useState("");
  const [duressPassword, setDuressPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [confirmWeak, setConfirmWeak] = useState(false);
  const [error, setError] = useState<{ status?: number; message: string } | null>(null);
  const [shakeKey, setShakeKey] = useState(0);

  const strength = useMemo(() => analyzePassword(password, true), [password]);

  async function executeSubmit() {
    setLoading(true);
    setError(null);

    try {
      if (vaultExists) {
        const res = await api.unlock(password);
        onUnlocked(res.mode, res.seq_num, res.unlock_ms);
      } else {
        const res = await api.init(password, duressPassword.trim() || undefined);
        onUnlocked("real", res.seq_num);
      }
    } catch (err) {
      setShakeKey((k) => k + 1);
      if (err instanceof ApiError) {
        setError({ status: err.status, message: err.message });
      } else {
        setError({ message: "Cannot reach local daemon at 127.0.0.1:8000." });
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!password.trim()) return;

    // Ask user to reconsider if creating a new vault with a weak master password
    if (!vaultExists && !strength.isSafe && !confirmWeak) {
      setConfirmWeak(true);
      return;
    }

    await executeSubmit();
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-obsidian px-4">
      <motion.div
        key={shakeKey}
        initial={{ opacity: 0, y: 12 }}
        animate={
          error
            ? { opacity: 1, y: 0, x: [0, -6, 6, -4, 4, 0] }
            : { opacity: 1, y: 0 }
        }
        transition={{ duration: error ? 0.32 : 0.25 }}
        className="w-full max-w-md rounded-lg border border-hairline bg-surface p-8"
      >
        <div className="mb-8 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-md border border-gold/30 bg-gold-dim text-gold">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-zinc-100">
              whoknows
            </h1>
            <p className="font-mono text-xs text-zinc-500">
              ML-DSA-65 · XChaCha20-Poly1305 · Argon2id
            </p>
          </div>
        </div>

        <h2 className="mb-1 text-sm font-medium text-zinc-200">
          {vaultExists ? "Unlock Local Vault" : "Initialize New Vault"}
        </h2>
        <p className="mb-6 text-xs text-zinc-500">
          {vaultExists
            ? "Signature and rollback anchor are verified before key derivation."
            : "Creates a fixed 68,909-byte IND-CPA container on disk."}
        </p>

        {error && (
          <div className="mb-5 flex items-start gap-2.5 rounded-md border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
            <div>
              {error.status === 403 && (
                <div className="mb-0.5 font-mono font-semibold text-red-400">
                  403 · ML-DSA-65 SIGNATURE INVALID
                </div>
              )}
              {error.status === 409 && (
                <div className="mb-0.5 font-mono font-semibold text-red-400">
                  409 · ROLLBACK / FORK DETECTED
                </div>
              )}
              <span>{error.message}</span>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-zinc-400">
              Master Password
            </label>
            <div className="relative">
              <Lock className="pointer-events-none absolute top-2.5 left-3 h-4 w-4 text-zinc-500" />
              <input
                type="password"
                autoFocus
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setConfirmWeak(false);
                }}
                placeholder="Enter master passphrase"
                className="w-full rounded-md border border-hairline bg-obsidian py-2 pr-3 pl-9 text-sm text-zinc-100 placeholder-zinc-600 focus:border-gold focus:outline-none"
              />
            </div>

            {!vaultExists && (
              <PasswordStrengthMeter analysis={strength} visible={password.length > 0} />
            )}
          </div>

          {!vaultExists && (
            <div>
              <label className="mb-1.5 block text-xs font-medium text-zinc-400">
                Duress Password <span className="text-zinc-600">(Optional)</span>
              </label>
              <div className="relative">
                <KeyRound className="pointer-events-none absolute top-2.5 left-3 h-4 w-4 text-zinc-500" />
                <input
                  type="password"
                  value={duressPassword}
                  onChange={(e) => setDuressPassword(e.target.value)}
                  placeholder="Opens plausible-deniability decoy slot"
                  className="w-full rounded-md border border-hairline bg-obsidian py-2 pr-3 pl-9 text-sm text-zinc-100 placeholder-zinc-600 focus:border-gold focus:outline-none"
                />
              </div>
            </div>
          )}

          <AnimatePresence>
            {confirmWeak && (
              <motion.div
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3.5 text-xs"
              >
                <div className="mb-1 font-medium text-amber-300">
                  Reconsider this master password?
                </div>
                <p className="mb-3 text-zinc-400">
                  Even with Argon2id, a low-entropy passphrase (~{strength.entropyBits} bits) is
                  vulnerable to offline dictionary attacks. Aim for 14+ characters.
                </p>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setConfirmWeak(false)}
                    className="flex-1 rounded border border-gold/40 bg-gold-dim py-1.5 font-medium text-gold hover:bg-gold/20"
                  >
                    Strengthen It
                  </button>
                  <button
                    type="button"
                    onClick={executeSubmit}
                    className="flex-1 rounded border border-hairline bg-obsidian py-1.5 text-zinc-400 hover:border-red-500/40 hover:text-red-300"
                  >
                    Use Anyway
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {!confirmWeak && (
            <button
              type="submit"
              disabled={loading || !password.trim()}
              className="flex w-full items-center justify-center gap-2 rounded-md bg-gold px-4 py-2.5 text-sm font-semibold text-obsidian transition hover:bg-gold-bright disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading
                ? "Deriving Keys..."
                : vaultExists
                ? "Verify & Unlock"
                : "Create Signed Vault"}
              {!loading && <ArrowRight className="h-4 w-4" />}
            </button>
          )}
        </form>
      </motion.div>
    </div>
  );
}