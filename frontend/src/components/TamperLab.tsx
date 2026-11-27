import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldCheck,
  ShieldAlert,
  Zap,
  RefreshCw,
  FileWarning,
  Signature,
  History,
  Timer,
  Binary,
  Trash2,
} from "lucide-react";
import {
  api,
  ApiError,
  type TamperInspectResult,
  type TamperAttackResult,
  type DuressTimingResult,
} from "../api";

const LAB_ERROR = "LAB ERROR";

interface AttackLogItem extends TamperAttackResult {
  id: number;
  timestamp: string;
}

export function TamperLab() {
  const [inspect, setInspect] = useState<TamperInspectResult | null>(null);
  const [inspectError, setInspectError] = useState<string | null>(null);
  const [loadingInspect, setLoadingInspect] = useState(true);

  const [offset, setOffset] = useState(264);
  const [flipTarget, setFlipTarget] = useState<"vault" | "synthetic">("vault");
  const [runningAttack, setRunningAttack] = useState<string | null>(null);
  const [logs, setLogs] = useState<AttackLogItem[]>([]);

  const [timing, setTiming] = useState<DuressTimingResult | null>(null);
  const [runningTiming, setRunningTiming] = useState(false);

  async function loadInspect() {
    setLoadingInspect(true);
    setInspectError(null);
    try {
      const data = await api.tamperInspect();
      setInspect(data);
    } catch (err) {
      setInspectError(err instanceof ApiError ? err.message : "Failed to inspect container.");
    } finally {
      setLoadingInspect(false);
    }
  }

  useEffect(() => {
    loadInspect();
  }, []);

  function pushLog(result: TamperAttackResult) {
    const now = new Date();
    const timestamp = now.toTimeString().slice(0, 8);
    setLogs((prev) => [{ ...result, id: Date.now() + Math.random(), timestamp }, ...prev]);
  }

  async function fireAttack(key: string, fn: () => Promise<TamperAttackResult>) {
    setRunningAttack(key);
    try {
      const res = await fn();
      pushLog(res);
    } catch (err) {
      // A failed request is a lab malfunction, never a defended attack.
      pushLog({
        attack: key,
        caught: false,
        layer: LAB_ERROR,
        error: err instanceof ApiError ? `${err.status}: ${err.message}` : "Request failed",
      });
    } finally {
      setRunningAttack(null);
    }
  }

  async function runDuressBenchmark() {
    setRunningTiming(true);
    try {
      const res = await api.tamperDuressTiming();
      setTiming(res);
    } catch (err) {
      pushLog({
        attack: "duress-timing",
        caught: false,
        layer: LAB_ERROR,
        error: err instanceof ApiError ? err.message : "Benchmark failed",
      });
    } finally {
      setRunningTiming(false);
    }
  }

  function getRegionLabel(byteOffset: number, total: number, sigBytes: number) {
    const sigStart = total - sigBytes;
    if (byteOffset < 64) return "HEADER (AAD)";
    if (byteOffset < 64 + 32768) return "SLOT 1 (REAL CIPHERTEXT)";
    if (byteOffset < sigStart) return "SLOT 2 (DECOY CIPHERTEXT)";
    return "ML-DSA-65 SIGNATURE";
  }

  const totalBytes = inspect?.total_bytes ?? 68909;
  const sigBytes = inspect?.sig_bytes ?? 3309;
  const regionLabel = getRegionLabel(offset, totalBytes, sigBytes);

  return (
    <div className="mx-auto max-w-5xl space-y-6 pb-10">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-hairline pb-4">
        <div>
          <h1 className="text-base font-semibold tracking-tight text-zinc-100">
            Interactive Tamper Lab
          </h1>
          <p className="font-mono text-xs text-zinc-500">
            Bit-flip and signature attacks run on an in-memory copy of your vault file (never written
            to disk). AEAD, header, rollback and timing demos need a password or file history, so they
            use a synthetic lab container.
          </p>
        </div>
        <button
          onClick={loadInspect}
          disabled={loadingInspect}
          className="flex items-center gap-1.5 rounded-md border border-hairline bg-surface px-3 py-1.5 font-mono text-xs text-zinc-300 transition hover:border-gold/40 hover:text-gold disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loadingInspect ? "animate-spin" : ""}`} />
          Re-Inspect Disk
        </button>
      </div>

      {inspectError && (
        <div className="rounded-md border border-red-500/30 bg-red-500/10 p-3 font-mono text-xs text-red-300">
          {inspectError}
        </div>
      )}

      {/* Container Binary Map & Slot Entropy */}
      <section className="rounded-lg border border-hairline bg-surface p-5 space-y-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Binary className="h-4 w-4 text-gold" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
              Fixed-Size Binary Container
            </h2>
          </div>
          <span className="font-mono text-xs text-gold">
            {totalBytes.toLocaleString()} bytes · SEQ #{inspect?.seq_num ?? "—"}
          </span>
        </div>

        {/* Visual Byte Layout Bar */}
        <div className="space-y-2">
          <div className="flex h-7 w-full overflow-hidden rounded border border-hairline bg-obsidian font-mono text-[10px]">
            <div
              style={{ width: "6%" }}
              className="flex items-center justify-center border-r border-hairline bg-gold-dim text-gold"
              title="64B Header"
            >
              HDR
            </div>
            <div
              style={{ width: "42%" }}
              className="flex items-center justify-center border-r border-hairline bg-elevated text-zinc-300"
              title="32 KB Slot 1 (Real)"
            >
              SLOT 1 · XChaCha20-Poly1305
            </div>
            <div
              style={{ width: "42%" }}
              className="flex items-center justify-center border-r border-hairline bg-elevated/60 text-zinc-400"
              title="32 KB Slot 2 (Decoy)"
            >
              SLOT 2 · DECOY / PADDING
            </div>
            <div
              style={{ width: "10%" }}
              className="flex items-center justify-center bg-gold/20 text-gold"
              title={`${sigBytes}B ML-DSA-65 Signature`}
            >
              SIG
            </div>
          </div>

          {inspect && (
            <div className="grid gap-3 pt-1 font-mono text-[11px] text-zinc-500 md:grid-cols-2">
              <div className="truncate rounded border border-hairline bg-obsidian px-2.5 py-1.5">
                <span className="text-zinc-400">HEADER_HEX: </span>
                <span className="text-zinc-300">{inspect.header_hex}</span>
              </div>
              <div className="truncate rounded border border-hairline bg-obsidian px-2.5 py-1.5">
                <span className="text-zinc-400">PREV_HASH: </span>
                <span className="text-zinc-300">{inspect.prev_hash}</span>
              </div>
            </div>
          )}
        </div>

        {/* Shannon Entropy Gauges */}
        {inspect && (
          <div className="grid gap-4 pt-1 md:grid-cols-2">
            {[
              { label: "Slot 1 Shannon Entropy (Real)", value: inspect.slot1_entropy },
              { label: "Slot 2 Shannon Entropy (Decoy)", value: inspect.slot2_entropy },
            ].map(({ label, value }) => {
              const pct = Math.min(100, (value / 8) * 100);
              return (
                <div key={label} className="rounded-md border border-hairline bg-obsidian p-3">
                  <div className="mb-1.5 flex items-center justify-between font-mono text-[11px]">
                    <span className="text-zinc-400">{label}</span>
                    <span className="text-gold">{value.toFixed(4)} / 8.0000 bits</span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-hairline">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 0.45 }}
                      className="h-full bg-gold"
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Attack Console Grid */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Left: Byte-Offset Bit-Flipper + One-Click Attacks */}
        <section className="space-y-4 rounded-lg border border-hairline bg-surface p-5">
          <div className="flex items-center gap-2">
            <Zap className="h-4 w-4 text-gold" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
              Adversarial Attack Console
            </h2>
          </div>

          {/* Interactive Bit-Flipper */}
          <div className="rounded-md border border-hairline bg-obsidian p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-zinc-200">
                1-Bit Ciphertext Corruption
              </span>
              <span className="rounded border border-gold/30 bg-gold-dim px-2 py-0.5 font-mono text-[10px] text-gold">
                {regionLabel}
              </span>
            </div>

            <div className="flex gap-2 font-mono text-[10px]">
              {(
                [
                  ["vault", "Your vault copy · ML-DSA-65 gate"],
                  ["synthetic", "Synthetic container · AEAD layer"],
                ] as const
              ).map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setFlipTarget(value)}
                  aria-pressed={flipTarget === value}
                  className={`flex-1 rounded border px-2 py-1 transition ${
                    flipTarget === value
                      ? "border-gold/50 bg-gold-dim text-gold"
                      : "border-hairline text-zinc-500 hover:text-zinc-300"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between font-mono text-[11px] text-zinc-400">
                <span>Byte Offset</span>
                <input
                  type="number"
                  min={0}
                  max={totalBytes - 1}
                  value={offset}
                  onChange={(e) =>
                    setOffset(Math.max(0, Math.min(totalBytes - 1, Number(e.target.value) || 0)))
                  }
                  className="w-24 rounded border border-hairline bg-surface px-2 py-0.5 text-right font-mono text-xs text-gold focus:border-gold focus:outline-none"
                />
              </div>
              <input
                type="range"
                min={0}
                max={totalBytes - 1}
                value={offset}
                onChange={(e) => setOffset(Number(e.target.value))}
                className="w-full accent-[#c9a84c]"
              />
            </div>

            <button
              onClick={() => fireAttack("bit-flip", () => api.tamperBitFlip(offset, flipTarget))}
              disabled={runningAttack !== null}
              className="flex w-full items-center justify-center gap-2 rounded-md bg-gold px-3 py-2 text-xs font-semibold text-obsidian transition hover:bg-gold-bright disabled:opacity-50"
            >
              <Zap className="h-3.5 w-3.5" />
              {runningAttack === "bit-flip"
                ? "Flipping Bit & Verifying..."
                : `Flip 1 Bit at Offset ${offset}`}
            </button>
          </div>

          {/* One-Click Cryptographic Attacks */}
          <div className="grid gap-2.5 sm:grid-cols-3">
            <button
              onClick={() => fireAttack("header-aad", () => api.tamperHeaderAad())}
              disabled={runningAttack !== null}
              className="flex flex-col items-start gap-1.5 rounded-md border border-hairline bg-obsidian p-3 text-left transition hover:border-gold/40 disabled:opacity-50"
            >
              <FileWarning className="h-4 w-4 text-gold" />
              <span className="text-xs font-medium text-zinc-200">Header AAD</span>
              <span className="font-mono text-[10px] text-zinc-500">Mutate metadata</span>
            </button>

            <button
              onClick={() => fireAttack("signature", () => api.tamperSignature())}
              disabled={runningAttack !== null}
              className="flex flex-col items-start gap-1.5 rounded-md border border-hairline bg-obsidian p-3 text-left transition hover:border-gold/40 disabled:opacity-50"
            >
              <Signature className="h-4 w-4 text-gold" />
              <span className="text-xs font-medium text-zinc-200">Forge Sig</span>
              <span className="font-mono text-[10px] text-zinc-500">ML-DSA-65 check</span>
            </button>

            <button
              onClick={() => fireAttack("rollback", () => api.tamperRollback())}
              disabled={runningAttack !== null}
              className="flex flex-col items-start gap-1.5 rounded-md border border-hairline bg-obsidian p-3 text-left transition hover:border-gold/40 disabled:opacity-50"
            >
              <History className="h-4 w-4 text-gold" />
              <span className="text-xs font-medium text-zinc-200">Rollback</span>
              <span className="font-mono text-[10px] text-zinc-500">Replay SEQ #</span>
            </button>
          </div>

          {/* Constant-Time Duress Timing Benchmark */}
          <div className="rounded-md border border-hairline bg-obsidian p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Timer className="h-4 w-4 text-gold" />
                <span className="text-xs font-medium text-zinc-200">
                  Duress Constant-Time Benchmark
                </span>
              </div>
              <button
                onClick={runDuressBenchmark}
                disabled={runningTiming}
                className="rounded border border-gold/40 bg-gold-dim px-2.5 py-1 font-mono text-[11px] font-medium text-gold transition hover:bg-gold/20 disabled:opacity-50"
              >
                {runningTiming ? "Measuring 30 trials..." : "Run Probe"}
              </button>
            </div>

            {timing ? (
              <div className="space-y-3 pt-1 font-mono text-[11px]">
                {(() => {
                  const rows = [
                    { label: "Real password", st: timing.real },
                    { label: "Decoy password", st: timing.decoy },
                    { label: "Wrong password", st: timing.wrong },
                  ];
                  const lo = Math.min(...rows.flatMap((r) => r.st.samples_ms));
                  const hi = Math.max(...rows.flatMap((r) => r.st.samples_ms));
                  const span = Math.max(hi - lo, 0.001);
                  const pos = (ms: number) => `${((ms - lo) / span) * 100}%`;
                  return rows.map(({ label, st }) => (
                    <div key={label} className="space-y-1">
                      <div className="flex justify-between text-zinc-400">
                        <span>{label}</span>
                        <span className="text-zinc-200">
                          median {st.median_ms.toFixed(1)} ms · p10–p90 {st.p10_ms.toFixed(1)}–
                          {st.p90_ms.toFixed(1)}
                        </span>
                      </div>
                      {/* p10–p90 band, one dot per trial, median tick */}
                      <div className="relative h-3 w-full rounded bg-hairline/60">
                        <div
                          className="absolute top-0 h-full rounded bg-gold/20"
                          style={{ left: pos(st.p10_ms), width: `calc(${pos(st.p90_ms)} - ${pos(st.p10_ms)})` }}
                        />
                        {st.samples_ms.map((ms, k) => (
                          <span
                            key={k}
                            className="absolute top-1 h-1 w-1 -translate-x-1/2 rounded-full bg-zinc-400"
                            style={{ left: pos(ms) }}
                          />
                        ))}
                        <span
                          className="absolute top-0 h-full w-0.5 -translate-x-1/2 bg-gold"
                          style={{ left: pos(st.median_ms) }}
                        />
                      </div>
                    </div>
                  ));
                })()}
                <div className="flex items-center justify-between border-t border-hairline pt-2">
                  <span className="text-zinc-500">
                    {timing.trials} trials · decoy/real {timing.decoy_vs_real_ratio.toFixed(3)}x ·
                    wrong/real {timing.wrong_vs_real_ratio.toFixed(3)}x
                  </span>
                  <span
                    className={
                      timing.constant_time_pass ? "text-gold" : "text-red-400"
                    }
                  >
                    {timing.constant_time_pass ? "INDISTINGUISHABLE" : "TIMING SKEW"}
                  </span>
                </div>
              </div>
            ) : (
              <p className="font-mono text-[11px] text-zinc-500">
                Times 30 alternating real, decoy and wrong-password unlocks of a synthetic container.
                Passes when the medians are within 10% of each other.
              </p>
            )}
          </div>
        </section>

        {/* Right: Live Security Telemetry Log */}
        <section className="flex flex-col rounded-lg border border-hairline bg-surface p-5">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-gold" />
              <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
                Verification Log
              </h2>
            </div>
            {logs.length > 0 && (
              <button
                onClick={() => setLogs([])}
                className="flex items-center gap-1 font-mono text-[11px] text-zinc-500 hover:text-zinc-300"
              >
                <Trash2 className="h-3 w-3" />
                Clear
              </button>
            )}
          </div>

          <div className="flex-1 space-y-2.5 overflow-y-auto max-h-[460px] pr-1">
            {logs.length === 0 ? (
              <div className="flex h-64 flex-col items-center justify-center rounded-md border border-dashed border-hairline bg-obsidian/50 text-center font-mono text-xs text-zinc-600">
                <ShieldCheck className="mb-2 h-6 w-6 text-zinc-700" />
                No attacks executed yet.
                <br />
                Fire a probe on the left to inspect cryptographic rejection.
              </div>
            ) : (
              <AnimatePresence initial={false}>
                {logs.map((item) => (
                  <motion.div
                    key={item.id}
                    initial={{ opacity: 0, y: -8 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={`rounded-md border p-3 font-mono text-xs ${
                      item.caught
                        ? "border-gold/30 bg-obsidian"
                        : "border-red-500/40 bg-red-500/10"
                    }`}
                  >
                    <div className="mb-1.5 flex items-center justify-between">
                      <span className="flex items-center gap-1.5 font-semibold text-zinc-100">
                        {item.caught ? (
                          <ShieldCheck className="h-3.5 w-3.5 text-gold" />
                        ) : (
                          <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
                        )}
                        {item.attack.toUpperCase()}
                      </span>
                      <span className="text-[10px] text-zinc-500">{item.timestamp}</span>
                    </div>

                    <div className="flex flex-wrap gap-1.5 mb-1.5 text-[10px]">
                      <span
                        className={`rounded px-1.5 py-0.5 ${
                          item.caught
                            ? "bg-gold-dim text-gold"
                            : "bg-red-500/20 text-red-300"
                        }`}
                      >
                        {item.caught
                          ? "ATTACK CAUGHT"
                          : item.layer === LAB_ERROR
                            ? "LAB ERROR · NO RESULT"
                            : "UNCAUGHT"}
                      </span>
                      {item.layer && (
                        <span className="rounded border border-hairline bg-surface px-1.5 py-0.5 text-zinc-300">
                          LAYER: {item.layer}
                        </span>
                      )}
                      {item.target && (
                        <span className="rounded border border-hairline bg-surface px-1.5 py-0.5 text-zinc-400">
                          {item.target === "vault" ? "TARGET: YOUR VAULT (COPY)" : "TARGET: SYNTHETIC"}
                        </span>
                      )}
                      {item.rejected_before_kdf && (
                        <span className="rounded border border-gold/30 bg-gold-dim px-1.5 py-0.5 text-gold">
                          REJECTED BEFORE KDF
                        </span>
                      )}
                      {item.offset !== undefined && (
                        <span className="rounded border border-hairline bg-surface px-1.5 py-0.5 text-zinc-400">
                          OFFSET {item.offset}
                        </span>
                      )}
                    </div>

                    {item.error && (
                      <p className="text-[11px] leading-relaxed text-zinc-400">
                        {item.error}
                      </p>
                    )}
                  </motion.div>
                ))}
              </AnimatePresence>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}