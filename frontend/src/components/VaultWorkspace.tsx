import { useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldCheck,
  KeyRound,
  Share2,
  FlaskConical,
  Lock,
  Plus,
  Search,
  Eye,
  EyeOff,
  Copy,
  Check,
  Trash2,
  Save,
  Globe,
  RefreshCw,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { api, type VaultEntry } from "../api";
import {
  analyzePassword,
  generateCryptoPassword,
  type GeneratorOptions,
} from "../utils/password";
import { PasswordStrengthMeter } from "./PasswordStrengthMeter";
import { copySecret, setClipboardNotifier } from "../utils/clipboard";

export type NavTab = "vault" | "pqc" | "tamper";

interface VaultWorkspaceProps {
  seqNum: number;
  unlockMs?: number;
  onSeqChange: (seq: number) => void;
  onLock: () => void;
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  renderSecondaryTab?: (tab: "pqc" | "tamper") => React.ReactNode;
}

const EMPTY_FORM = {
  title: "",
  username: "",
  password: "",
  url: "",
  totp_secret: "",
  notes: "",
};

const DEFAULT_GEN_OPTS: GeneratorOptions = {
  length: 24,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
};

export function VaultWorkspace({
  seqNum,
  unlockMs,
  onSeqChange,
  onLock,
  activeTab,
  onTabChange,
  renderSecondaryTab,
}: VaultWorkspaceProps) {
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [showPass, setShowPass] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Interactive controls
  const [showGenerator, setShowGenerator] = useState(false);
  const [genOpts, setGenOpts] = useState<GeneratorOptions>(DEFAULT_GEN_OPTS);
  const [genPreview, setGenPreview] = useState(() => generateCryptoPassword(DEFAULT_GEN_OPTS));
  const [confirmWeakSave, setConfirmWeakSave] = useState(false);
  const [toast, setToast] = useState<{ id: number; message: string } | null>(null);

  const searchInputRef = useRef<HTMLInputElement>(null);

  const passwordAnalysis = useMemo(() => analyzePassword(form.password, false), [form.password]);

  function pushToast(message: string) {
    const id = Date.now();
    setToast({ id, message });
    window.setTimeout(() => {
      setToast((curr) => (curr?.id === id ? null : curr));
    }, 3200);
  }

  async function loadEntries(q?: string) {
    const list = await api.listEntries(q);
    setEntries(list);
    if (!selectedId && list.length > 0 && !isCreating) {
      selectEntry(list[0]);
    }
  }

  useEffect(() => {
    loadEntries(search || undefined);
  }, [search]);

  useEffect(() => {
    setClipboardNotifier(pushToast);
    return () => setClipboardNotifier(() => {});
  }, []);

  // Keyboard shortcuts: Ctrl+K (search), Alt+N (new), Alt+L (lock)
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onTabChange("vault");
        setTimeout(() => searchInputRef.current?.focus(), 0);
      } else if (e.altKey && e.key.toLowerCase() === "n") {
        e.preventDefault();
        onTabChange("vault");
        startCreate();
      } else if (e.altKey && e.key.toLowerCase() === "l") {
        e.preventDefault();
        onLock();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onLock, onTabChange]);

  useEffect(() => {
    setGenPreview(generateCryptoPassword(genOpts));
  }, [genOpts]);

  function selectEntry(entry: VaultEntry) {
    setIsCreating(false);
    setSelectedId(entry.id);
    setShowPass(false);
    setShowGenerator(false);
    setConfirmWeakSave(false);
    setForm({
      title: entry.title,
      username: entry.username,
      password: entry.password,
      url: entry.url,
      totp_secret: entry.totp_secret,
      notes: entry.notes,
    });
  }

  function startCreate() {
    setSelectedId(null);
    setIsCreating(true);
    setShowPass(true);
    setShowGenerator(false);
    setConfirmWeakSave(false);
    setForm(EMPTY_FORM);
  }

  async function executeSave() {
    setSaving(true);
    setConfirmWeakSave(false);
    try {
      if (isCreating) {
        const res = await api.createEntry(form);
        onSeqChange(res.seq_num);
        await loadEntries(search || undefined);
        selectEntry(res.entry);
        pushToast(`Signed & saved SEQ #${res.seq_num}`);
      } else if (selectedId) {
        const res = await api.updateEntry(selectedId, form);
        onSeqChange(res.seq_num);
        await loadEntries(search || undefined);
        selectEntry(res.entry);
        pushToast(`Re-signed container SEQ #${res.seq_num}`);
      }
    } finally {
      setSaving(false);
    }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!form.title.trim()) return;

    if (form.password.length > 0 && !passwordAnalysis.isSafe && !confirmWeakSave) {
      setConfirmWeakSave(true);
      return;
    }

    await executeSave();
  }

  async function handleDelete() {
    if (!selectedId) return;
    const res = await api.deleteEntry(selectedId);
    onSeqChange(res.seq_num);
    setSelectedId(null);
    setForm(EMPTY_FORM);
    await loadEntries(search || undefined);
    pushToast(`Deleted · Re-signed SEQ #${res.seq_num}`);
  }

  async function copyValue(field: string, value: string, isSecret = false) {
    if (!value) return;
    try {
      if (isSecret) await copySecret(value);
      else await navigator.clipboard.writeText(value);
    } catch {
      pushToast("Copy failed: clipboard not available");
      return;
    }
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 1500);
    pushToast(isSecret ? "Password copied · clipboard clears in 30s" : "Copied to clipboard");
  }

  function applyGeneratedPassword(pw: string) {
    setForm((prev) => ({ ...prev, password: pw }));
    setShowPass(true);
    setShowGenerator(false);
    setConfirmWeakSave(false);
    pushToast("CSPRNG password applied");
  }

  return (
    <div className="relative flex h-screen overflow-hidden bg-obsidian text-zinc-100">
      {/* PANE 1: Left Navigation & Security Telemetry */}
      <aside className="flex w-56 shrink-0 flex-col border-r border-hairline bg-surface">
        <div className="flex items-center gap-2.5 border-b border-hairline px-4 py-4">
          <div className="flex h-7 w-7 items-center justify-center rounded border border-gold/40 bg-gold-dim text-gold">
            <ShieldCheck className="h-4 w-4" />
          </div>
          <span className="text-sm font-semibold tracking-tight">whoknows</span>
        </div>

        <nav className="flex-1 space-y-1 p-2.5">
          {[
            { id: "vault" as const, label: "Credentials", icon: KeyRound },
            { id: "pqc" as const, label: "PQ Share", icon: Share2 },
            { id: "tamper" as const, label: "Tamper Lab", icon: FlaskConical },
          ].map(({ id, label, icon: Icon }) => {
            const active = activeTab === id;
            return (
              <button
                key={id}
                onClick={() => onTabChange(id)}
                className={`flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-xs font-medium transition ${
                  active
                    ? "border border-gold/30 bg-gold-dim text-gold"
                    : "border border-transparent text-zinc-400 hover:bg-elevated hover:text-zinc-200"
                }`}
              >
                <Icon className="h-4 w-4" />
                {label}
              </button>
            );
          })}
        </nav>

        {/* Gold Cryptographic Status Footer */}
        <div className="border-t border-hairline p-3">
          <div className="mb-3 rounded-md border border-gold/25 bg-obsidian p-2.5 font-mono text-[11px]">
            <div className="flex items-center justify-between text-gold">
              <span>ML-DSA-65</span>
              <span>VERIFIED</span>
            </div>
            <div className="mt-1 flex items-center justify-between text-zinc-500">
              <span>SEQ #{seqNum}</span>
              {unlockMs !== undefined && <span>{unlockMs}ms</span>}
            </div>
          </div>

          <button
            onClick={onLock}
            className="flex w-full items-center justify-between rounded-md border border-hairline bg-elevated px-3 py-2 text-xs font-medium text-zinc-300 transition hover:border-gold/40 hover:text-gold"
          >
            <span className="flex items-center gap-2">
              <Lock className="h-3.5 w-3.5" />
              Lock Vault
            </span>
            <kbd className="rounded bg-obsidian px-1.5 py-0.5 font-mono text-[10px] text-zinc-500">
              Alt+L
            </kbd>
          </button>
        </div>
      </aside>

      {/* Secondary Tabs */}
      {activeTab !== "vault" ? (
        <main className="flex-1 overflow-y-auto p-6">
          {renderSecondaryTab ? (
            renderSecondaryTab(activeTab)
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-zinc-500">
              {activeTab === "pqc" ? "Hybrid PQ Share" : "Interactive Tamper Lab"} — coming in Commit 13.
            </div>
          )}
        </main>
      ) : (
        <>
          {/* PANE 2: Searchable Entry List */}
          <section className="flex w-72 shrink-0 flex-col border-r border-hairline bg-obsidian">
            <div className="flex items-center gap-2 border-b border-hairline p-3">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute top-2.5 left-2.5 h-3.5 w-3.5 text-zinc-500" />
                <input
                  ref={searchInputRef}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search… (Ctrl+K)"
                  className="w-full rounded-md border border-hairline bg-surface py-1.5 pr-2.5 pl-8 text-xs text-zinc-100 placeholder-zinc-600 focus:border-gold focus:outline-none"
                />
              </div>
              <button
                onClick={startCreate}
                title="New Credential (Alt+N)"
                className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-gold text-obsidian transition hover:bg-gold-bright"
              >
                <Plus className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 space-y-1 overflow-y-auto p-2">
              {entries.length === 0 ? (
                <div className="px-3 py-10 text-center text-xs text-zinc-600">
                  No credentials yet. Press <span className="font-mono text-gold">Alt+N</span> to add one.
                </div>
              ) : (
                entries.map((entry) => {
                  const selected = !isCreating && selectedId === entry.id;
                  return (
                    <div
                      key={entry.id}
                      onClick={() => selectEntry(entry)}
                      className={`group flex cursor-pointer items-center justify-between rounded-md border px-3 py-2.5 transition ${
                        selected
                          ? "border-gold/40 bg-surface"
                          : "border-transparent hover:bg-surface/60"
                      }`}
                    >
                      <div className="min-w-0 flex-1 pr-2">
                        <div className="truncate text-xs font-medium text-zinc-100">
                          {entry.title}
                        </div>
                        <div className="mt-0.5 truncate font-mono text-[11px] text-zinc-500">
                          {entry.username || entry.url || "No username"}
                        </div>
                      </div>
                      {entry.password && (
                        <button
                          type="button"
                          title="Quick-copy password"
                          onClick={(e) => {
                            e.stopPropagation();
                            copyValue(`list-${entry.id}`, entry.password, true);
                          }}
                          className="rounded p-1.5 text-zinc-500 opacity-0 transition hover:bg-elevated hover:text-gold group-hover:opacity-100"
                        >
                          {copiedField === `list-${entry.id}` ? (
                            <Check className="h-3.5 w-3.5 text-gold" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </section>

          {/* PANE 3: Detail Inspector / Editor */}
          <main className="flex-1 overflow-y-auto bg-obsidian p-8">
            <AnimatePresence mode="wait">
              {!isCreating && !selectedId ? (
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="flex h-full flex-col items-center justify-center text-zinc-600"
                >
                  <KeyRound className="mb-3 h-8 w-8 text-zinc-700" />
                  <p className="text-xs">Select a credential or press Alt+N to create one.</p>
                </motion.div>
              ) : (
                <motion.form
                  key={selectedId || "new"}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.15 }}
                  onSubmit={handleSave}
                  className="mx-auto max-w-xl space-y-5"
                >
                  <div className="flex items-center justify-between border-b border-hairline pb-4">
                    <div>
                      <h2 className="text-base font-semibold text-zinc-100">
                        {isCreating ? "New Credential" : form.title}
                      </h2>
                      <p className="font-mono text-[11px] text-zinc-500">
                        {isCreating
                          ? "Encrypted into RAM SQLite & signed on save"
                          : `ID: ${selectedId?.slice(0, 8)}…`}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      {!isCreating && (
                        <button
                          type="button"
                          onClick={handleDelete}
                          className="rounded-md border border-hairline p-2 text-zinc-400 transition hover:border-red-500/40 hover:text-red-400"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      )}
                      <button
                        type="submit"
                        disabled={saving || !form.title.trim()}
                        className="flex items-center gap-1.5 rounded-md bg-gold px-3.5 py-2 text-xs font-semibold text-obsidian transition hover:bg-gold-bright disabled:opacity-50"
                      >
                        <Save className="h-3.5 w-3.5" />
                        {saving ? "Signing..." : "Save"}
                      </button>
                    </div>
                  </div>

                  {/* Weak Password Reconsider Banner */}
                  <AnimatePresence>
                    {confirmWeakSave && (
                      <motion.div
                        initial={{ opacity: 0, y: -6 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -6 }}
                        className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3.5 text-xs"
                      >
                        <div className="mb-1 font-medium text-amber-300">
                          Reconsider saving a weak password?
                        </div>
                        <p className="mb-3 text-zinc-400">
                          This password scores {passwordAnalysis.label.toLowerCase()} (~
                          {passwordAnalysis.entropyBits} bits). You can swap it for a
                          cryptographically random one in a single click.
                        </p>
                        <div className="flex gap-2">
                          <button
                            type="button"
                            onClick={() =>
                              applyGeneratedPassword(generateCryptoPassword(DEFAULT_GEN_OPTS))
                            }
                            className="rounded border border-gold/40 bg-gold-dim px-3 py-1.5 font-medium text-gold hover:bg-gold/20"
                          >
                            Generate 24-Char Strong Password
                          </button>
                          <button
                            type="button"
                            onClick={executeSave}
                            className="rounded border border-hairline bg-obsidian px-3 py-1.5 text-zinc-400 hover:border-red-500/40 hover:text-red-300"
                          >
                            Save Anyway
                          </button>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  <div className="space-y-4">
                    <div>
                      <label className="mb-1 block text-xs text-zinc-400">Title</label>
                      <input
                        value={form.title}
                        onChange={(e) => setForm({ ...form, title: e.target.value })}
                        placeholder="e.g. GitHub, AWS Production"
                        className="w-full rounded-md border border-hairline bg-surface px-3 py-2 text-sm text-zinc-100 focus:border-gold focus:outline-none"
                      />
                    </div>

                    <div>
                      <label className="mb-1 block text-xs text-zinc-400">Username / Email</label>
                      <div className="flex gap-2">
                        <input
                          value={form.username}
                          onChange={(e) => setForm({ ...form, username: e.target.value })}
                          className="flex-1 rounded-md border border-hairline bg-surface px-3 py-2 font-mono text-xs text-zinc-100 focus:border-gold focus:outline-none"
                        />
                        <button
                          type="button"
                          onClick={() => copyValue("username", form.username)}
                          className="rounded-md border border-hairline bg-surface px-2.5 text-zinc-400 hover:border-gold/40 hover:text-gold"
                        >
                          {copiedField === "username" ? (
                            <Check className="h-4 w-4 text-gold" />
                          ) : (
                            <Copy className="h-4 w-4" />
                          )}
                        </button>
                      </div>
                    </div>

                    <div>
                      <label className="mb-1 block text-xs text-zinc-400">Password</label>
                      <div className="flex gap-2">
                        <input
                          type={showPass ? "text" : "password"}
                          value={form.password}
                          onChange={(e) => {
                            setForm({ ...form, password: e.target.value });
                            setConfirmWeakSave(false);
                          }}
                          className="flex-1 rounded-md border border-hairline bg-surface px-3 py-2 font-mono text-xs text-zinc-100 focus:border-gold focus:outline-none"
                        />
                        <button
                          type="button"
                          title="Password Generator"
                          onClick={() => setShowGenerator((s) => !s)}
                          className={`rounded-md border px-2.5 transition ${
                            showGenerator
                              ? "border-gold/50 bg-gold-dim text-gold"
                              : "border-hairline bg-surface text-zinc-400 hover:border-gold/40 hover:text-gold"
                          }`}
                        >
                          <SlidersHorizontal className="h-4 w-4" />
                        </button>
                        <button
                          type="button"
                          onClick={() => setShowPass(!showPass)}
                          className="rounded-md border border-hairline bg-surface px-2.5 text-zinc-400 hover:border-gold/40 hover:text-gold"
                        >
                          {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </button>
                        <button
                          type="button"
                          onClick={() => copyValue("password", form.password, true)}
                          className="rounded-md border border-hairline bg-surface px-2.5 text-zinc-400 hover:border-gold/40 hover:text-gold"
                        >
                          {copiedField === "password" ? (
                            <Check className="h-4 w-4 text-gold" />
                          ) : (
                            <Copy className="h-4 w-4" />
                          )}
                        </button>
                      </div>

                      <PasswordStrengthMeter
                        analysis={passwordAnalysis}
                        visible={form.password.length > 0}
                      />

                      {/* CSPRNG Generator Drawer */}
                      <AnimatePresence>
                        {showGenerator && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            exit={{ opacity: 0, height: 0 }}
                            className="mt-3 overflow-hidden rounded-md border border-gold/30 bg-surface p-3.5"
                          >
                            <div className="mb-2.5 flex items-center justify-between">
                              <span className="font-mono text-[11px] font-medium text-gold">
                                CSPRNG GENERATOR
                              </span>
                              <button
                                type="button"
                                onClick={() => setShowGenerator(false)}
                                className="text-zinc-500 hover:text-zinc-300"
                              >
                                <X className="h-3.5 w-3.5" />
                              </button>
                            </div>

                            <div className="mb-3 flex items-center gap-2 rounded border border-hairline bg-obsidian px-2.5 py-2 font-mono text-xs text-zinc-100">
                              <span className="flex-1 truncate">{genPreview}</span>
                              <button
                                type="button"
                                onClick={() => setGenPreview(generateCryptoPassword(genOpts))}
                                className="text-zinc-400 hover:text-gold"
                              >
                                <RefreshCw className="h-3.5 w-3.5" />
                              </button>
                            </div>

                            <div className="mb-3 space-y-2 text-xs">
                              <div className="flex items-center justify-between text-zinc-400">
                                <span>Length</span>
                                <span className="font-mono text-gold">{genOpts.length}</span>
                              </div>
                              <input
                                type="range"
                                min={12}
                                max={64}
                                value={genOpts.length}
                                onChange={(e) =>
                                  setGenOpts({ ...genOpts, length: Number(e.target.value) })
                                }
                                className="w-full accent-[#c9a84c]"
                              />
                              <div className="flex flex-wrap gap-3 pt-1 text-[11px] text-zinc-400">
                                {(
                                  [
                                    ["uppercase", "A-Z"],
                                    ["lowercase", "a-z"],
                                    ["numbers", "0-9"],
                                    ["symbols", "!@#"],
                                  ] as const
                                ).map(([key, label]) => (
                                  <label key={key} className="flex cursor-pointer items-center gap-1.5">
                                    <input
                                      type="checkbox"
                                      checked={genOpts[key]}
                                      onChange={(e) =>
                                        setGenOpts({ ...genOpts, [key]: e.target.checked })
                                      }
                                      className="accent-[#c9a84c]"
                                    />
                                    <span className="font-mono">{label}</span>
                                  </label>
                                ))}
                              </div>
                            </div>

                            <button
                              type="button"
                              onClick={() => applyGeneratedPassword(genPreview)}
                              className="w-full rounded-md bg-gold py-1.5 text-xs font-semibold text-obsidian hover:bg-gold-bright"
                            >
                              Use Generated Password
                            </button>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>

                    <div>
                      <label className="mb-1 block text-xs text-zinc-400">URL</label>
                      <div className="relative">
                        <Globe className="pointer-events-none absolute top-2.5 left-3 h-4 w-4 text-zinc-500" />
                        <input
                          value={form.url}
                          onChange={(e) => setForm({ ...form, url: e.target.value })}
                          placeholder="https://"
                          className="w-full rounded-md border border-hairline bg-surface py-2 pr-3 pl-9 font-mono text-xs text-zinc-100 focus:border-gold focus:outline-none"
                        />
                      </div>
                    </div>

                    <div>
                      <label className="mb-1 block text-xs text-zinc-400">Notes</label>
                      <textarea
                        rows={3}
                        value={form.notes}
                        onChange={(e) => setForm({ ...form, notes: e.target.value })}
                        className="w-full rounded-md border border-hairline bg-surface px-3 py-2 text-xs text-zinc-100 focus:border-gold focus:outline-none"
                      />
                    </div>
                  </div>
                </motion.form>
              )}
            </AnimatePresence>
          </main>
        </>
      )}

      {/* Gold Telemetry Toast */}
      <AnimatePresence>
        {toast && (
          <motion.div
            key={toast.id}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 12 }}
            className="fixed right-6 bottom-6 flex items-center gap-2 rounded-md border border-gold/40 bg-surface px-3.5 py-2 font-mono text-xs text-gold shadow-lg"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            {toast.message}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}