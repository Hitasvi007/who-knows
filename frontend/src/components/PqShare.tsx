import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  KeyRound,
  Copy,
  Check,
  Lock,
  Unlock,
  ArrowRight,
  AlertTriangle,
  ShieldCheck,
} from "lucide-react";
import { api, ApiError } from "../api";
import { bundleFingerprint } from "../utils/fingerprint";
import { copySecret } from "../utils/clipboard";

function Fingerprint({ value, label }: { value: string | null; label: string }) {
  if (!value) return null;
  return (
    <p className="font-mono text-[11px] text-zinc-500">
      {label}: <span className="text-gold">{value}</span>
    </p>
  );
}

export function PqShare() {
  const [publicBundle, setPublicBundle] = useState("");
  const [bundleBytes, setBundleBytes] = useState(0);
  const [copied, setCopied] = useState<string | null>(null);
  const [ownFp, setOwnFp] = useState<string | null>(null);
  const [recipientFp, setRecipientFp] = useState<string | null>(null);

  // Encrypt state
  const [recipientBundle, setRecipientBundle] = useState("");
  const [plaintextInput, setPlaintextInput] = useState("");
  const [envelopeOutput, setEnvelopeOutput] = useState("");
  const [encrypting, setEncrypting] = useState(false);
  const [encryptError, setEncryptError] = useState<string | null>(null);

  // Decrypt state
  const [envelopeInput, setEnvelopeInput] = useState("");
  const [decryptedText, setDecryptedText] = useState<string | null>(null);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptError, setDecryptError] = useState<string | null>(null);

  useEffect(() => {
    api
      .pqcPublicKey()
      .then((res) => {
        setPublicBundle(res.public_bundle);
        setBundleBytes(res.size_bytes);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    bundleFingerprint(publicBundle).then(setOwnFp);
  }, [publicBundle]);

  useEffect(() => {
    bundleFingerprint(recipientBundle).then(setRecipientFp);
  }, [recipientBundle]);

  async function copy(key: string, value: string) {
    if (!value) return;
    try {
      // Decrypted plaintext is a secret: same 30s auto-clear as vault passwords
      if (key === "plain") await copySecret(value);
      else await navigator.clipboard.writeText(value);
    } catch {
      return;
    }
    setCopied(key);
    setTimeout(() => setCopied(null), 1500);
  }

  async function handleEncrypt(e: React.FormEvent) {
    e.preventDefault();
    if (!recipientBundle.trim() || !plaintextInput.trim()) return;
    setEncrypting(true);
    setEncryptError(null);
    try {
      const res = await api.pqcEncrypt(recipientBundle.trim(), plaintextInput);
      setEnvelopeOutput(JSON.stringify(res.envelope, null, 2));
    } catch (err) {
      setEncryptError(err instanceof ApiError ? err.message : "Encryption failed.");
    } finally {
      setEncrypting(false);
    }
  }

  async function handleDecrypt(e: React.FormEvent) {
    e.preventDefault();
    if (!envelopeInput.trim()) return;
    setDecrypting(true);
    setDecryptError(null);
    setDecryptedText(null);
    try {
      const parsed = JSON.parse(envelopeInput) as Record<string, string>;
      const res = await api.pqcDecrypt(parsed);
      setDecryptedText(res.plaintext);
    } catch (err) {
      if (err instanceof SyntaxError) {
        setDecryptError("Invalid JSON envelope format.");
      } else if (err instanceof ApiError) {
        setDecryptError(err.message);
      } else {
        setDecryptError("Decryption failed.");
      }
    } finally {
      setDecrypting(false);
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6 pb-10">
      {/* Header */}
      <div className="border-b border-hairline pb-4">
        <h1 className="text-base font-semibold tracking-tight text-zinc-100">
          Hybrid Post-Quantum Share
        </h1>
        <p className="font-mono text-xs text-zinc-500">
          Offline X25519 + ML-KEM-768 hybrid key encapsulation with XChaCha20-Poly1305.
        </p>
      </div>

      {/* Your Public Bundle Card */}
      <section className="rounded-lg border border-gold/25 bg-surface p-5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-gold" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
              Your Hybrid Public Key Bundle
            </h2>
          </div>
          <span className="font-mono text-[11px] text-gold">
            {bundleBytes ? `${bundleBytes.toLocaleString()} bytes · X25519 + ML-KEM-768` : "Loading..."}
          </span>
        </div>

        <div className="flex gap-2">
          <input
            readOnly
            value={publicBundle}
            placeholder="Fetching public bundle..."
            className="flex-1 rounded-md border border-hairline bg-obsidian px-3 py-2 font-mono text-xs text-zinc-300 focus:outline-none"
          />
          <button
            type="button"
            onClick={() => copy("pub", publicBundle)}
            className="flex items-center gap-1.5 rounded-md border border-hairline bg-obsidian px-3 py-2 text-xs text-zinc-300 transition hover:border-gold/40 hover:text-gold"
          >
            {copied === "pub" ? (
              <Check className="h-3.5 w-3.5 text-gold" />
            ) : (
              <Copy className="h-3.5 w-3.5" />
            )}
            Copy
          </button>
          <button
            type="button"
            onClick={() => setRecipientBundle(publicBundle)}
            className="rounded-md border border-gold/30 bg-gold-dim px-3 py-2 font-mono text-xs text-gold transition hover:bg-gold/20"
          >
            Use Own Key
          </button>
        </div>
        <Fingerprint value={ownFp} label="Your fingerprint" />
        {ownFp && <p className="text-[11px] text-zinc-500">Compare this fingerprint with the other person over a separate channel (in person or by phone). The share format does not authenticate keys or senders.</p>}
      </section>

      {/* Split-Pane Encrypt / Decrypt */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Encrypt Pane */}
        <form
          onSubmit={handleEncrypt}
          className="space-y-4 rounded-lg border border-hairline bg-surface p-5"
        >
          <div className="flex items-center gap-2">
            <Lock className="h-4 w-4 text-gold" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
              Encapsulate & Encrypt
            </h2>
          </div>

          <div>
            <label className="mb-1 block text-xs text-zinc-400">Recipient Public Bundle</label>
            <textarea
              rows={2}
              value={recipientBundle}
              onChange={(e) => setRecipientBundle(e.target.value)}
              placeholder="Paste recipient's wk_pub_... bundle"
              className="w-full rounded-md border border-hairline bg-obsidian px-3 py-2 font-mono text-[11px] text-zinc-200 placeholder-zinc-600 focus:border-gold focus:outline-none"
            />
            <Fingerprint value={recipientFp} label="Recipient fingerprint" />
            {recipientFp && (
              <p className="text-[11px] text-zinc-500">
                Confirm this matches the fingerprint the recipient sees before sending.
              </p>
            )}
          </div>

          <div>
            <label className="mb-1 block text-xs text-zinc-400">Secret Payload</label>
            <textarea
              rows={3}
              value={plaintextInput}
              onChange={(e) => setPlaintextInput(e.target.value)}
              placeholder="Credential, API key, or recovery phrase to share offline..."
              className="w-full rounded-md border border-hairline bg-obsidian px-3 py-2 font-mono text-xs text-zinc-100 placeholder-zinc-600 focus:border-gold focus:outline-none"
            />
          </div>

          {encryptError && (
            <div className="flex items-center gap-2 rounded border border-red-500/30 bg-red-500/10 p-2.5 text-xs text-red-300">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              {encryptError}
            </div>
          )}

          <button
            type="submit"
            disabled={encrypting || !recipientBundle.trim() || !plaintextInput.trim()}
            className="flex w-full items-center justify-center gap-2 rounded-md bg-gold px-4 py-2 text-xs font-semibold text-obsidian transition hover:bg-gold-bright disabled:opacity-50"
          >
            <Lock className="h-3.5 w-3.5" />
            {encrypting ? "Encapsulating..." : "Generate PQ Envelope"}
          </button>

          {envelopeOutput && (
            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-2 pt-2"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-[11px] text-gold">PQ ENVELOPE (UNSIGNED)</span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => copy("env", envelopeOutput)}
                    className="flex items-center gap-1 font-mono text-[11px] text-zinc-400 hover:text-gold"
                  >
                    {copied === "env" ? (
                      <Check className="h-3 w-3 text-gold" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                    Copy
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setEnvelopeInput(envelopeOutput);
                      setDecryptedText(null);
                      setDecryptError(null);
                    }}
                    className="flex items-center gap-1 font-mono text-[11px] text-gold hover:underline"
                  >
                    Send to Decrypt
                    <ArrowRight className="h-3 w-3" />
                  </button>
                </div>
              </div>
              <pre className="max-h-48 overflow-auto rounded-md border border-hairline bg-obsidian p-3 font-mono text-[11px] text-zinc-300">
                {envelopeOutput}
              </pre>
            </motion.div>
          )}
        </form>

        {/* Decrypt Pane */}
        <form
          onSubmit={handleDecrypt}
          className="space-y-4 rounded-lg border border-hairline bg-surface p-5"
        >
          <div className="flex items-center gap-2">
            <Unlock className="h-4 w-4 text-gold" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
              Decapsulate & Decrypt
            </h2>
          </div>

          <div>
            <label className="mb-1 block text-xs text-zinc-400">Encrypted JSON Envelope</label>
            <textarea
              rows={7}
              value={envelopeInput}
              onChange={(e) => setEnvelopeInput(e.target.value)}
              placeholder='Paste JSON envelope {"mlkem_ciphertext": "...", "ephemeral_x25519_pub": "...", ...}'
              className="w-full rounded-md border border-hairline bg-obsidian px-3 py-2 font-mono text-[11px] text-zinc-200 placeholder-zinc-600 focus:border-gold focus:outline-none"
            />
          </div>

          {decryptError && (
            <div className="flex items-center gap-2 rounded border border-red-500/30 bg-red-500/10 p-2.5 text-xs text-red-300">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              {decryptError}
            </div>
          )}

          <button
            type="submit"
            disabled={decrypting || !envelopeInput.trim()}
            className="flex w-full items-center justify-center gap-2 rounded-md border border-gold/40 bg-gold-dim px-4 py-2 text-xs font-semibold text-gold transition hover:bg-gold/20 disabled:opacity-50"
          >
            <Unlock className="h-3.5 w-3.5" />
            {decrypting ? "Decapsulating..." : "Decrypt with Local Vault Key"}
          </button>

          {decryptedText !== null && (
            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-2 rounded-md border border-gold/35 bg-obsidian p-3.5"
            >
              <div className="flex items-center justify-between font-mono text-[11px]">
                <span className="flex items-center gap-1.5 text-gold">
                  <ShieldCheck className="h-3.5 w-3.5" />
                  DECRYPTED · SENDER NOT AUTHENTICATED
                </span>
                <button
                  type="button"
                  onClick={() => copy("plain", decryptedText)}
                  className="flex items-center gap-1 text-zinc-400 hover:text-gold"
                >
                  {copied === "plain" ? (
                    <Check className="h-3 w-3 text-gold" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                  Copy
                </button>
              </div>
              <pre className="whitespace-pre-wrap break-all font-mono text-xs text-zinc-100">
                {decryptedText}
              </pre>
            </motion.div>
          )}
        </form>
      </div>
    </div>
  );
}