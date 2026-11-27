const PUB_PREFIX = "wk_pub_";
const BUNDLE_BYTES = 1216; // X25519 (32B) + ML-KEM-768 (1,184B)

/**
 * Short fingerprint of a hybrid public bundle: first 20 hex chars of SHA-256 over the raw
 * bundle bytes, grouped in blocks of 4. Returns null for anything that is not a valid bundle.
 */
export async function bundleFingerprint(bundle: string): Promise<string | null> {
  const trimmed = bundle.trim();
  if (!trimmed.startsWith(PUB_PREFIX)) return null;
  try {
    const b64 = trimmed.slice(PUB_PREFIX.length).replace(/-/g, "+").replace(/_/g, "/");
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    if (bytes.length !== BUNDLE_BYTES) return null;
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    const hex = Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("").slice(0, 20);
    return hex.match(/.{4}/g)!.join(" ");
  } catch {
    return null;
  }
}
