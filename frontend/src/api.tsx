const API_BASE = "http://127.0.0.1:8000";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      // fallback to statusText
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  mode: "real" | "decoy" | null;
  seq_num: number;
}

export interface VaultEntry {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  totp_secret: string;
  notes: string;
  created_at: number;
  updated_at: number;
}

export interface TamperInspectResult {
  total_bytes: number;
  header_hex: string;
  seq_num: number;
  prev_hash: string;
  slot1_entropy: number;
  slot2_entropy: number;
  sig_bytes: number;
}

export interface TamperAttackResult {
  attack: string;
  caught: boolean;
  layer?: string;
  offset?: number;
  rejected_before_kdf?: boolean;
  error?: string;
}

export interface DuressTimingResult {
  real_ms: number;
  decoy_ms: number;
  ratio: number;
  constant_time_pass: boolean;
}

export const api = {
  // Vault Lifecycle
  status: () => request<VaultStatus>("/api/vault/status"),
  init: (real_password: string, duress_password?: string) =>
    request<{ status: string; seq_num: number; size_bytes: number }>("/api/vault/init", {
      method: "POST",
      body: JSON.stringify({
        real_password,
        duress_password: duress_password || undefined,
      }),
    }),
  unlock: (password: string) =>
    request<{ status: string; mode: "real" | "decoy"; seq_num: number; unlock_ms: number }>(
      "/api/vault/unlock",
      { method: "POST", body: JSON.stringify({ password }) }
    ),
  lock: () => request<{ status: string }>("/api/vault/lock", { method: "POST" }),

  // Credential CRUD
  listEntries: (q?: string) =>
    request<VaultEntry[]>(`/api/entries${q ? `?q=${encodeURIComponent(q)}` : ""}`),
  createEntry: (entry: Partial<VaultEntry> & { title: string }) =>
    request<{ entry: VaultEntry; seq_num: number }>("/api/entries", {
      method: "POST",
      body: JSON.stringify(entry),
    }),
  updateEntry: (id: string, fields: Partial<VaultEntry>) =>
    request<{ entry: VaultEntry; seq_num: number }>(`/api/entries/${id}`, {
      method: "PATCH",
      body: JSON.stringify(fields),
    }),
  deleteEntry: (id: string) =>
    request<{ deleted: boolean; seq_num: number }>(`/api/entries/${id}`, {
      method: "DELETE",
    }),

  // Hybrid Post-Quantum Sharing
  pqcPublicKey: () =>
    request<{ public_bundle: string; size_bytes: number }>("/api/pqc/public-key"),
  pqcEncrypt: (recipient_bundle: string, payload: string) =>
    request<{ envelope: Record<string, string> }>("/api/pqc/encrypt", {
      method: "POST",
      body: JSON.stringify({ recipient_bundle, payload }),
    }),
  pqcDecrypt: (envelope: Record<string, string>) =>
    request<{ plaintext: string }>("/api/pqc/decrypt", {
      method: "POST",
      body: JSON.stringify({ envelope }),
    }),

  // Interactive Tamper Lab
  tamperInspect: () => request<TamperInspectResult>("/api/tamper/inspect"),
  tamperBitFlip: (offset = 264) =>
    request<TamperAttackResult>("/api/tamper/bit-flip", {
      method: "POST",
      body: JSON.stringify({ offset }),
    }),
  tamperHeaderAad: () =>
    request<TamperAttackResult>("/api/tamper/header-aad", { method: "POST" }),
  tamperSignature: () =>
    request<TamperAttackResult>("/api/tamper/signature", { method: "POST" }),
  tamperRollback: () =>
    request<TamperAttackResult>("/api/tamper/rollback", { method: "POST" }),
  tamperDuressTiming: () =>
    request<DuressTimingResult>("/api/tamper/duress-timing", { method: "POST" }),
};