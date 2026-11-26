export interface PasswordAnalysis {
  score: 0 | 1 | 2 | 3 | 4;
  label: "Critical" | "Weak" | "Fair" | "Strong" | "Hardened";
  entropyBits: number;
  isSafe: boolean;
  warnings: string[];
}

const COMMON_FRAGMENTS = [
  "password",
  "qwerty",
  "admin",
  "welcome",
  "letmein",
  "123456",
  "12345",
  "1234",
  "abcd",
  "iloveyou",
  "whoknows",
  "pass123",
  "master",
];

export function analyzePassword(pw: string, isMaster = false): PasswordAnalysis {
  if (!pw) {
    return { score: 0, label: "Critical", entropyBits: 0, isSafe: false, warnings: [] };
  }

  const warnings: string[] = [];
  const lower = pw.toLowerCase();

  let pool = 0;
  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /\d/.test(pw);
  const hasSymbol = /[^a-zA-Z0-9]/.test(pw);

  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigit) pool += 10;
  if (hasSymbol) pool += 32;

  // Base entropy reduced for repeated characters
  const uniqueChars = new Set(pw).size;
  const uniquenessRatio = uniqueChars / pw.length;
  let entropy = pw.length * Math.log2(Math.max(pool, 1)) * (0.5 + 0.5 * uniquenessRatio);

  const minLen = isMaster ? 14 : 12;
  if (pw.length < minLen) {
    warnings.push(`Under ${minLen} characters`);
  }

  if (COMMON_FRAGMENTS.some((frag) => lower.includes(frag))) {
    entropy *= 0.45;
    warnings.push("Contains common word or sequence");
  }

  if (/(.)\1{2,}/.test(pw)) {
    entropy *= 0.75;
    warnings.push("Repeated characters reduce entropy");
  }

  if (/^\d+$/.test(pw) || /^[a-zA-Z]+$/.test(pw)) {
    warnings.push("Mix letters, numbers, and symbols");
  }

  const entropyBits = Math.round(entropy);
  const safeThreshold = isMaster ? 72 : 60;

  let score: 0 | 1 | 2 | 3 | 4 = 0;
  let label: PasswordAnalysis["label"] = "Critical";

  if (entropyBits >= 95 && warnings.length === 0) {
    score = 4;
    label = "Hardened";
  } else if (entropyBits >= safeThreshold && warnings.length <= 1) {
    score = 3;
    label = "Strong";
  } else if (entropyBits >= 42) {
    score = 2;
    label = "Fair";
  } else if (entropyBits >= 25) {
    score = 1;
    label = "Weak";
  }

  return {
    score,
    label,
    entropyBits,
    isSafe: score >= 3,
    warnings,
  };
}

export interface GeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

export function generateCryptoPassword(opts: GeneratorOptions): string {
  let charset = "";
  if (opts.lowercase) charset += "abcdefghijkmnopqrstuvwxyz";
  if (opts.uppercase) charset += "ABCDEFGHJKLMNPQRSTUVWXYZ";
  if (opts.numbers) charset += "23456789";
  if (opts.symbols) charset += "!@#$%^&*()-_=+[]{}?";

  if (!charset) charset = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  // Rejection sampling prevents modulo bias
  const maxValid = Math.floor(256 / charset.length) * charset.length;
  const result: string[] = [];
  const buf = new Uint8Array(opts.length * 2);

  while (result.length < opts.length) {
    window.crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && result.length < opts.length; i++) {
      if (buf[i] < maxValid) {
        result.push(charset[buf[i] % charset.length]);
      }
    }
  }
  return result.join("");
}