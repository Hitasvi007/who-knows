import { ZxcvbnFactory } from "@zxcvbn-ts/core";
import * as zxcvbnCommon from "@zxcvbn-ts/language-common";
import * as zxcvbnEn from "@zxcvbn-ts/language-en";

export interface PasswordAnalysis {
  score: 0 | 1 | 2 | 3 | 4;
  label: "Critical" | "Weak" | "Fair" | "Strong" | "Hardened";
  entropyBits: number;
  isSafe: boolean;
  warnings: string[];
}

const zxcvbn = new ZxcvbnFactory({
  translations: zxcvbnEn.translations,
  graphs: zxcvbnCommon.adjacencyGraphs,
  dictionary: { ...zxcvbnCommon.dictionary, ...zxcvbnEn.dictionary, app: ["whoknows"] },
});

const LABELS: PasswordAnalysis["label"][] = ["Critical", "Weak", "Fair", "Strong", "Hardened"];

export function analyzePassword(pw: string, isMaster = false): PasswordAnalysis {
  if (!pw) {
    return { score: 0, label: "Critical", entropyBits: 0, isSafe: false, warnings: [] };
  }

  // zxcvbn models dictionary words, keyboard walks, dates and l33t, so human-style passwords
  // are not scored as if every character were random within its class.
  const result = zxcvbn.check(pw);
  const minLen = isMaster ? 14 : 12;
  const warnings = [
    ...(pw.length < minLen ? [`Under ${minLen} characters`] : []),
    ...(result.feedback.warning ? [result.feedback.warning] : []),
    ...result.feedback.suggestions,
  ];
  const score = result.score;

  return {
    score,
    label: LABELS[score],
    entropyBits: Math.round(result.guessesLog10 * Math.log2(10)),
    // The master password guards everything offline, so it needs the top score
    isSafe: score >= (isMaster ? 4 : 3) && pw.length >= minLen,
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