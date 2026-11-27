const CLEAR_AFTER_MS = 30_000;

let clearTimer: number | null = null;
let secretOnClipboard = false;
let notify: (message: string) => void = () => {};

/** Lets the workspace show toasts (e.g. when a clear attempt fails). */
export function setClipboardNotifier(fn: (message: string) => void) {
  notify = fn;
}

/**
 * Clears the clipboard if we put a secret there. Browsers reject clipboard writes while the
 * page is unfocused, so a failed clear stays pending and is retried on focus/visibility.
 */
export async function clearClipboard(): Promise<boolean> {
  if (!secretOnClipboard) return true;
  try {
    await navigator.clipboard.writeText("");
    secretOnClipboard = false;
    if (clearTimer !== null) window.clearTimeout(clearTimer);
    clearTimer = null;
    return true;
  } catch {
    notify("Could not clear the clipboard (window not focused). It will clear when you return.");
    return false;
  }
}

/** Copies a secret and schedules an auto-clear after 30 seconds. */
export async function copySecret(value: string) {
  await navigator.clipboard.writeText(value);
  secretOnClipboard = true;
  if (clearTimer !== null) window.clearTimeout(clearTimer);
  clearTimer = window.setTimeout(() => {
    clearTimer = null;
    clearClipboard();
  }, CLEAR_AFTER_MS);
}

function retryPendingClear() {
  // Retry only after the 30s timer has fired; before that the secret is meant to stay
  if (secretOnClipboard && clearTimer === null) clearClipboard();
}

if (typeof document !== "undefined") {
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") clearClipboard();
    else retryPendingClear();
  });
  window.addEventListener("focus", retryPendingClear);
}
