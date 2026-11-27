import { useEffect, useState } from "react";
import { api, ApiError, type VaultStatus } from "./api";
import { LockScreen } from "./components/LockScreen";
import { VaultWorkspace, type NavTab } from "./components/VaultWorkspace";
import { TamperLab } from "./components/TamperLab";
import { PqShare } from "./components/PqShare";
import { clearClipboard } from "./utils/clipboard";

export default function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [unlockMs, setUnlockMs] = useState<number | undefined>();
  const [activeTab, setActiveTab] = useState<NavTab>("vault");

  async function refreshStatus() {
    try {
      setStatus(await api.status());
      setConnectError(null);
    } catch (err) {
      setConnectError(
        err instanceof ApiError && err.status === 401
          ? "No session. Open the one-time launch link printed by the whoknows daemon."
          : "Cannot reach the local vault daemon."
      );
    }
  }

  useEffect(() => {
    refreshStatus();
  }, []);

  if (!status) {
    return (
      <div className="flex h-screen items-center justify-center bg-obsidian font-mono text-xs text-zinc-500">
        {connectError ?? "Connecting to local vault daemon…"}
      </div>
    );
  }

  if (!status.unlocked) {
    return (
      <LockScreen
        vaultExists={status.exists}
        onUnlocked={(seqNum, ms) => {
          setUnlockMs(ms);
          setStatus({ exists: true, unlocked: true, seq_num: seqNum });
        }}
      />
    );
  }

  return (
    <VaultWorkspace
      seqNum={status.seq_num}
      unlockMs={unlockMs}
      activeTab={activeTab}
      onTabChange={setActiveTab}
      onSeqChange={(seq) => setStatus((prev) => (prev ? { ...prev, seq_num: seq } : prev))}
      onLock={async () => {
        await clearClipboard();
        await api.lock();
        setUnlockMs(undefined);
        await refreshStatus();
      }}
      renderSecondaryTab={(tab) => (tab === "tamper" ? <TamperLab /> : <PqShare />)}
    />
  );
}