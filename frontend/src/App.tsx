import { useEffect, useState } from "react";
import { api, type VaultStatus } from "./api";
import { LockScreen } from "./components/LockScreen";
import { VaultWorkspace, type NavTab } from "./components/VaultWorkspace";
import { TamperLab } from "./components/TamperLab";
import { PqShare } from "./components/PqShare";

export default function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [unlockMs, setUnlockMs] = useState<number | undefined>();
  const [activeTab, setActiveTab] = useState<NavTab>("vault");

  async function refreshStatus() {
    const s = await api.status();
    setStatus(s);
  }

  useEffect(() => {
    refreshStatus();
  }, []);

  if (!status) {
    return (
      <div className="flex h-screen items-center justify-center bg-obsidian font-mono text-xs text-zinc-500">
        Connecting to local vault daemon…
      </div>
    );
  }

  if (!status.unlocked) {
    return (
      <LockScreen
        vaultExists={status.exists}
        onUnlocked={(mode, seqNum, ms) => {
          setUnlockMs(ms);
          setStatus({ exists: true, unlocked: true, mode, seq_num: seqNum });
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
        await api.lock();
        setUnlockMs(undefined);
        await refreshStatus();
      }}
      renderSecondaryTab={(tab) => (tab === "tamper" ? <TamperLab /> : <PqShare />)}
    />
  );
}