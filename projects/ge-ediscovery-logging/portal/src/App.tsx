import React, { useState, useMemo, useEffect, useCallback } from 'react';
import {
  buildDynamicUsers,
  getUnifiedReviewItems,
} from './data/dbData';
import { TopBar } from './components/TopBar';
import { LoginScreen } from './components/LoginScreen';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LegalBriefNarrative } from './components/architectures/LegalBriefNarrative';
import {
  auth,
  onAuthStateChanged,
  logout,
  isAuthorizedEmail,
  User,
} from './services/firebaseAuth';
import { fetchLiveComplianceLogs } from './services/complianceApi';
import { matchesQuery } from './utils/searchUtils';
import { ComplianceDataset, EMPTY_DATASET } from './types/schema';
import { EditorialTheme, THEMES } from './types/theme';
import { Loader2 } from 'lucide-react';

export const App: React.FC = () => {
  // Theme State (Default: 'cloud' - True Blue)
  const [selectedTheme, setSelectedTheme] = useState<EditorialTheme>(() => {
    const saved = localStorage.getItem('ge_portal_theme') as EditorialTheme;
    if (saved && ['cloud', 'canvas', 'legal', 'dark'].includes(saved)) {
      return saved;
    }
    return 'cloud';
  });

  const handleSelectTheme = (theme: EditorialTheme) => {
    setSelectedTheme(theme);
    localStorage.setItem('ge_portal_theme', theme);
  };

  const currentTheme = THEMES[selectedTheme] || THEMES.cloud;

  // Auth State
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [authInitialized, setAuthInitialized] = useState(false);

  // BigQuery Dataset
  const [dataset, setDataset] = useState<ComplianceDataset>(EMPTY_DATASET);

  // Syncing state
  const [isSyncing, setIsSyncing] = useState(false);
  const [lastSyncedTime, setLastSyncedTime] = useState<string | null>(null);

  // Surface & Filters State
  const [surfaceMode, setSurfaceMode] = useState<'NOTEBOOK_LM' | 'GEMINI_ENTERPRISE_CHAT'>('GEMINI_ENTERPRISE_CHAT');
  const [selectedUserEmail, setSelectedUserEmail] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);
  const [selectedStartTime, setSelectedStartTime] = useState<number | null>(null);

  // Live BigQuery Sync Function
  const syncWithBigQuery = useCallback(async (forceRefresh = false) => {
    setIsSyncing(true);
    try {
      const live = await fetchLiveComplianceLogs(forceRefresh);
      setDataset({
        processedLogs: live.processed_logs || [],
        sources: live.sources || [],
        chats: live.chat || [],
        studio: live.studio || [],
        notebookRawLogs: live.notebook_raw_logs || [],
      });
      setLastSyncedTime(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    } catch (e) {
      console.warn('BigQuery live sync error:', e);
    } finally {
      setIsSyncing(false);
    }
  }, []);

  // Initialize Firebase Auth listener
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      if (user && isAuthorizedEmail(user.email)) {
        setCurrentUser(user);
      } else {
        setCurrentUser(null);
      }
      setAuthInitialized(true);
    });
    return () => unsubscribe();
  }, []);

  // Automatically sync BigQuery telemetry whenever user is authenticated
  useEffect(() => {
    if (currentUser) {
      syncWithBigQuery(false);
    }
  }, [currentUser, syncWithBigQuery]);

  const handleSignOut = async () => {
    await logout();
    setCurrentUser(null);
  };

  // Build Dynamic Users
  const users = useMemo(() => {
    return buildDynamicUsers(dataset);
  }, [dataset]);

  // Build Unified Review Items
  const unifiedItems = useMemo(() => {
    return getUnifiedReviewItems(dataset);
  }, [dataset]);

  // Compute dataset bounds: Max is ALWAYS Today (Now), Min is earliest record creation
  const { minTimestamp, maxTimestamp } = useMemo(() => {
    const now = Date.now();
    if (unifiedItems.length === 0) {
      return { minTimestamp: now - 30 * 24 * 60 * 60 * 1000, maxTimestamp: now };
    }
    let minT = Infinity;
    for (const item of unifiedItems) {
      const t = new Date(item.timestamp).getTime();
      if (!isNaN(t) && t < minT) {
        minT = t;
      }
    }
    if (minT === Infinity || minT >= now) {
      minT = now - 30 * 24 * 60 * 60 * 1000;
    }
    return { minTimestamp: minT, maxTimestamp: now };
  }, [unifiedItems]);

  const activeStartTime = useMemo<number>(() => {
    if (selectedStartTime !== null) {
      return Math.max(minTimestamp, Math.min(maxTimestamp, selectedStartTime));
    }
    return minTimestamp;
  }, [selectedStartTime, minTimestamp, maxTimestamp]);

  // Filtered items based on surface, user, search, and single lookback start time
  const filteredItems = useMemo(() => {
    const targetEmail = selectedUserEmail?.toLowerCase() ?? null;

    return unifiedItems.filter((item) => {
      if (item.surface !== surfaceMode) return false;
      if (targetEmail && item.user_email.toLowerCase() !== targetEmail) return false;
      
      const itemTime = new Date(item.timestamp).getTime();
      if (!isNaN(itemTime)) {
        if (itemTime < activeStartTime || itemTime > maxTimestamp) return false;
      }
      return matchesQuery(item, searchQuery);
    });
  }, [unifiedItems, surfaceMode, selectedUserEmail, searchQuery, activeStartTime, maxTimestamp]);

  const activeItem = useMemo(() => {
    if (selectedItemId) {
      const found = filteredItems.find((i) => i.id === selectedItemId);
      if (found) return found;
    }
    return filteredItems[0] || null;
  }, [filteredItems, selectedItemId]);

  if (!authInitialized) {
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-zinc-100 text-zinc-600 font-sans">
        <Loader2 className="w-6 h-6 animate-spin text-zinc-900 mr-2" />
        <span className="font-medium text-xs">Authenticating Compliance Portal...</span>
      </div>
    );
  }

  if (!currentUser) {
    return <LoginScreen onLoginSuccess={(user) => setCurrentUser(user)} />;
  }

  return (
    <ErrorBoundary>
      <div className={`flex flex-col h-screen w-screen overflow-hidden antialiased select-none transition-colors duration-150 ${currentTheme.appBgClass} ${currentTheme.bodyFont}`}>
        {/* Universal Top Navigation Header */}
        <TopBar
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          currentUser={currentUser}
          onSignOut={handleSignOut}
          onSyncBigQuery={() => syncWithBigQuery(true)}
          isSyncing={isSyncing}
          lastSyncedTime={lastSyncedTime || undefined}
          selectedTheme={selectedTheme}
          allItems={unifiedItems}
          onSelectSearchResult={(res) => {
            setSurfaceMode(res.surface);
            setSelectedUserEmail(res.userEmail);
            setSelectedItemId(res.sessionId);
            setSearchQuery('');
          }}
        />

        {/* Master-Detail Compliance Workspace */}
        <main className="flex-1 flex overflow-hidden">
          <LegalBriefNarrative
            items={filteredItems}
            allItems={unifiedItems}
            users={users}
            activeItem={activeItem}
            onSelectItem={(id) => setSelectedItemId(id)}
            selectedUserEmail={selectedUserEmail}
            onSelectUser={setSelectedUserEmail}
            surfaceMode={surfaceMode}
            onSurfaceChange={(mode) => {
              setSurfaceMode(mode);
              setSelectedItemId(null);
            }}
            selectedTheme={selectedTheme}
            onSelectTheme={handleSelectTheme}
            minTimestamp={minTimestamp}
            maxTimestamp={maxTimestamp}
            selectedStartTime={activeStartTime}
            onStartTimeChange={setSelectedStartTime}
          />
        </main>
      </div>
    </ErrorBoundary>
  );
};

export default App;
