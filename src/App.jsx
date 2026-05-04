import React, { useState, useEffect } from 'react';
import { Loader2, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import Header from '@/components/Header.jsx';
import LoginScreen from '@/components/LoginScreen.jsx';
import ScanInput from '@/components/ScanInput.jsx';
import ScanAnimation from '@/components/ScanAnimation.jsx';
import ResultsDashboard from '@/components/ResultsDashboard.jsx';
import { extractOAuthCode, exchangeCodeForToken } from '@/auth/github-oauth.js';
import { getAuthenticatedUser } from '@/engine/github-api.js';
import { scanRepository } from '@/engine/scanner.js';

const PHASE = {
  LOGIN:    'login',
  CALLBACK: 'callback',
  INPUT:    'input',
  SCANNING: 'scanning',
  RESULTS:  'results',
  ERROR:    'error',
};

const TOKEN_KEY = 'pwnpipe_token';

function saveToken(t) { localStorage.setItem(TOKEN_KEY, t); }
function loadToken()  { return localStorage.getItem(TOKEN_KEY) ?? ''; }
function clearToken() { localStorage.removeItem(TOKEN_KEY); }

const BASE = import.meta.env.BASE_URL; // '/PWNPipe/' in production, configurable via vite.config.js

// Parse /owner/repo from the URL path, stripping the app base prefix if present.
// Handles both direct navigation (/PWNPipe/owner/repo) and the GitHub Pages 404
// restore cycle which replaces state to /owner/repo (without base).
function parsePathRepo() {
  const path = window.location.pathname;
  const relative = path.startsWith(BASE) ? path.slice(BASE.length) : path.replace(/^\//, '');
  const parts = relative.split('/').filter(Boolean);
  if (parts.length >= 2) return { owner: parts[0], repo: parts[1] };
  return null;
}

function setPathRepo(owner, repo) {
  window.history.pushState({}, '', `${BASE}${owner}/${repo}`);
}

function clearPathRepo() {
  window.history.pushState({}, '', BASE);
}

export default function App() {
  const [phase, setPhase]           = useState(PHASE.LOGIN);
  const [token, setToken]           = useState(null);
  const [user, setUser]             = useState(null);
  const [scanStep, setScanStep]     = useState(0);
  const [scanTarget, setScanTarget] = useState(null);
  const [result, setResult]         = useState(null);
  const [error, setError]           = useState(null);
  const [rateLimit, setRateLimit]   = useState(null);
  // Repo from URL to auto-scan once authenticated
  const [pendingRepo, setPendingRepo] = useState(null);

  useEffect(() => {
    // VITE_DEV_TOKEN is only read in development mode.
    // Vite sets import.meta.env.DEV = true in dev, false in prod builds.
    const DEV_TOKEN = import.meta.env.DEV ? (import.meta.env.VITE_DEV_TOKEN ?? '') : '';

    const initWithToken = async (t, autoScan = null) => {
      setPhase(PHASE.CALLBACK);
      try {
        const { user: profile, rateLimit: rl } = await getAuthenticatedUser(t);
        setToken(t);
        setUser(profile);
        saveToken(t);
        if (rl) setRateLimit(rl);
        if (autoScan) {
          // Trigger the scan directly after auth
          await runScan(t, autoScan.owner, autoScan.repo);
        } else {
          setPhase(PHASE.INPUT);
        }
      } catch {
        clearToken();
        clearPathRepo();
        setPhase(PHASE.LOGIN);
      }
    };

    if (DEV_TOKEN) {
      const pathRepo = parsePathRepo();
      initWithToken(DEV_TOKEN, pathRepo);
      return;
    }

    const code = extractOAuthCode();
    if (code) {
      setPhase(PHASE.CALLBACK);
      (async () => {
        try {
          const accessToken = await exchangeCodeForToken(code);
          // After OAuth callback, check if there was a pending repo in the URL
          const pathRepo = parsePathRepo();
          await initWithToken(accessToken, pathRepo);
        } catch (err) {
          setError(err.message || 'Authentication failed.');
          setPhase(PHASE.ERROR);
        }
      })();
      return;
    }

    // Check URL for /owner/repo before restoring session
    const pathRepo = parsePathRepo();

    const saved = loadToken();
    if (saved) {
      initWithToken(saved, pathRepo);
      return;
    }

    // No token — if URL has /owner/repo, remember it for after login
    if (pathRepo) setPendingRepo(pathRepo);
    setPhase(PHASE.LOGIN);
  }, []);

  // Handle browser back/forward button
  useEffect(() => {
    function onPopState() {
      const pathRepo = parsePathRepo();
      if (!pathRepo && (phase === PHASE.RESULTS || phase === PHASE.SCANNING)) {
        setResult(null);
        setScanTarget(null);
        setPhase(PHASE.INPUT);
      }
    }
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, [phase]);

  async function runScan(t, owner, repo) {
    setScanTarget({ owner, repo });
    setScanStep(0);
    setError(null);
    setPathRepo(owner, repo);
    setPhase(PHASE.SCANNING);

    try {
      const scanResult = await scanRepository(owner, repo, t, ({ step, rateLimit: rl }) => {
        setScanStep(step);
        if (rl) setRateLimit(rl);
      });
      setResult(scanResult);
      if (scanResult.rateLimit) setRateLimit(scanResult.rateLimit);
      setPhase(PHASE.RESULTS);
    } catch (err) {
      setError(err.message || 'Scan failed.');
      clearPathRepo();
      setPhase(PHASE.ERROR);
    }
  }

  function handleContinueAsGuest() {
    if (pendingRepo) {
      runScan(null, pendingRepo.owner, pendingRepo.repo);
      setPendingRepo(null);
    } else {
      setPhase(PHASE.INPUT);
    }
  }

  function handleLogout() {
    clearToken();
    clearPathRepo();
    setToken(null);
    setUser(null);
    setResult(null);
    setScanTarget(null);
    setPendingRepo(null);
    setPhase(PHASE.LOGIN);
  }

  async function handleScan(owner, repo) {
    await runScan(token, owner, repo);
  }

  function handleReset() {
    setResult(null);
    setScanTarget(null);
    clearPathRepo();
    setPhase(PHASE.INPUT);
  }

  return (
    <div className="flex min-h-screen flex-col">
      <Header user={user} onLogout={handleLogout} rateLimit={rateLimit} />

      {phase === PHASE.LOGIN    && (
        <LoginScreen
          onContinueAsGuest={handleContinueAsGuest}
          pendingRepo={pendingRepo}
        />
      )}

      {phase === PHASE.CALLBACK && (
        <Centered>
          <Loader2 className="size-8 animate-spin text-primary" />
          <p className="font-mono text-sm text-muted-foreground">Authenticating with GitHub…</p>
        </Centered>
      )}

      {phase === PHASE.INPUT    && <ScanInput user={user} token={token} rateLimit={rateLimit} onScan={handleScan} />}

      {phase === PHASE.SCANNING && scanTarget && (
        <ScanAnimation currentStep={scanStep} owner={scanTarget.owner} repo={scanTarget.repo} />
      )}

      {phase === PHASE.RESULTS  && result && (
        <ResultsDashboard result={result} onReset={handleReset} />
      )}

      {phase === PHASE.ERROR && (
        <Centered>
          <Card className="w-full max-w-md border-red-600/30">
            <CardContent className="pt-8 pb-6 text-center">
              <AlertTriangle className="mx-auto mb-4 size-10 text-primary" />
              <p className="mb-2 text-base font-semibold">Error</p>
              <p className="mb-6 text-sm leading-7 text-muted-foreground">{error}</p>
              <Button onClick={() => setPhase(token ? PHASE.INPUT : PHASE.LOGIN)}>
                {token ? '← Back to scan' : '← Back to login'}
              </Button>
            </CardContent>
          </Card>
        </Centered>
      )}
    </div>
  );
}

function Centered({ children }) {
  return (
    <main className="flex flex-1 flex-col items-center justify-center gap-4 px-6">
      {children}
    </main>
  );
}
