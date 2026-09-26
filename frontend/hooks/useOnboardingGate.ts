'use client';

import { useEffect, useState, useCallback } from 'react';
import { apiClient } from '@/lib/api-client';
import { useAuth } from '@/store/authStore';

const SKIP_KEY = 'chioma_onboarding_email_skip';

interface OnboardingStatus {
  emailCollected: boolean;
  emailCollectedAt: string | null;
}

interface OnboardingGate {
  /** True while the server status is being fetched */
  loading: boolean;
  /** Whether the user has completed email onboarding server-side */
  emailCollected: boolean;
  /** User explicitly skipped for this session (cleared on next login/refresh) */
  skipped: boolean;
  /** Call when the user completes the email step — persists to server */
  markEmailCollected: () => Promise<void>;
  /** Temporarily defer the gate for this session */
  skipForSession: () => void;
  /** Whether the gate should be shown to the user */
  showGate: boolean;
}

export function useOnboardingGate(): OnboardingGate {
  const { isAuthenticated } = useAuth();
  const [loading, setLoading] = useState(true);
  const [emailCollected, setEmailCollected] = useState(false);
  const [skipped, setSkipped] = useState(false);

  // Clear any stale skip flag from a previous session on mount.
  // sessionStorage is tab-scoped, but we also clear on auth state change to
  // prevent the flag surviving a token refresh within the same tab.
  useEffect(() => {
    if (!isAuthenticated) {
      sessionStorage.removeItem(SKIP_KEY);
      setSkipped(false);
    }
  }, [isAuthenticated]);

  // Fetch server-side onboarding status whenever the user is authenticated.
  useEffect(() => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);

    apiClient
      .get<OnboardingStatus>('/users/me/email-onboarding-status')
      .then(({ data }) => {
        if (!cancelled) {
          setEmailCollected(data.emailCollected);
          // If server says collected, clear any lingering skip flag
          if (data.emailCollected) {
            sessionStorage.removeItem(SKIP_KEY);
            setSkipped(false);
          } else {
            // Restore skip state from sessionStorage (same browser tab only)
            setSkipped(sessionStorage.getItem(SKIP_KEY) === '1');
          }
        }
      })
      .catch(() => {
        // On error, default to not blocking the user — fail open here
        if (!cancelled) setEmailCollected(false);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [isAuthenticated]);

  const markEmailCollected = useCallback(async () => {
    await apiClient.post('/users/me/email-collected');
    setEmailCollected(true);
    sessionStorage.removeItem(SKIP_KEY);
    setSkipped(false);
  }, []);

  const skipForSession = useCallback(() => {
    sessionStorage.setItem(SKIP_KEY, '1');
    setSkipped(true);
  }, []);

  const showGate =
    isAuthenticated && !loading && !emailCollected && !skipped;

  return {
    loading,
    emailCollected,
    skipped,
    markEmailCollected,
    skipForSession,
    showGate,
  };
}
