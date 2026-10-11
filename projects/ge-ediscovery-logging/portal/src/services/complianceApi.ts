import { getCachedAuthToken, getActiveAuthToken } from './firebaseAuth';

export interface ComplianceDataResponse {
  processed_logs: any[];
  sources: any[];
  chat: any[];
  studio: any[];
  notebook_raw_logs: any[];
  sandbox_artifacts: any[];
  fetched_at: string;
  is_live: boolean;
  cached?: boolean;
}

async function getAuthHeaders(): Promise<Record<string, string>> {
  const headers: Record<string, string> = {
    'Accept': 'application/json',
  };
  try {
    const token = await getActiveAuthToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  } catch (err) {
    console.warn('Failed to retrieve Firebase ID token:', err);
  }
  return headers;
}

export async function fetchLiveComplianceLogs(forceRefresh = false): Promise<ComplianceDataResponse> {
  try {
    const url = `/api/logs?force_refresh=${forceRefresh ? 'true' : 'false'}`;
    const headers = await getAuthHeaders();
    const response = await fetch(url, {
      method: 'GET',
      headers,
    });

    if (response.ok) {
      const data = await response.json();
      return {
        processed_logs: data.processed_logs || [],
        sources: data.sources || [],
        chat: data.chat || [],
        studio: data.studio || [],
        notebook_raw_logs: data.notebook_raw_logs || [],
        sandbox_artifacts: data.sandbox_artifacts || [],
        fetched_at: data.fetched_at || new Date().toISOString(),
        is_live: true,
        cached: data.cached,
      };
    }
  } catch (err) {
    console.warn('API fetch failed:', err);
  }

  return {
    processed_logs: [],
    sources: [],
    chat: [],
    studio: [],
    notebook_raw_logs: [],
    sandbox_artifacts: [],
    fetched_at: new Date().toISOString(),
    is_live: false,
  };
}

/**
 * Fetch signed or direct media proxy URL for native in-browser media rendering/streaming
 */
export async function fetchSignedUrl(gcsUri: string): Promise<string> {
  if (!gcsUri) return '';
  if (gcsUri.startsWith('http://') || gcsUri.startsWith('https://')) {
    return gcsUri;
  }
  try {
    const headers = await getAuthHeaders();
    const res = await fetch(`/api/signed-url?gcs_uri=${encodeURIComponent(gcsUri)}`, {
      method: 'GET',
      headers,
    });
    if (res.ok) {
      const data = await res.json();
      return data.url || `/api/media?gcs_uri=${encodeURIComponent(gcsUri)}`;
    }
  } catch (err) {
    console.warn('Failed to fetch signed URL:', err);
  }
  return `/api/media?gcs_uri=${encodeURIComponent(gcsUri)}`;
}

export function getCleanExtension(urlOrUri?: string): string {
  if (!urlOrUri) return '';
  try {
    const parsed = new URL(urlOrUri, typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
    const gcsParam = parsed.searchParams.get('gcs_uri');
    const target = gcsParam || parsed.pathname;
    return target.split('?')[0].split('#')[0].toLowerCase();
  } catch {
    return urlOrUri.split('?')[0].split('#')[0].toLowerCase();
  }
}

export function getDirectMediaUrl(gcsUri?: string, tokenOverride?: string): string {
  if (!gcsUri) return '';
  if (gcsUri.startsWith('http://') || gcsUri.startsWith('https://')) {
    return gcsUri;
  }
  const cleanUri = gcsUri.startsWith('gs://') ? gcsUri : `gs://${gcsUri}`;
  const token = tokenOverride || getCachedAuthToken() || '';
  const base = `/api/media?gcs_uri=${encodeURIComponent(cleanUri)}`;
  return token ? `${base}&token=${encodeURIComponent(token)}` : base;
}

/**
 * Search BigQuery directly using inverted search indexes
 */
export async function searchBigQuery(
  query: string,
  userEmail = ''
): Promise<{ matched_sessions: string[]; matched_notebooks: string[]; total_matches: number }> {
  if (!query && !userEmail) {
    return { matched_sessions: [], matched_notebooks: [], total_matches: 0 };
  }
  try {
    const params = new URLSearchParams();
    if (query) params.append('q', query);
    if (userEmail) params.append('user_email', userEmail);
    const headers = await getAuthHeaders();
    const res = await fetch(`/api/search?${params.toString()}`, {
      method: 'GET',
      headers,
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn('BigQuery search failed:', err);
  }
  return { matched_sessions: [], matched_notebooks: [], total_matches: 0 };
}
