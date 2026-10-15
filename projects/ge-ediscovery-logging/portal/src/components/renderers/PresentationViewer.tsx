/**
 * PresentationViewer.tsx
 * ---------------------------------------------------------------------------
 * Gemini Enterprise Compliance Review Portal: Slide Deck Evidence Viewer.
 *
 * ARCHITECTURE
 *  • PDF decks are rendered through a native PDF.js <canvas> engine that paints
 *    EXACTLY ONE page (currentSlideIndex + 1) at devicePixelRatio into an
 *    off-screen buffer, then blits it: eliminating the continuous-scroll
 *    "stacked slides" behaviour of `<iframe src="…#page=N">` entirely.
 *  • HTML / Markdown / plain decks render as sanitized, CSS-scoped rich cards
 *    locked to a computed 16:9 stage box.
 *  • Thumbnails are rasterized once (280×160 JPEG) and served from a 2-tier
 *    cache: module-level Map (in-memory) → sessionStorage (`ge_thumb_${k}_${p}`).
 *
 * ZERO external dependencies beyond React + lucide-react + a lazy PDF.js CDN.
 * ---------------------------------------------------------------------------
 */

import React, {
  memo,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import type { ThemeConfig } from '../../types/theme';
import { getDirectMediaUrl, getCleanExtension } from '../../services/complianceApi';
import {
  ArrowLeft,
  ChevronLeft,
  ChevronRight,
  Download,
  ExternalLink,
  Grid,
  Layers,
  Loader2,
  Maximize2,
  Minimize2,
  Pause,
  Play,
  Presentation,
  RotateCcw,
  ShieldAlert,
  Timer,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';

/* ========================================================================== */
/* 1. PUBLIC TYPES                                                            */
/* ========================================================================== */

export interface ParsedSlide {
  index: number;
  id: string;
  title: string;
  htmlContent: string;
  plainText: string;
  notes?: string;
}

export interface PresentationViewerProps {
  title: string;
  gcsUri?: string;
  previewUrl?: string;
  webUrl?: string;
  mimeType?: string;
  rawHtml?: string;
  snippet?: string;
  sizeBytes?: number;
  sha256?: string;
  slideCount?: number;
  theme: ThemeConfig;
  className?: string;
  onClose?: () => void;
}

type ViewMode = 'SLIDE' | 'GRID';
type DeckKind = 'PDF' | 'HTML';
type LoadStatus = 'idle' | 'loading' | 'ready' | 'error';

interface Size {
  w: number;
  h: number;
}

interface Point {
  x: number;
  y: number;
}

/* ========================================================================== */
/* 2. CONSTANTS                                                               */
/* ========================================================================== */

const PDFJS_VERSION = '3.11.174';
const PDFJS_BASE = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${PDFJS_VERSION}`;

const THUMB_W = 280;
const THUMB_H = 160;
const THUMB_QUALITY = 0.72;
const THUMB_START_DELAY_MS = 220;

const MAX_DPR = 2.5;
const MIN_ZOOM = 1;
const MAX_ZOOM = 5;
const ZOOM_STEP = 0.25;
const ZOOM_COMMIT_DELAY_MS = 130;

const AUTOPLAY_INTERVALS = [3000, 5000, 10000] as const;
type AutoplayInterval = (typeof AUTOPLAY_INTERVALS)[number];

const ZERO_POINT: Point = { x: 0, y: 0 };

/* ========================================================================== */
/* 3. MINIMAL PDF.JS TYPE SHIMS (avoids pulling @types/pdfjs-dist)            */
/* ========================================================================== */

interface PdfViewport {
  width: number;
  height: number;
}

interface PdfRenderTask {
  promise: Promise<void>;
  cancel: () => void;
}

interface PdfTextItem {
  str?: string;
}

interface PdfPageProxy {
  getViewport(params: { scale: number; rotation?: number }): PdfViewport;
  render(params: {
    canvasContext: CanvasRenderingContext2D;
    viewport: PdfViewport;
    intent?: string;
  }): PdfRenderTask;
  getTextContent(): Promise<{ items: PdfTextItem[] }>;
  cleanup(): void;
}

interface PdfDocumentProxy {
  numPages: number;
  getPage(pageNumber: number): Promise<PdfPageProxy>;
  destroy(): Promise<void>;
}

interface PdfJsLib {
  GlobalWorkerOptions: { workerSrc: string };
  getDocument(src: Record<string, unknown>): { promise: Promise<PdfDocumentProxy> };
}

/** Singleton CDN loader: one <script>, one promise, for the whole app. */
let pdfJsPromise: Promise<PdfJsLib> | null = null;

function loadPdfJs(): Promise<PdfJsLib> {
  if (typeof window === 'undefined') {
    return Promise.reject(new Error('PDF.js requires a browser environment'));
  }
  const scope = window as Window & { pdfjsLib?: PdfJsLib };

  const configure = (lib: PdfJsLib): PdfJsLib => {
    if (!lib.GlobalWorkerOptions.workerSrc) {
      lib.GlobalWorkerOptions.workerSrc = `${PDFJS_BASE}/pdf.worker.min.js`;
    }
    return lib;
  };

  if (scope.pdfjsLib) return Promise.resolve(configure(scope.pdfjsLib));
  if (pdfJsPromise) return pdfJsPromise;

  pdfJsPromise = new Promise<PdfJsLib>((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>('script[data-pdfjs-loader="true"]');
    const script = existing ?? document.createElement('script');

    const onLoad = (): void => {
      const lib = (window as Window & { pdfjsLib?: PdfJsLib }).pdfjsLib;
      if (lib) resolve(configure(lib));
      else reject(new Error('PDF.js global object unavailable after load'));
    };
    const onError = (): void => {
      pdfJsPromise = null;
      reject(new Error('Unable to load the PDF rendering engine'));
    };

    script.addEventListener('load', onLoad, { once: true });
    script.addEventListener('error', onError, { once: true });

    if (!existing) {
      script.src = `${PDFJS_BASE}/pdf.min.js`;
      script.async = true;
      script.dataset.pdfjsLoader = 'true';
      document.head.appendChild(script);
    }
  });

  return pdfJsPromise;
}

/* ========================================================================== */
/* 4. UTILITIES: CACHE, HASHING, SANITIZATION, HOOKS                         */
/* ========================================================================== */

/** Tier-1 cache: survives remounts within the SPA session. */
const memThumbCache = new Map<string, string>();
let sessionWritable = true;

const thumbKey = (key: string, page: number): string => `ge_thumb_${key}_${page}`;
const titleKey = (key: string, page: number): string => `ge_title_${key}_${page}`;

function cacheRead(storageKey: string): string | null {
  const hit = memThumbCache.get(storageKey);
  if (hit !== undefined) return hit;
  try {
    const value = window.sessionStorage.getItem(storageKey);
    if (value) {
      memThumbCache.set(storageKey, value);
      return value;
    }
  } catch {
    /* storage disabled: memory tier only */
  }
  return null;
}

function cacheWrite(storageKey: string, value: string): void {
  memThumbCache.set(storageKey, value);
  if (!sessionWritable) return;
  try {
    window.sessionStorage.setItem(storageKey, value);
  } catch {
    sessionWritable = false; // quota exceeded → degrade to memory-only silently
  }
}

/** Stable, collision-resistant-enough key for anonymous URLs (FNV-1a 32). */
function fnv1a(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(36);
}

const clamp = (value: number, min: number, max: number): number =>
  value < min ? min : value > max ? max : value;

const formatBytes = (bytes?: number): string => {
  if (!bytes || bytes <= 0) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const yieldToBrowser = (): Promise<void> =>
  new Promise((resolve) => {
    const ric = (window as Window & { requestIdleCallback?: (cb: () => void) => number })
      .requestIdleCallback;
    if (ric) ric(() => resolve());
    else window.setTimeout(resolve, 0);
  });

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => window.setTimeout(resolve, ms));

/** Always-fresh callback identity-stable across renders (avoids effect churn). */
function useEventCallback<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R {
  const ref = useRef(fn);
  useLayoutEffect(() => {
    ref.current = fn;
  });
  return useCallback((...args: A) => ref.current(...args), []);
}

/** ResizeObserver-backed element measurement, integer-quantized to stop loops. */
function useElementSize<T extends HTMLElement>(): [React.RefObject<T>, Size] {
  const ref = useRef<T>(null);
  const [size, setSize] = useState<Size>({ w: 0, h: 0 });

  useLayoutEffect(() => {
    const node = ref.current;
    if (!node) return;

    const observer = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (!rect) return;
      const next = { w: Math.round(rect.width), h: Math.round(rect.height) };
      setSize((prev) => (prev.w === next.w && prev.h === next.h ? prev : next));
    });

    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  return [ref, size];
}

const BLOCKED_TAGS = new Set([
  'SCRIPT', 'IFRAME', 'OBJECT', 'EMBED', 'LINK', 'META', 'BASE', 'FORM', 'INPUT', 'BUTTON',
  'SVG', 'FOREIGNOBJECT', 'MATH', 'STYLE', 'TEMPLATE',
]);

/** Strips executable vectors from untrusted deck markup before injection. */
function sanitizeHtml(html: string): string {
  if (!html) return '';
  const doc = new DOMParser().parseFromString(`<div id="ge-root">${html}</div>`, 'text/html');
  const root = doc.getElementById('ge-root');
  if (!root) return '';

  root.querySelectorAll('*').forEach((el) => {
    const tag = el.tagName.toUpperCase();
    if (BLOCKED_TAGS.has(tag)) {
      el.remove();
      return;
    }
    Array.from(el.attributes).forEach(({ name, value }) => {
      const attr = name.toLowerCase();
      const isUrlAttr =
        attr === 'href' ||
        attr === 'src' ||
        attr === 'xlink:href' ||
        attr === 'action' ||
        attr === 'formaction' ||
        attr === 'data' ||
        attr === 'poster';
      if (attr.startsWith('on') || attr === 'srcdoc' || attr === 'formaction' || attr === 'style') {
        el.removeAttribute(name);
        return;
      }
      if (isUrlAttr) {
        // Strip all ASCII control characters and whitespace before scheme validation
        const normalized = value.replace(/[\u0000-\u0020]+/g, '');
        const isSafeHttp = /^https?:\/\//i.test(normalized);
        const isSafeMailto = attr === 'href' && /^mailto:/i.test(normalized);
        const isSafeRelative = normalized.startsWith('/api/media?') || normalized.startsWith('#');
        const isSafeDataImg =
          tag === 'IMG' &&
          attr === 'src' &&
          /^data:image\/(png|jpeg|jpg|gif|webp);base64,[a-z0-9+/=]+$/i.test(normalized);
        if (!isSafeHttp && !isSafeMailto && !isSafeRelative && !isSafeDataImg) {
          el.removeAttribute(name);
        }
      }
    });
  });

  return root.innerHTML;
}

/** Prefixes every selector with a scope class so deck CSS cannot leak globally. */
function scopeCss(css: string, scope: string): string {
  if (!css.trim()) return '';
  return css
    .replace(/<\/style/gi, '')
    .replace(/@import[^;]+;/g, '')
    .replace(/(^|\}|\{)([^{}@]+)\{/g, (_match, boundary: string, selectorList: string) => {
      const scoped = selectorList
        .split(',')
        .map((raw) => {
          const sel = raw.trim();
          if (!sel) return sel;
          if (/^(from|to|\d+(\.\d+)?%)$/i.test(sel)) return sel; // @keyframes stops
          if (/^(html|body|:root)$/i.test(sel)) return scope;
          return `${scope} ${sel}`;
        })
        .join(', ');
      return `${boundary}${scoped}{`;
    });
}

/* ========================================================================== */
/* 5. HTML DECK PARSER (public API: preserved)                               */
/* ========================================================================== */

export function parseHtmlIntoSlides(htmlText: string): {
  slides: ParsedSlide[];
  styles: string;
  documentTitle: string;
} {
  if (!htmlText || !htmlText.trim()) return { slides: [], styles: '', documentTitle: '' };

  const doc = new DOMParser().parseFromString(htmlText, 'text/html');
  const styles = Array.from(doc.querySelectorAll('style'))
    .map((node) => node.innerHTML)
    .join('\n');
  const documentTitle = doc.title || '';

  const SELECTOR_TIERS = [
    '.reveal .slides > section, .slides > section',
    'body > section, main > section, section.slide, section[data-slide]',
    'section',
    '.slide, .slide-container > div, .page, article.slide, [data-slide], .swiper-slide, .carousel-item',
  ];

  let nodes: Element[] = [];
  for (const selector of SELECTOR_TIERS) {
    nodes = Array.from(doc.querySelectorAll(selector));
    if (nodes.length > 0) break;
  }

  if (nodes.length === 0) {
    const children = Array.from(doc.body.children).filter(
      (el) => !['STYLE', 'SCRIPT', 'NOSCRIPT', 'LINK', 'META'].includes(el.tagName),
    );
    if (children.length > 1) nodes = children;
  }
  if (nodes.length === 0 && doc.body.innerHTML.trim()) nodes = [doc.body];

  const slides = nodes.map<ParsedSlide>((node, index) => {
    const clone = node.cloneNode(true) as HTMLElement;

    const noteEl = clone.querySelector('aside.notes, .notes, .speaker-notes, [data-speaker-notes]');
    const notes = noteEl?.textContent?.trim() || undefined;
    noteEl?.remove();

    const heading = clone.querySelector('h1, h2, h3, h4, .slide-title, [data-title], header');
    let title = heading?.textContent?.trim() ?? '';
    if (!title) {
      const firstLine = clone.textContent?.trim().split('\n')[0] ?? '';
      title = firstLine.length > 45 ? `${firstLine.slice(0, 45)}…` : firstLine || `Slide ${index + 1}`;
    }

    return {
      index,
      id: node.id || `slide-${index + 1}`,
      title,
      htmlContent: clone.innerHTML || clone.outerHTML,
      plainText: clone.textContent?.trim() ?? '',
      notes,
    };
  });

  return { slides, styles, documentTitle };
}

/* ========================================================================== */
/* 6. DATA HOOKS: PDF DOCUMENT, THUMBNAILS, AUTOPLAY                         */
/* ========================================================================== */

interface PdfDocState {
  doc: PdfDocumentProxy | null;
  numPages: number;
  status: LoadStatus;
  error: string | null;
}

/** Fetches the PDF once as an ArrayBuffer and owns the PDFDocumentProxy lifetime. */
function usePdfDocument(url: string | undefined, enabled: boolean): PdfDocState {
  const [state, setState] = useState<PdfDocState>({
    doc: null,
    numPages: 0,
    status: 'idle',
    error: null,
  });

  useEffect(() => {
    if (!enabled || !url) {
      setState({ doc: null, numPages: 0, status: 'idle', error: null });
      return;
    }

    let cancelled = false;
    let doc: PdfDocumentProxy | null = null;
    const controller = new AbortController();

    setState({ doc: null, numPages: 0, status: 'loading', error: null });

    void (async () => {
      try {
        const [pdfjs, response] = await Promise.all([
          loadPdfJs(),
          fetch(url, { signal: controller.signal }),
        ]);
        if (!response.ok) throw new Error(`Document fetch failed (HTTP ${response.status})`);

        const data = await response.arrayBuffer();
        if (cancelled) return;

        doc = await pdfjs.getDocument({
          data,
          useWorkerFetch: false,
          isEvalSupported: false,
          disableAutoFetch: true,
          disableStream: true,
        }).promise;

        if (cancelled) {
          void doc.destroy().catch(() => undefined);
          return;
        }
        setState({ doc, numPages: doc.numPages, status: 'ready', error: null });
      } catch (error) {
        if (cancelled || (error as Error)?.name === 'AbortError') return;
        setState({
          doc: null,
          numPages: 0,
          status: 'error',
          error: (error as Error)?.message ?? 'Unable to render this document inline',
        });
      }
    })();

    return () => {
      cancelled = true;
      controller.abort();
      void doc?.destroy().catch(() => undefined);
    };
  }, [url, enabled]);

  return state;
}

interface ThumbnailState {
  thumbs: Record<number, string>;
  titles: Record<number, string>;
  pending: number;
}

/** Rasterizes 16:9-ish 280×160 JPEG previews with 2-tier caching + text titles. */
function usePdfThumbnails(
  doc: PdfDocumentProxy | null,
  numPages: number,
  cacheKey: string,
): ThumbnailState {
  const [thumbs, setThumbs] = useState<Record<number, string>>({});
  const [titles, setTitles] = useState<Record<number, string>>({});
  const [pending, setPending] = useState(0);

  // Tier-1/2 hydration: synchronous, no flicker on remount.
  useEffect(() => {
    if (!cacheKey || numPages <= 0) return;
    const seededThumbs: Record<number, string> = {};
    const seededTitles: Record<number, string> = {};

    for (let page = 1; page <= numPages; page += 1) {
      const thumb = cacheRead(thumbKey(cacheKey, page));
      if (thumb) seededThumbs[page] = thumb;
      const title = cacheRead(titleKey(cacheKey, page));
      if (title) seededTitles[page] = title;
    }

    setThumbs(seededThumbs);
    setTitles(seededTitles);
    setPending(numPages - Object.keys(seededThumbs).length);
  }, [cacheKey, numPages]);

  // Rasterization pass for cache misses only.
  useEffect(() => {
    if (!doc || numPages <= 0 || !cacheKey) return;

    let cancelled = false;
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { alpha: false });

    void (async () => {
      await delay(THUMB_START_DELAY_MS); // let the main stage paint first
      if (cancelled || !ctx) return;

      for (let page = 1; page <= numPages; page += 1) {
        if (cancelled) break;
        if (cacheRead(thumbKey(cacheKey, page))) continue;

        try {
          const pdfPage = await doc.getPage(page);
          if (cancelled) break;

          const base = pdfPage.getViewport({ scale: 1 });
          const scale = Math.min(THUMB_W / base.width, THUMB_H / base.height) || 0.25;
          const viewport = pdfPage.getViewport({ scale });

          canvas.width = Math.max(1, Math.round(viewport.width));
          canvas.height = Math.max(1, Math.round(viewport.height));
          ctx.fillStyle = '#ffffff';
          ctx.fillRect(0, 0, canvas.width, canvas.height);

          await pdfPage.render({ canvasContext: ctx, viewport, intent: 'display' }).promise;
          if (cancelled) break;

          const dataUrl = canvas.toDataURL('image/jpeg', THUMB_QUALITY);
          cacheWrite(thumbKey(cacheKey, page), dataUrl);
          setThumbs((prev) => ({ ...prev, [page]: dataUrl }));

          const text = await pdfPage.getTextContent();
          const label = text.items
            .map((item) => item.str ?? '')
            .join(' ')
            .replace(/\s+/g, ' ')
            .trim()
            .slice(0, 54);
          if (label) {
            cacheWrite(titleKey(cacheKey, page), label);
            if (!cancelled) setTitles((prev) => ({ ...prev, [page]: label }));
          }

          pdfPage.cleanup();
        } catch {
          /* skip unrenderable page, keep the pipeline alive */
        }

        if (!cancelled) setPending((prev) => Math.max(0, prev - 1));
        await yieldToBrowser();
      }
      if (!cancelled) setPending(0);
    })();

    return () => {
      cancelled = true;
      canvas.width = 0;
      canvas.height = 0; // release GPU/heap backing store
    };
  }, [doc, numPages, cacheKey]);

  return { thumbs, titles, pending };
}

/** rAF-driven autoplay: progress writes straight to the DOM (zero re-renders). */
function useAutoplay(
  enabled: boolean,
  intervalMs: number,
  resetToken: number,
  barRef: React.RefObject<HTMLDivElement>,
  onAdvance: () => void,
): void {
  const advance = useEventCallback(onAdvance);

  useEffect(() => {
    const bar = barRef.current;
    if (!enabled) {
      if (bar) bar.style.transform = 'scaleX(0)';
      return;
    }

    let frame = 0;
    let start = performance.now();

    const tick = (now: number): void => {
      const progress = Math.min(1, (now - start) / intervalMs);
      if (barRef.current) barRef.current.style.transform = `scaleX(${progress})`;
      if (progress >= 1) {
        start = now;
        advance();
      }
      frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(frame);
      if (barRef.current) barRef.current.style.transform = 'scaleX(0)';
    };
  }, [enabled, intervalMs, resetToken, advance, barRef]);
}

/* ========================================================================== */
/* 7. PRESENTATION CANVAS: SINGLE-PAGE PDF.JS ENGINE                         */
/* ========================================================================== */

interface PdfSlideCanvasProps {
  doc: PdfDocumentProxy;
  pageNumber: number;
  zoom: number;
  onZoomChange: (zoom: number) => void;
}

const PdfSlideCanvas = memo<PdfSlideCanvasProps>(function PdfSlideCanvas({
  doc,
  pageNumber,
  zoom,
  onZoomChange,
}) {
  const [stageRef, stage] = useElementSize<HTMLDivElement>();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const taskRef = useRef<PdfRenderTask | null>(null);

  const [renderZoom, setRenderZoom] = useState(zoom);      // zoom the raster targets
  const [committedZoom, setCommittedZoom] = useState(zoom); // zoom currently painted
  const [fitSize, setFitSize] = useState<Size>({ w: 0, h: 0 }); // CSS px at zoom = 1
  const [offset, setOffset] = useState<Point>(ZERO_POINT);
  const [painted, setPainted] = useState(false);
  const [failed, setFailed] = useState(false);
  const [syncedPage, setSyncedPage] = useState(pageNumber);

  // Render-phase derived-state sync: a page change re-bases zoom instantly,
  // preventing a wasted raster pass at the previous zoom level.
  if (syncedPage !== pageNumber) {
    setSyncedPage(pageNumber);
    setRenderZoom(zoom);
    setCommittedZoom(zoom);
    setOffset(ZERO_POINT);
    setPainted(false);
  }

  // Debounced high-resolution re-raster (pinch/zoom stays at 60fps meanwhile).
  useEffect(() => {
    if (Math.abs(zoom - renderZoom) < 0.001) return;
    const timer = window.setTimeout(() => setRenderZoom(zoom), ZOOM_COMMIT_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [zoom, renderZoom]);

  /* ---- Core single-page raster: off-screen buffer → blit (no white flash) -- */
  useEffect(() => {
    if (stage.w < 8 || stage.h < 8) return;

    let cancelled = false;
    setFailed(false);

    void (async () => {
      let buffer: HTMLCanvasElement | null = null;
      try {
        const page = await doc.getPage(pageNumber);
        if (cancelled) return;

        const base = page.getViewport({ scale: 1 });
        const fitScale = Math.min(stage.w / base.width, stage.h / base.height);
        const cssScale = fitScale * renderZoom;
        const dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR);
        const viewport = page.getViewport({ scale: cssScale * dpr });

        buffer = document.createElement('canvas');
        buffer.width = Math.max(1, Math.floor(viewport.width));
        buffer.height = Math.max(1, Math.floor(viewport.height));
        const bufferCtx = buffer.getContext('2d', { alpha: false });
        if (!bufferCtx) throw new Error('Canvas 2D context unavailable');

        bufferCtx.fillStyle = '#ffffff';
        bufferCtx.fillRect(0, 0, buffer.width, buffer.height);

        const task = page.render({ canvasContext: bufferCtx, viewport, intent: 'display' });
        taskRef.current = task;
        await task.promise;
        taskRef.current = null;
        if (cancelled) return;

        const canvas = canvasRef.current;
        if (!canvas) return;
        canvas.width = buffer.width;
        canvas.height = buffer.height;
        canvas.style.width = `${Math.round(base.width * cssScale)}px`;
        canvas.style.height = `${Math.round(base.height * cssScale)}px`;
        canvas.getContext('2d', { alpha: false })?.drawImage(buffer, 0, 0);

        page.cleanup();
        setFitSize({
          w: Math.round(base.width * fitScale),
          h: Math.round(base.height * fitScale),
        });
        setCommittedZoom(renderZoom);
        setPainted(true);
      } catch (error) {
        if (cancelled || (error as Error)?.name === 'RenderingCancelledException') return;
        setFailed(true);
        setPainted(true);
      } finally {
        if (buffer) {
          buffer.width = 0;
          buffer.height = 0;
        }
      }
    })();

    return () => {
      cancelled = true;
      try {
        taskRef.current?.cancel();
      } catch {
        /* already settled */
      }
      taskRef.current = null;
    };
  }, [doc, pageNumber, stage.w, stage.h, renderZoom]);

  // Free the visible canvas backing store on unmount.
  useEffect(
    () => () => {
      const canvas = canvasRef.current;
      if (canvas) {
        canvas.width = 0;
        canvas.height = 0;
      }
    },
    [],
  );

  /* ---- Pan clamping ------------------------------------------------------ */
  const clampOffset = useCallback(
    (next: Point, level: number): Point => {
      const maxX = Math.max(0, (fitSize.w * level - stage.w) / 2);
      const maxY = Math.max(0, (fitSize.h * level - stage.h) / 2);
      return { x: clamp(next.x, -maxX, maxX), y: clamp(next.y, -maxY, maxY) };
    },
    [fitSize.w, fitSize.h, stage.w, stage.h],
  );

  useEffect(() => {
    setOffset((prev) => {
      const next = clampOffset(prev, zoom);
      return next.x === prev.x && next.y === prev.y ? prev : next;
    });
  }, [zoom, clampOffset]);

  /* ---- Pointer gestures: pinch-zoom + drag-pan --------------------------- */
  const pointers = useRef(new Map<number, Point>());
  const pinch = useRef<{ distance: number; zoom: number } | null>(null);
  const drag = useRef<{ origin: Point; offset: Point } | null>(null);
  const [grabbing, setGrabbing] = useState(false);

  const pinchDistance = (): number => {
    const [a, b] = Array.from(pointers.current.values());
    return a && b ? Math.hypot(a.x - b.x, a.y - b.y) : 0;
  };

  const handlePointerDown = (event: React.PointerEvent<HTMLDivElement>): void => {
    (event.target as Element).setPointerCapture?.(event.pointerId);
    pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY });

    if (pointers.current.size === 2) {
      pinch.current = { distance: pinchDistance(), zoom };
      drag.current = null;
    } else if (zoom > 1) {
      drag.current = { origin: { x: event.clientX, y: event.clientY }, offset };
      setGrabbing(true);
    }
  };

  const handlePointerMove = (event: React.PointerEvent<HTMLDivElement>): void => {
    if (!pointers.current.has(event.pointerId)) return;
    pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY });

    if (pinch.current && pointers.current.size === 2) {
      const distance = pinchDistance();
      if (pinch.current.distance > 0 && distance > 0) {
        onZoomChange(
          clamp((pinch.current.zoom * distance) / pinch.current.distance, MIN_ZOOM, MAX_ZOOM),
        );
      }
      return;
    }

    if (drag.current && zoom > 1) {
      const { origin, offset: base } = drag.current;
      setOffset(
        clampOffset(
          { x: base.x + (event.clientX - origin.x), y: base.y + (event.clientY - origin.y) },
          zoom,
        ),
      );
    }
  };

  const endPointer = (event: React.PointerEvent<HTMLDivElement>): void => {
    pointers.current.delete(event.pointerId);
    if (pointers.current.size < 2) pinch.current = null;
    if (pointers.current.size === 0) {
      drag.current = null;
      setGrabbing(false);
    }
  };

  // Non-passive wheel listener so ctrl/⌘ + wheel (trackpad pinch) can be captured.
  useEffect(() => {
    const node = stageRef.current;
    if (!node) return;

    const onWheel = (event: WheelEvent): void => {
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        onZoomChange(clamp(zoom * Math.exp(-event.deltaY * 0.0022), MIN_ZOOM, MAX_ZOOM));
      } else if (zoom > 1) {
        event.preventDefault();
        setOffset((prev) => clampOffset({ x: prev.x - event.deltaX, y: prev.y - event.deltaY }, zoom));
      }
    };

    node.addEventListener('wheel', onWheel, { passive: false });
    return () => node.removeEventListener('wheel', onWheel);
  }, [zoom, onZoomChange, clampOffset, stageRef]);

  const previewScale = committedZoom > 0 ? zoom / committedZoom : 1;

  return (
    <div
      ref={stageRef}
      className="relative flex h-full w-full items-center justify-center overflow-hidden"
      style={{ touchAction: 'none', cursor: zoom > 1 ? (grabbing ? 'grabbing' : 'grab') : 'default' }}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={endPointer}
      onPointerCancel={endPointer}
      onDoubleClick={() => onZoomChange(zoom > 1 ? 1 : 2)}
    >
      <div
        className="will-change-transform"
        style={{
          transform: `translate3d(${offset.x}px, ${offset.y}px, 0) scale(${previewScale})`,
          transition: grabbing || pinch.current ? 'none' : 'transform 140ms cubic-bezier(0.16,1,0.3,1)',
        }}
      >
        <canvas
          ref={canvasRef}
          aria-label={`Slide ${pageNumber}`}
          className="block rounded-lg bg-white shadow-2xl shadow-black/60 ring-1 ring-white/10"
          style={{
            opacity: painted ? 1 : 0.35,
            transition: 'opacity 180ms ease-out',
          }}
        />
      </div>

      {!painted && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <Loader2 className="h-7 w-7 animate-spin text-orange-500" />
        </div>
      )}

      {failed && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-slate-950/85 text-xs font-mono text-rose-300">
          <ShieldAlert className="h-6 w-6" />
          <span>Page {pageNumber} could not be rasterized</span>
        </div>
      )}
    </div>
  );
});

/* ========================================================================== */
/* 8. HTML / MARKDOWN RICH CARD STAGE                                         */
/* ========================================================================== */

interface HtmlSlideStageProps {
  slide: ParsedSlide;
  scopeId: string;
  scopedCss: string;
  index: number;
  zoom: number;
}

const HtmlSlideStage = memo<HtmlSlideStageProps>(function HtmlSlideStage({
  slide,
  scopeId,
  scopedCss,
  index,
  zoom,
}) {
  const [stageRef, stage] = useElementSize<HTMLDivElement>();
  const html = useMemo(() => sanitizeHtml(slide.htmlContent), [slide.htmlContent]);

  const box = useMemo<Size>(() => {
    if (stage.w < 8 || stage.h < 8) return { w: 0, h: 0 };
    const width = Math.min(stage.w, (stage.h * 16) / 9);
    return { w: Math.round(width), h: Math.round((width * 9) / 16) };
  }, [stage.w, stage.h]);

  return (
    <div ref={stageRef} className="relative flex h-full w-full items-center justify-center overflow-hidden">
      <style>{scopedCss}</style>
      <article
        key={slide.id}
        className="ge-fade overflow-hidden rounded-xl border border-slate-700/70 bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 shadow-2xl shadow-black/60"
        style={{
          width: box.w || undefined,
          height: box.h || undefined,
          transform: `scale(${zoom})`,
          transition: 'transform 140ms cubic-bezier(0.16,1,0.3,1)',
        }}
      >
        <header className="flex items-center justify-between border-b border-slate-800/80 px-5 py-2.5">
          <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-orange-400">
            Slide #{index + 1}
          </span>
          <h2 className="max-w-[70%] truncate text-sm font-bold text-sky-300">{slide.title}</h2>
        </header>
        <div className={`${scopeId} ge-scroll h-[calc(100%-2.75rem)] overflow-y-auto px-6 py-5 text-slate-200`}>
          <div dangerouslySetInnerHTML={{ __html: html }} />
        </div>
      </article>
    </div>
  );
});

/* ========================================================================== */
/* 9. THUMBNAIL RAIL + GRID                                                   */
/* ========================================================================== */

interface ThumbCardProps {
  index: number;
  label: string;
  src?: string;
  active: boolean;
  variant: 'rail' | 'grid';
  onSelect: (index: number) => void;
}

const ThumbCard = memo<ThumbCardProps>(function ThumbCard({
  index,
  label,
  src,
  active,
  variant,
  onSelect,
}) {
  const ref = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (active && variant === 'rail') {
      ref.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }, [active, variant]);

  return (
    <button
      ref={ref}
      type="button"
      aria-current={active}
      onClick={() => onSelect(index)}
      title={`Slide ${index + 1}${label ? `: ${label}` : ''}`}
      className={`group flex w-full shrink-0 flex-col overflow-hidden rounded-xl border text-left transition-all duration-150 ${
        active
          ? 'border-orange-500 bg-orange-950/40 shadow-lg shadow-orange-900/30 ring-2 ring-orange-500/60'
          : 'border-slate-800/80 bg-slate-900/60 hover:border-slate-600 hover:bg-slate-900 hover:shadow-lg'
      }`}
    >
      <div className="relative aspect-video min-h-[90px] w-full overflow-hidden border-b border-slate-800/60 bg-slate-950">
        {src ? (
          <img
            src={src}
            alt={`Slide ${index + 1} preview`}
            loading="lazy"
            decoding="async"
            className="h-full w-full object-contain transition-transform duration-200 group-hover:scale-[1.06]"
          />
        ) : (
          <div className="ge-skeleton flex h-full w-full flex-col items-center justify-center gap-1 text-slate-600">
            <Presentation className="h-5 w-5 opacity-40" />
            <span className="font-mono text-[9px]">Rendering…</span>
          </div>
        )}
        <span
          className={`absolute left-1.5 top-1.5 rounded px-1.5 py-0.5 font-mono text-[9px] font-bold shadow-md ${
            active ? 'bg-orange-500 text-slate-950' : 'border border-slate-700/60 bg-slate-950/90 text-slate-300'
          }`}
        >
          #{index + 1}
        </span>
      </div>
      <div className="px-2 py-1.5">
        <span
          className={`block truncate text-[10px] font-medium ${
            active ? 'font-semibold text-orange-300' : 'text-slate-400 group-hover:text-slate-200'
          }`}
        >
          {label || `Slide ${index + 1}`}
        </span>
      </div>
    </button>
  );
});

/* ========================================================================== */
/* 10. TOOLBAR PRIMITIVE                                                      */
/* ========================================================================== */

interface ToolbarButtonProps {
  icon: React.ReactNode;
  title: string;
  label?: string;
  active?: boolean;
  disabled?: boolean;
  tone?: 'default' | 'accent' | 'success';
  labelClass?: string;
  theme: ThemeConfig;
  onClick: () => void;
}

const ToolbarButton = memo<ToolbarButtonProps>(function ToolbarButton({
  icon,
  title,
  label,
  active = false,
  disabled = false,
  tone = 'default',
  labelClass = 'hidden md:inline',
  theme,
  onClick,
}) {
  const activeClass =
    tone === 'success'
      ? 'border-emerald-400 bg-emerald-500/20 text-emerald-700 dark:text-emerald-300'
      : theme.accentBtn;

  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      aria-pressed={active}
      disabled={disabled}
      onClick={onClick}
      className={`inline-flex cursor-pointer items-center gap-1 rounded-lg border p-1.5 text-[11px] font-semibold shadow-2xs transition-all duration-150 disabled:cursor-not-allowed disabled:opacity-40 ${
        active ? activeClass : `${theme.cardClass} ${theme.textSecondary} hover:${theme.textPrimary} hover:brightness-110`
      }`}
    >
      {icon}
      {label && <span className={labelClass}>{label}</span>}
    </button>
  );
});

/* ========================================================================== */
/* 11. MAIN COMPONENT                                                         */
/* ========================================================================== */

export const PresentationViewer: React.FC<PresentationViewerProps> = ({
  title,
  gcsUri,
  previewUrl,
  webUrl,
  mimeType,
  rawHtml,
  snippet,
  sizeBytes,
  sha256,
  slideCount: propSlideCount,
  theme,
  className = '',
  onClose,
}) => {
  /* ---- Source resolution ------------------------------------------------- */
  const directUrl = useMemo<string | undefined>(() => {
    if (previewUrl) return previewUrl;
    if (gcsUri) return getDirectMediaUrl(gcsUri);
    return webUrl;
  }, [previewUrl, gcsUri, webUrl]);

  const deckKind = useMemo<DeckKind>(() => {
    const cleanGcs = getCleanExtension(gcsUri);
    const cleanDirect = getCleanExtension(directUrl);
    const cleanWeb = getCleanExtension(webUrl);
    const cleanPreview = getCleanExtension(previewUrl);
    const cleanTitle = (title || '').toLowerCase();
    const cleanMime = (mimeType || '').toLowerCase();

    if (
      cleanMime.includes('pdf') ||
      cleanGcs.endsWith('.pdf') ||
      cleanDirect.endsWith('.pdf') ||
      cleanWeb.endsWith('.pdf') ||
      cleanPreview.endsWith('.pdf') ||
      cleanTitle.endsWith('.pdf') ||
      cleanGcs.includes('/pdf') ||
      cleanDirect.includes('/pdf')
    ) {
      return 'PDF';
    }
    return 'HTML';
  }, [title, gcsUri, directUrl, webUrl, previewUrl, mimeType]);

  const cacheKey = useMemo(
    () => (sha256 ? sha256.slice(0, 16) : fnv1a(directUrl ?? title)),
    [sha256, directUrl, title],
  );

  const scopeId = useMemo(() => `ge-deck-${cacheKey}`, [cacheKey]);

  /* ---- State ------------------------------------------------------------- */
  const [currentIndex, setCurrentIndex] = useState(0);
  const [parsedSlides, setParsedSlides] = useState<ParsedSlide[]>([]);
  const [docStyles, setDocStyles] = useState('');
  const [docTitle, setDocTitle] = useState(title);
  const [htmlStatus, setHtmlStatus] = useState<LoadStatus>('idle');

  const [viewMode, setViewMode] = useState<ViewMode>('SLIDE');
  const [showRail, setShowRail] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isPlaying, setIsPlaying] = useState(false);
  const [autoplayMs, setAutoplayMs] = useState<AutoplayInterval>(5000);
  const [zoom, setZoom] = useState(1);

  const containerRef = useRef<HTMLDivElement>(null);
  const autoplayBarRef = useRef<HTMLDivElement>(null);
  const focusedRef = useRef(false);

  /* ---- PDF pipeline ------------------------------------------------------ */
  const isPdf = deckKind === 'PDF';
  const { doc, numPages, status: pdfStatus, error: pdfError } = usePdfDocument(directUrl, isPdf);
  const { thumbs, titles, pending } = usePdfThumbnails(doc, numPages, cacheKey);

  /* ---- HTML pipeline ----------------------------------------------------- */
  useEffect(() => {
    if (isPdf) {
      setHtmlStatus('idle');
      return;
    }

    let cancelled = false;
    const controller = new AbortController();
    setHtmlStatus('loading');

    void (async () => {
      let source = rawHtml || snippet || '';

      if (!source && directUrl) {
        try {
          const response = await fetch(directUrl, { signal: controller.signal });
          if (response.ok) {
            const text = await response.text();
            if (/<(html|body|section|div|article)/i.test(text)) source = text;
          }
        } catch {
          /* CORS or network: fall through to placeholder deck */
        }
      }
      if (cancelled) return;

      if (source.trim()) {
        const { slides, styles, documentTitle } = parseHtmlIntoSlides(source);
        setParsedSlides(
          slides.length > 0
            ? slides
            : [
                {
                  index: 0,
                  id: 'slide-1',
                  title: title || 'Slide 1',
                  htmlContent: source,
                  plainText: source.replace(/<[^>]*>?/gm, ''),
                },
              ],
        );
        setDocStyles(styles);
        setDocTitle(documentTitle || title);
      } else {
        const count = Math.max(1, propSlideCount ?? 1);
        setParsedSlides(
          Array.from({ length: count }, (_, i) => ({
            index: i,
            id: `slide-${i + 1}`,
            title: `Slide ${i + 1}`,
            htmlContent:
              '<p class="text-sm leading-relaxed text-slate-300">Inline preview unavailable for this artifact. Open or download the original evidence file to review its contents.</p>',
            plainText: 'Preview unavailable',
          })),
        );
        setDocTitle(title);
      }
      setHtmlStatus('ready');
    })();

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [isPdf, rawHtml, snippet, directUrl, title, propSlideCount]);

  const scopedCss = useMemo(() => scopeCss(docStyles, `.${scopeId}`), [docStyles, scopeId]);

  /* ---- Unified deck model ------------------------------------------------ */
  const totalSlides = useMemo(() => {
    if (isPdf) return numPages > 0 ? numPages : Math.max(1, propSlideCount ?? 1);
    return Math.max(1, parsedSlides.length || propSlideCount || 1);
  }, [isPdf, numPages, parsedSlides.length, propSlideCount]);

  const labels = useMemo<string[]>(
    () =>
      Array.from({ length: totalSlides }, (_, i) =>
        isPdf ? titles[i + 1] || `Slide ${i + 1}` : parsedSlides[i]?.title || `Slide ${i + 1}`,
      ),
    [totalSlides, isPdf, titles, parsedSlides],
  );

  useEffect(() => {
    setCurrentIndex((prev) => clamp(prev, 0, totalSlides - 1));
  }, [totalSlides]);

  const status: LoadStatus = isPdf ? pdfStatus : htmlStatus;
  const errorMessage = isPdf ? pdfError : null;

  /* ---- Navigation -------------------------------------------------------- */
  const goToSlide = useCallback(
    (index: number) => {
      setCurrentIndex((prev) => {
        const next = clamp(index, 0, totalSlides - 1);
        if (next !== prev) setZoom(1);
        return next;
      });
    },
    [totalSlides],
  );

  const step = useCallback(
    (delta: number, wrap = false) => {
      setCurrentIndex((prev) => {
        const raw = prev + delta;
        const next = wrap ? (raw + totalSlides) % totalSlides : clamp(raw, 0, totalSlides - 1);
        if (next !== prev) setZoom(1);
        return next;
      });
    },
    [totalSlides],
  );

  const nextSlide = useCallback(() => step(1), [step]);
  const prevSlide = useCallback(() => step(-1), [step]);
  const advanceAutoplay = useCallback(() => step(1, true), [step]);

  useAutoplay(isPlaying && viewMode === 'SLIDE', autoplayMs, currentIndex, autoplayBarRef, advanceAutoplay);

  const cycleAutoplayInterval = useCallback(() => {
    setAutoplayMs((prev) => {
      const idx = AUTOPLAY_INTERVALS.indexOf(prev);
      return AUTOPLAY_INTERVALS[(idx + 1) % AUTOPLAY_INTERVALS.length];
    });
  }, []);

  /* ---- Fullscreen -------------------------------------------------------- */
  const toggleFullscreen = useCallback(() => {
    const node = containerRef.current;
    if (!node) return;
    if (document.fullscreenElement) void document.exitFullscreen().catch(() => undefined);
    else void node.requestFullscreen().catch(() => undefined);
  }, []);

  useEffect(() => {
    const onChange = (): void => setIsFullscreen(document.fullscreenElement === containerRef.current);
    document.addEventListener('fullscreenchange', onChange);
    return () => document.removeEventListener('fullscreenchange', onChange);
  }, []);

  /* ---- Keyboard ---------------------------------------------------------- */
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent): void => {
      const target = event.target as HTMLElement | null;
      if (target && (/^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName) || target.isContentEditable)) return;
      // Only claim keys when this viewer is focused, hovered, or presenting.
      if (!focusedRef.current && !isFullscreen) return;

      switch (event.key) {
        case 'ArrowRight':
        case 'ArrowDown':
        case 'PageDown':
        case ' ':
          event.preventDefault();
          nextSlide();
          break;
        case 'ArrowLeft':
        case 'ArrowUp':
        case 'PageUp':
          event.preventDefault();
          prevSlide();
          break;
        case 'Home':
          event.preventDefault();
          goToSlide(0);
          break;
        case 'End':
          event.preventDefault();
          goToSlide(totalSlides - 1);
          break;
        case 'Escape':
          if (viewMode === 'GRID') {
            event.preventDefault();
            setViewMode('SLIDE');
          } else if (document.fullscreenElement) {
            void document.exitFullscreen().catch(() => undefined);
          }
          break;
        default:
          if (event.ctrlKey || event.metaKey || event.altKey) return;
          if (event.key.toLowerCase() === 'f') {
            event.preventDefault();
            toggleFullscreen();
          } else if (event.key.toLowerCase() === 'g') {
            event.preventDefault();
            setViewMode((mode) => (mode === 'GRID' ? 'SLIDE' : 'GRID'));
          }
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [nextSlide, prevSlide, goToSlide, toggleFullscreen, totalSlides, viewMode, isFullscreen]);

  /* ---- Actions ----------------------------------------------------------- */
  const openInNewTab = useCallback(() => {
    if (directUrl) window.open(directUrl, '_blank', 'noopener,noreferrer');
  }, [directUrl]);

  const currentSlide = parsedSlides[currentIndex] ?? parsedSlides[0] ?? null;
  const railVisible = showRail && viewMode === 'SLIDE' && totalSlides > 1;

  /* ---- Render ------------------------------------------------------------ */
  return (
    <div
      ref={containerRef}
      tabIndex={-1}
      role="region"
      aria-label={`Presentation viewer: ${docTitle}`}
      onMouseEnter={() => {
        focusedRef.current = true;
      }}
      onMouseLeave={() => {
        focusedRef.current = false;
      }}
      onFocusCapture={() => {
        focusedRef.current = true;
      }}
      className={`flex select-none flex-col overflow-hidden rounded-2xl border shadow-lg outline-none transition-all duration-200 ${
        isFullscreen
          ? 'fixed inset-0 z-50 h-screen w-screen rounded-none bg-slate-950 text-white'
          : `h-[560px] w-full ${theme.cardClass}`
      } ${className}`}
    >
      <style>{`
        @keyframes geFade { from { opacity:0; transform:translateY(4px) } to { opacity:1; transform:none } }
        .ge-fade { animation: geFade .22s cubic-bezier(.16,1,.3,1) }
        @keyframes geShimmer { 0% { background-position:-200% 0 } 100% { background-position:200% 0 } }
        .ge-skeleton {
          background: linear-gradient(100deg,#0f172a 30%,#1e293b 50%,#0f172a 70%);
          background-size: 200% 100%;
          animation: geShimmer 1.4s linear infinite;
        }
        .ge-scroll::-webkit-scrollbar { width:6px; height:6px }
        .ge-scroll::-webkit-scrollbar-thumb { background:#334155; border-radius:9999px }
        .ge-scroll::-webkit-scrollbar-track { background:transparent }
      `}</style>

      {/* ================= TOOLBAR ================= */}
      <header
        className={`flex shrink-0 items-center justify-between gap-3 border-b px-4 py-2.5 ${theme.sidebarHeaderClass}`}
      >
        <div className="flex min-w-0 items-center gap-3">
          <div className="shrink-0 rounded-lg bg-orange-500/15 p-1.5 text-orange-600 dark:text-orange-400">
            <Presentation className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded bg-orange-500/20 px-2 py-0.5 font-mono text-[9px] font-bold uppercase tracking-wider text-orange-700 dark:text-orange-300">
                Slide Deck
              </span>
              <span
                className={`rounded-md border px-2.5 py-0.5 font-mono text-xs font-bold shadow-2xs ${theme.badgePill}`}
              >
                Slide {currentIndex + 1} of {totalSlides}
              </span>
              {isPlaying && (
                <span className="inline-flex animate-pulse items-center gap-1 font-mono text-[10px] text-emerald-600 dark:text-emerald-400">
                  <Play className="h-3 w-3 fill-current" />
                  Autoplay {autoplayMs / 1000}s
                </span>
              )}
              {pending > 0 && (
                <span className="inline-flex items-center gap-1 font-mono text-[10px] text-zinc-400">
                  <Loader2 className="h-2.5 w-2.5 animate-spin text-orange-400" />
                  Caching {pending}
                </span>
              )}
            </div>
            <h3 className={`${theme.headingFont} mt-0.5 max-w-sm truncate text-xs font-bold ${theme.textPrimary}`}>
              {docTitle}
            </h3>
          </div>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-1.5">
          <div className={`flex items-center rounded-lg border p-0.5 ${theme.quoteBox}`}>
            <button
              type="button"
              onClick={prevSlide}
              disabled={currentIndex === 0}
              title="Previous slide (← / ↑)"
              className={`flex cursor-pointer items-center gap-1 rounded-md p-1.5 text-[11px] font-semibold transition disabled:cursor-not-allowed disabled:opacity-40 ${theme.textPrimary}`}
            >
              <ChevronLeft className="h-4 w-4" />
              <span className="hidden sm:inline">Prev</span>
            </button>
            <span className="px-2 font-mono text-[11px] font-bold text-zinc-500 dark:text-zinc-400">
              {currentIndex + 1}/{totalSlides}
            </span>
            <button
              type="button"
              onClick={nextSlide}
              disabled={currentIndex >= totalSlides - 1}
              title="Next slide (→ / ↓ / Space)"
              className={`flex cursor-pointer items-center gap-1 rounded-md p-1.5 text-[11px] font-semibold transition disabled:cursor-not-allowed disabled:opacity-40 ${theme.textPrimary}`}
            >
              <span className="hidden sm:inline">Next</span>
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>

          <ToolbarButton
            theme={theme}
            icon={<Layers className="h-3.5 w-3.5" />}
            label="Slides"
            title="Toggle slide rail"
            active={showRail}
            onClick={() => setShowRail((value) => !value)}
          />
          <ToolbarButton
            theme={theme}
            icon={<Grid className="h-3.5 w-3.5" />}
            label={viewMode === 'GRID' ? 'Single' : 'Grid'}
            title="Toggle grid overview (G)"
            active={viewMode === 'GRID'}
            onClick={() => setViewMode((mode) => (mode === 'GRID' ? 'SLIDE' : 'GRID'))}
          />

          {isPdf && viewMode === 'SLIDE' && (
            <div className={`flex items-center rounded-lg border p-0.5 ${theme.quoteBox}`}>
              <button
                type="button"
                title="Zoom out"
                disabled={zoom <= MIN_ZOOM}
                onClick={() => setZoom((z) => clamp(z - ZOOM_STEP, MIN_ZOOM, MAX_ZOOM))}
                className={`cursor-pointer rounded-md p-1.5 transition disabled:opacity-40 ${theme.textPrimary}`}
              >
                <ZoomOut className="h-3.5 w-3.5" />
              </button>
              <span className="w-10 text-center font-mono text-[10px] font-bold text-zinc-500 dark:text-zinc-400">
                {Math.round(zoom * 100)}%
              </span>
              <button
                type="button"
                title="Zoom in"
                disabled={zoom >= MAX_ZOOM}
                onClick={() => setZoom((z) => clamp(z + ZOOM_STEP, MIN_ZOOM, MAX_ZOOM))}
                className={`cursor-pointer rounded-md p-1.5 transition disabled:opacity-40 ${theme.textPrimary}`}
              >
                <ZoomIn className="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                title="Reset to page fit"
                disabled={zoom === 1}
                onClick={() => setZoom(1)}
                className={`cursor-pointer rounded-md p-1.5 transition disabled:opacity-40 ${theme.textPrimary}`}
              >
                <RotateCcw className="h-3.5 w-3.5" />
              </button>
            </div>
          )}

          <ToolbarButton
            theme={theme}
            tone="success"
            icon={isPlaying ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
            title={isPlaying ? 'Pause slideshow' : 'Start slideshow'}
            active={isPlaying}
            onClick={() => setIsPlaying((value) => !value)}
          />
          <ToolbarButton
            theme={theme}
            icon={<Timer className="h-3.5 w-3.5" />}
            label={`${autoplayMs / 1000}s`}
            labelClass="inline"
            title="Cycle autoplay interval (3s / 5s / 10s)"
            onClick={cycleAutoplayInterval}
          />
          <ToolbarButton
            theme={theme}
            icon={isFullscreen ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
            title={isFullscreen ? 'Exit fullscreen (Esc)' : 'Fullscreen (F)'}
            onClick={toggleFullscreen}
          />

          {directUrl && (
            <>
              <a
                href={directUrl}
                download
                target="_blank"
                rel="noopener noreferrer"
                title="Download original file"
                className={`inline-flex cursor-pointer items-center gap-1 rounded-lg border p-1.5 text-[11px] font-semibold shadow-2xs transition ${theme.accentBtn}`}
              >
                <Download className="h-3.5 w-3.5" />
                <span className="hidden lg:inline">Download</span>
              </a>
              <ToolbarButton
                theme={theme}
                icon={<ExternalLink className="h-3.5 w-3.5" />}
                title="Open in new tab"
                onClick={openInNewTab}
              />
            </>
          )}

          {onClose && (
            <button
              type="button"
              onClick={onClose}
              title="Close presentation"
              className="ml-1 rounded-lg p-1.5 text-zinc-400 transition hover:bg-zinc-200 hover:text-zinc-600 dark:hover:bg-zinc-800"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </header>

      {/* ================= PROGRESS ================= */}
      <div className="shrink-0">
        <div className="h-1 w-full bg-slate-800">
          <div
            className="h-full bg-gradient-to-r from-orange-500 via-amber-500 to-sky-500 transition-[width] duration-300"
            style={{ width: `${((currentIndex + 1) / totalSlides) * 100}%` }}
          />
        </div>
        <div className="h-0.5 w-full overflow-hidden bg-transparent">
          <div
            ref={autoplayBarRef}
            className="h-full w-full origin-left bg-emerald-400/80"
            style={{ transform: 'scaleX(0)' }}
          />
        </div>
      </div>

      {/* ================= STAGE ================= */}
      <div className="relative flex min-h-0 min-w-0 flex-1 overflow-hidden bg-slate-950">
        {/* Thumbnail rail */}
        {railVisible && (
          <aside className="ge-scroll z-10 flex w-48 shrink-0 flex-col gap-2 overflow-y-auto border-r border-slate-800 bg-slate-950/95 p-2 sm:w-60">
            <div className="mb-0.5 flex items-center justify-between border-b border-slate-800/80 px-1.5 py-1 font-mono text-[10px]">
              <span className="font-bold uppercase tracking-wider text-orange-400">Slides ({totalSlides})</span>
              {pending > 0 && <Loader2 className="h-2.5 w-2.5 animate-spin text-orange-400" />}
            </div>
            {labels.map((label, index) => (
              <ThumbCard
                key={`rail-${index}`}
                index={index}
                label={label}
                src={thumbs[index + 1]}
                active={index === currentIndex}
                variant="rail"
                onSelect={goToSlide}
              />
            ))}
          </aside>
        )}

        {/* Viewport */}
        <div className="relative flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
          {status === 'loading' ? (
            <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center text-zinc-400">
              <Loader2 className="h-8 w-8 animate-spin text-orange-500" />
              <p className="font-mono text-xs">
                {isPdf ? 'Initializing PDF canvas engine…' : 'Parsing slide deck…'}
              </p>
            </div>
          ) : status === 'error' ? (
            <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
              <ShieldAlert className="h-8 w-8 text-rose-400" />
              <p className="font-mono text-xs text-rose-300">{errorMessage}</p>
              <p className="max-w-sm text-[11px] text-zinc-500">
                Inline rasterization was blocked (network or CORS policy). The original artifact remains
                available through the secured evidence link.
              </p>
              {directUrl && (
                <button
                  type="button"
                  onClick={openInNewTab}
                  className={`flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-semibold ${theme.accentBtn}`}
                >
                  <ExternalLink className="h-4 w-4" />
                  Open in external tab
                </button>
              )}
            </div>
          ) : viewMode === 'GRID' ? (
            <div className="ge-scroll grid flex-1 grid-cols-1 gap-4 overflow-y-auto bg-slate-900/90 p-6 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4">
              {labels.map((label, index) => (
                <ThumbCard
                  key={`grid-${index}`}
                  index={index}
                  label={label}
                  src={thumbs[index + 1]}
                  active={index === currentIndex}
                  variant="grid"
                  onSelect={(i) => {
                    goToSlide(i);
                    setViewMode('SLIDE');
                  }}
                />
              ))}
            </div>
          ) : (
            <div className="group/stage relative flex min-h-0 flex-1 flex-col overflow-hidden">
              <div className="relative flex min-h-0 flex-1 items-center justify-center overflow-hidden p-2 sm:p-4">
                {isPdf && doc ? (
                  <PdfSlideCanvas
                    doc={doc}
                    pageNumber={currentIndex + 1}
                    zoom={zoom}
                    onZoomChange={setZoom}
                  />
                ) : currentSlide ? (
                  <HtmlSlideStage
                    slide={currentSlide}
                    scopeId={scopeId}
                    scopedCss={scopedCss}
                    index={currentIndex}
                    zoom={zoom}
                  />
                ) : null}

                {totalSlides > 1 && (
                  <>
                    <button
                      type="button"
                      onClick={prevSlide}
                      disabled={currentIndex === 0}
                      title="Previous slide (←)"
                      className="absolute left-4 top-1/2 -translate-y-1/2 cursor-pointer rounded-full border border-slate-700 bg-slate-900/80 p-3 text-white opacity-0 shadow-xl backdrop-blur-md transition-all hover:scale-110 hover:bg-slate-800 group-hover/stage:opacity-100 disabled:pointer-events-none disabled:!opacity-0"
                    >
                      <ChevronLeft className="h-5 w-5" />
                    </button>
                    <button
                      type="button"
                      onClick={nextSlide}
                      disabled={currentIndex >= totalSlides - 1}
                      title="Next slide (→)"
                      className="absolute right-4 top-1/2 -translate-y-1/2 cursor-pointer rounded-full border border-slate-700 bg-slate-900/80 p-3 text-white opacity-0 shadow-xl backdrop-blur-md transition-all hover:scale-110 hover:bg-slate-800 group-hover/stage:opacity-100 disabled:pointer-events-none disabled:!opacity-0"
                    >
                      <ChevronRight className="h-5 w-5" />
                    </button>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ================= FOOTER ================= */}
      <footer className="flex shrink-0 items-center justify-between border-t border-slate-800 bg-slate-950 px-4 py-1.5 font-mono text-[10px] text-zinc-400">
        <div className="flex items-center gap-2">
          <span>
            <kbd className="rounded bg-slate-800 px-1 py-0.5 text-zinc-300">←</kbd>{' '}
            <kbd className="rounded bg-slate-800 px-1 py-0.5 text-zinc-300">→</kbd> navigate
          </span>
          <span className="hidden sm:inline">•</span>
          <span className="hidden sm:inline">
            <kbd className="rounded bg-slate-800 px-1 py-0.5 text-zinc-300">F</kbd> fullscreen
          </span>
          <span className="hidden sm:inline">•</span>
          <span className="hidden sm:inline">
            <kbd className="rounded bg-slate-800 px-1 py-0.5 text-zinc-300">G</kbd> grid
          </span>
          {isPdf && (
            <>
              <span className="hidden md:inline">•</span>
              <span className="hidden md:inline">⌘/Ctrl + scroll or pinch to zoom</span>
            </>
          )}
        </div>
        <div className="flex items-center gap-3">
          {sha256 && <span className="truncate text-zinc-500">SHA {sha256.slice(0, 10)}…</span>}
          {sizeBytes ? <span>{formatBytes(sizeBytes)}</span> : null}
        </div>
      </footer>
    </div>
  );
};

export default PresentationViewer;
