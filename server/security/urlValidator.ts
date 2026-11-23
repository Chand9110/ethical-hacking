import dns from 'dns/promises';
import net from 'net';

export const DEMO_STORE_HOST = 'demo-store.aegiscommerce.test';
export const DEMO_STORE_BASE_URL = `https://${DEMO_STORE_HOST}`;

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal',
  'metadata',
  '169.254.169.254',
]);

function isPrivateOrReservedIPv4(ip: string): boolean {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts;

  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 127) return true; // 127.0.0.0/8 Loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 Link-local / Cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 Benchmark
  if (a >= 224) return true; // Multicast & reserved

  return false;
}

function isPrivateOrReservedIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase().split('%')[0];
  if (normalized === '::' || normalized === '::1') return true;
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true; // ULA fc00::/7
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return true; // Link-local fe80::/10
  }
  if (normalized.startsWith('ff')) return true; // Multicast

  // IPv4-mapped IPv6 ::ffff:a.b.c.d
  const v4Mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Mapped) {
    return isPrivateOrReservedIPv4(v4Mapped[1]);
  }
  return false;
}

export function isBlockedIp(ip: string): boolean {
  const ipVersion = net.isIP(ip);
  if (ipVersion === 4) return isPrivateOrReservedIPv4(ip);
  if (ipVersion === 6) return isPrivateOrReservedIPv6(ip);
  return true;
}

export interface ValidatedTargetUrl {
  normalizedUrl: string;
  hostname: string;
  isDemoTarget: boolean;
}

export async function validateScanTargetUrl(rawUrl: string): Promise<ValidatedTargetUrl> {
  const trimmed = rawUrl.trim();
  if (!trimmed || trimmed.length > 2048) {
    throw new Error('Please enter a valid HTTP or HTTPS URL.');
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error('Invalid URL format. Include https:// or http://.');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only http:// and https:// protocols are permitted.');
  }

  if (parsed.username || parsed.password) {
    throw new Error('URLs containing embedded credentials are not permitted.');
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    throw new Error('Target URL must include a valid hostname.');
  }

  // Built-in sandboxed demo e-commerce target (executed strictly in-process)
  if (hostname === DEMO_STORE_HOST) {
    parsed.protocol = 'https:';
    parsed.port = '';
    return {
      normalizedUrl: parsed.toString(),
      hostname,
      isDemoTarget: true,
    };
  }

  // Block explicit internal/local hostnames
  if (
    BLOCKED_HOSTNAMES.has(hostname) ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.localdomain') ||
    hostname.endsWith('.example')
  ) {
    throw new Error(
      `Target host "${hostname}" is blocked. Private, local, internal, and reserved domains cannot be scanned.`
    );
  }

  // Check if raw IP literal was provided
  const cleanHost = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(cleanHost)) {
    if (isBlockedIp(cleanHost)) {
      throw new Error('Scanning private, loopback, link-local, or cloud metadata IP addresses is strictly prohibited.');
    }
    return {
      normalizedUrl: parsed.toString(),
      hostname,
      isDemoTarget: false,
    };
  }

  // Resolve DNS and verify all A/AAAA records are public unicast
  let records: { address: string; family: number }[];
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch {
    throw new Error(`Unable to resolve hostname "${hostname}". Verify the domain exists and is reachable.`);
  }

  if (!records || records.length === 0) {
    throw new Error(`No DNS records found for "${hostname}".`);
  }

  for (const rec of records) {
    if (isBlockedIp(rec.address)) {
      throw new Error(
        `Hostname "${hostname}" resolves to a restricted private or internal network address and cannot be scanned.`
      );
    }
  }

  return {
    normalizedUrl: parsed.toString(),
    hostname,
    isDemoTarget: false,
  };
}

export async function safeExternalFetch(
  targetUrl: string,
  signal?: AbortSignal,
  maxRedirects = 3
): Promise<{
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  responseTimeMs: number;
}> {
  let currentUrl = targetUrl;
  const start = Date.now();

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const validated = await validateScanTargetUrl(currentUrl);
    if (validated.isDemoTarget) {
      throw new Error('Demo target must be routed via virtual demo store handler.');
    }

    const timeoutController = new AbortController();
    const timeoutId = setTimeout(() => timeoutController.abort(), 8000);

    const onAbort = () => timeoutController.abort();
    if (signal) {
      if (signal.aborted) {
        clearTimeout(timeoutId);
        throw new Error('Scan aborted by user');
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }

    let response: globalThis.Response;
    try {
      response = await fetch(validated.normalizedUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: timeoutController.signal,
        headers: {
          'User-Agent': 'AegisCommerce-Security-Scanner/1.0 (Authorized-NonDestructive-Audit)',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });
    } finally {
      clearTimeout(timeoutId);
      if (signal) signal.removeEventListener('abort', onAbort);
    }

    // Handle redirects manually with SSRF re-validation
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location) {
        break;
      }
      if (hop === maxRedirects) {
        throw new Error('Maximum redirect limit reached during safe crawl.');
      }
      currentUrl = new URL(location, validated.normalizedUrl).toString();
      continue;
    }

    const headers: Record<string, string> = {};
    response.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val;
    });

    const getSetCookie = (response.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
    const setCookies = typeof getSetCookie === 'function'
      ? getSetCookie.call(response.headers)
      : response.headers.get('set-cookie')
        ? [response.headers.get('set-cookie') as string]
        : [];

    // Cap response body read at 512KB for safety
    const rawText = await response.text();
    const body = rawText.length > 524288 ? rawText.slice(0, 524288) : rawText;

    return {
      finalUrl: validated.normalizedUrl,
      status: response.status,
      headers,
      setCookies,
      body,
      responseTimeMs: Math.max(1, Date.now() - start),
    };
  }

  throw new Error('Unable to complete safe HTTP fetch.');
}
