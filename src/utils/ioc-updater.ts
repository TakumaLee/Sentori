import { IOCBlocklist } from '../scanners/supply-chain-scanner';

const IOC_REMOTE_URL =
  'https://raw.githubusercontent.com/TakumaLee/Sentori/main/src/data/ioc-blocklist.json';
const FETCH_TIMEOUT_MS = 3000;

export async function fetchRemoteIOC(): Promise<Partial<IOCBlocklist> | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    const res = await fetch(IOC_REMOTE_URL, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data: unknown = await res.json();
    if (typeof data !== 'object' || data === null) return null;
    return data as Partial<IOCBlocklist>;
  } catch {
    return null;
  }
}

export async function mergeIOC(
  base: IOCBlocklist,
  remote: Partial<IOCBlocklist>
): Promise<IOCBlocklist> {
  return {
    malicious_ips: [
      ...new Set([...base.malicious_ips, ...(remote.malicious_ips ?? [])]),
    ],
    malicious_domains: [
      ...new Set([...base.malicious_domains, ...(remote.malicious_domains ?? [])]),
    ],
    malicious_mcp_packages: [
      ...new Set([...base.malicious_mcp_packages, ...(remote.malicious_mcp_packages ?? [])]),
    ],
    malicious_mcp_servers: [
      ...new Set([...base.malicious_mcp_servers, ...(remote.malicious_mcp_servers ?? [])]),
    ],
  };
}
