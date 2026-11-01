// Is this host public? The rule for fetching an address that someone other than the machine's owner chose: a visitor of
// the web app, or an agent acting on text it read.
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/** A refusal, not a failure: its message is a machine word (invalid, port, dns, private, redirects). */
export class Refused extends Error {}

const v4 = (ip: string) => ip.split(".").reduce((n, o) => n * 256 + Number(o), 0);
const cidr4 = (base: string, bits: number) => [v4(base), 2 ** (32 - bits)] as const;
const PRIVATE_V4 = [
  cidr4("0.0.0.0", 8), cidr4("10.0.0.0", 8), cidr4("100.64.0.0", 10), cidr4("127.0.0.0", 8), cidr4("169.254.0.0", 16),
  cidr4("172.16.0.0", 12), cidr4("192.0.0.0", 24), cidr4("192.0.2.0", 24), cidr4("192.88.99.0", 24), cidr4("192.168.0.0", 16),
  cidr4("198.18.0.0", 15), cidr4("198.51.100.0", 24), cidr4("203.0.113.0", 24), cidr4("224.0.0.0", 4), cidr4("240.0.0.0", 4),
];

/** Public unicast only. IPv6 is allow-listed to global unicast 2000::/3 (minus documentation and 6to4). */
export function isPublicAddress(ip: string): boolean {
  if (isIP(ip) === 4) {
    const n = v4(ip);
    return !PRIVATE_V4.some(([base, size]) => n >= base && n < base + size);
  }
  if (isIP(ip) !== 6) return false;
  const lower = ip.toLowerCase();
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPublicAddress(mapped[1]!);
  const first = parseInt(lower.split(":")[0] || "0", 16);
  if ((first & 0xe000) !== 0x2000) return false; // not 2000::/3
  if (lower.startsWith("2001:db8:") || lower.startsWith("2002:")) return false;
  return true;
}

export async function assertPublic(url: URL) {
  const host = url.hostname.replace(/^\[|\]$/g, "");
  let addrs: { address: string }[];
  try {
    addrs = await lookup(host, { all: true, verbatim: true });
  } catch {
    throw new Refused("dns");
  }
  if (addrs.length === 0 || !addrs.every((a) => isPublicAddress(a.address))) throw new Refused("private");
}
