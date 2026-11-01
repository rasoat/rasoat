// A GET that reads what a browser would, within size and time limits. What may be fetched is the caller's policy
// (`admit`): the web app refuses private addresses, the CLI runs on the user's own machine and does not.
import type { Get } from "./crawl.ts";

const MAX_BYTES = 3_000_000;
const TIMEOUT_MS = 8_000;
/** Certificate-chain failures a browser would usually repair (missing intermediate, unknown issuer). */
const TLS_CHAIN = new Set(["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "UNABLE_TO_GET_ISSUER_CERT", "SELF_SIGNED_CERT_IN_CHAIN"]);

async function readCapped(res: Response): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BYTES) {
      await reader.cancel();
      break; // keep what we have: a version string sits early in a chunk more often than not
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

export interface CappedGetOptions {
  userAgent: string;
  /** Called for the first URL and every redirect; returns the URL to fetch, or throws to refuse (or to stop a redirect loop). */
  admit(href: string, hop: number): Promise<URL>;
}

export function cappedGet({ userAgent, admit }: CappedGetOptions): Get {
  return async (input) => {
    for (let hop = 0, href = input; ; hop++) {
      const url = await admit(href, hop);
      const init = {
        redirect: "manual" as const,
        signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { "user-agent": userAgent, accept: "text/html,*/*" },
      };
      // A server that omits its intermediate certificate loads in browsers (they fetch it) but fails here. We only read
      // public files, so read once more without chain verification — and say so.
      let tlsUnverified = false;
      const res = await fetch(url, init).catch(async (e) => {
        if (!TLS_CHAIN.has(e?.code)) throw e;
        tlsUnverified = true;
        return fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS), tls: { rejectUnauthorized: false } });
      });
      const location = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && location) {
        await res.body?.cancel();
        href = new URL(location, url).href;
        continue;
      }
      return { url: url.href, status: res.status, headers: Object.fromEntries(res.headers), body: await readCapped(res), ...(tlsUnverified ? { tlsUnverified } : {}) };
    }
  };
}
