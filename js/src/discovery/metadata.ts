import { initWasm } from "../wasm-init.js";
import type { ServerMetadata } from "./types.js";

/** Timeout for all discovery HTTP requests (10 seconds). */
export const DISCOVERY_TIMEOUT_MS = 10_000;

/**
 * Infer the URL scheme for a domain.
 * Loopback names — localhost, 127.0.0.1, and anything under the reserved
 * .localhost TLD (RFC 6761, e.g. accounts.betterbase.localhost) — get http;
 * everything else gets https.
 */
function inferScheme(domain: string): string {
  const host = domain.split(":")[0]!;
  return host === "localhost" ||
    host === "127.0.0.1" ||
    host.endsWith(".localhost")
    ? "http"
    : "https";
}

/**
 * Fetch server metadata from a domain's .well-known endpoint.
 *
 * The domain should NOT include a scheme — it is inferred automatically
 * (http for loopback names incl. the .localhost TLD, https for everything else).
 *
 * @throws Error on network failure or invalid response.
 */
export async function fetchServerMetadata(
  domain: string,
): Promise<ServerMetadata> {
  if (!domain) {
    throw new Error("domain parameter is required");
  }
  if (domain.startsWith("http://") || domain.startsWith("https://")) {
    throw new Error(
      `domain should not include a scheme (got "${domain}"). Pass just the hostname.`,
    );
  }

  const scheme = inferScheme(domain);
  const url = `${scheme}://${domain}/.well-known/betterbase`;

  const response = await fetch(url, {
    signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(
      `Discovery failed for ${domain}: HTTP ${response.status} from ${url}`,
    );
  }

  const json = await response.text();
  // Discovery is also used before SDK bootstrap; preserve its standalone
  // async API by loading WASM here rather than requiring caller setup.
  const wasm = await initWasm();
  try {
    const wire = wasm.validateServerMetadata(json);
    return {
      version: wire.version,
      federation: wire.federation,
      accountsEndpoint: wire.accounts_endpoint,
      syncEndpoint: wire.sync_endpoint,
      federationWs: wire.federation_ws,
      jwksUri: wire.jwks_uri,
      webfinger: wire.webfinger,
      protocols: wire.protocols,
      powRequired: wire.pow_required,
    };
  } catch (error) {
    throw error instanceof Error ? error : new Error(String(error));
  }
}
