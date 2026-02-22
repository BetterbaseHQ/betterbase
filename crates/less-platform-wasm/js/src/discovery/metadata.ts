import type { ServerMetadata } from "./types.js";

/** Timeout for all discovery HTTP requests (10 seconds). */
export const DISCOVERY_TIMEOUT_MS = 10_000;

/**
 * Infer the URL scheme for a domain.
 * localhost / 127.0.0.1 → http, everything else → https.
 */
function inferScheme(domain: string): string {
  const host = domain.split(":")[0]!;
  return host === "localhost" || host === "127.0.0.1" ? "http" : "https";
}

/** Wire format from the server (snake_case). */
interface ServerMetadataWire {
  version: number;
  federation: boolean;
  accounts_endpoint: string;
  sync_endpoint: string;
  federation_ws: string;
  jwks_uri: string;
  webfinger: string;
  protocols: string[];
  pow_required: boolean;
}

/**
 * Fetch server metadata from a domain's .well-known endpoint.
 *
 * The domain should NOT include a scheme — it is inferred automatically
 * (http for localhost/127.0.0.1, https for everything else).
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
  const url = `${scheme}://${domain}/.well-known/less-platform`;

  const response = await fetch(url, {
    signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(
      `Discovery failed for ${domain}: HTTP ${response.status} from ${url}`,
    );
  }

  const data: unknown = await response.json();
  return parseServerMetadata(data);
}

/** Validate and map a wire-format response to camelCase ServerMetadata. */
function parseServerMetadata(data: unknown): ServerMetadata {
  if (typeof data !== "object" || data === null) {
    throw new Error("Invalid discovery response: expected object");
  }

  const obj = data as Record<string, unknown>;

  if (typeof obj["version"] !== "number") {
    throw new Error("Invalid discovery response: missing or invalid version");
  }
  if (obj["version"] !== 1) {
    throw new Error(
      `Unsupported discovery version ${obj["version"]} (this client supports version 1)`,
    );
  }
  if (
    typeof obj["accounts_endpoint"] !== "string" ||
    !obj["accounts_endpoint"]
  ) {
    throw new Error("Invalid discovery response: missing accounts_endpoint");
  }
  if (typeof obj["sync_endpoint"] !== "string" || !obj["sync_endpoint"]) {
    throw new Error("Invalid discovery response: missing sync_endpoint");
  }

  const wire = data as ServerMetadataWire;
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
}
