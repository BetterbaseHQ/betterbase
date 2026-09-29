/** Response from GET {domain}/.well-known/betterbase */
export interface ServerMetadata {
  version: number;
  federation: boolean;
  accountsEndpoint: string;
  syncEndpoint: string;
  federationWs: string;
  jwksUri: string;
  webfinger: string;
  protocols: string[];
  powRequired: boolean;
}

/** RFC 7033 WebFinger JRD response. */
export interface WebFingerResponse {
  subject: string;
  links: WebFingerLink[];
}

export interface WebFingerLink {
  rel: string;
  href: string;
}

/** Parsed result from WebFinger resolution. */
export interface UserResolution {
  subject: string;
  syncEndpoint: string;
}

/** Rust-validated metadata at the WASM boundary (server field names). */
export interface ServerMetadataWire {
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

/** Rust-validated WebFinger resolution at the WASM boundary. */
export interface UserResolutionWire {
  subject: string;
  sync_endpoint: string;
}
