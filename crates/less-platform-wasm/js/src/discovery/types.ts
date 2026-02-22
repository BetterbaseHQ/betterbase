/** Response from GET {domain}/.well-known/less-platform */
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
