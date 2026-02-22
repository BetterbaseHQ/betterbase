/**
 * Auth module — OAuth 2.0 + PKCE + scoped key delivery.
 */

// Main client
export { OAuthClient } from "./client.js";

// Session management
export { AuthSession } from "./session.js";

// Secure key storage
export { KeyStore, type KeyId } from "./key-store.js";

// Error classes
export {
  AuthError,
  SessionExpiredError,
  TokenRefreshError,
  OAuthTokenError,
  CallbackError,
  CSRFError,
} from "./errors.js";

// Types
export type {
  OAuthConfig,
  AuthResult,
  TokenResponse,
  AuthSessionConfig,
  TokenRefresher,
} from "./types.js";
