/** Base error for all auth-related failures. */
export class AuthError extends Error {
  override name = "AuthError";
}

/** The session has expired and cannot be refreshed. Re-login required. */
export class SessionExpiredError extends AuthError {
  override name = "SessionExpiredError";
}

/** Token refresh failed (network or server error). */
export class TokenRefreshError extends AuthError {
  override name = "TokenRefreshError";
}

/**
 * OAuth token endpoint returned an error response.
 *
 * Carries the HTTP status code for reliable server-vs-network error detection.
 * 4xx errors indicate the token is invalid (re-login required).
 * 5xx errors may be transient (retriable).
 */
export class OAuthTokenError extends AuthError {
  override name = "OAuthTokenError";
  constructor(
    message: string,
    public readonly statusCode: number,
  ) {
    super(message);
  }
}

/** OAuth callback processing failed. */
export class CallbackError extends AuthError {
  override name = "CallbackError";
}

/** CSRF state mismatch during OAuth callback. */
export class CSRFError extends CallbackError {
  override name = "CSRFError";
}
