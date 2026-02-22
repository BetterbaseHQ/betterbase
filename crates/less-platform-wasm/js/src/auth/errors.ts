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

/** OAuth callback processing failed. */
export class CallbackError extends AuthError {
  override name = "CallbackError";
}

/** CSRF state mismatch during OAuth callback. */
export class CSRFError extends CallbackError {
  override name = "CSRFError";
}
