/**
 * Stack config for browser-side tests, fetched once from the Node sidecar.
 * Tests skip when the stack is unavailable.
 */

export interface IntegrationConfig {
  available: boolean;
  reason?: string;
  accountsUrl: string;
  syncUrl: string;
  clientId?: string;
}

let cached: Promise<IntegrationConfig> | null = null;

export function stackConfig(): Promise<IntegrationConfig> {
  if (!cached) {
    cached = fetch("http://127.0.0.1:25499/config")
      .then((r) => {
        if (!r.ok) throw new Error(`sidecar /config: ${r.status}`);
        return r.json() as Promise<IntegrationConfig>;
      })
      .catch((err) => {
        // Sidecar itself down (suite run without globalSetup) — skip shape
        return {
          available: false,
          reason: `integration sidecar unreachable: ${String(err)}`,
          accountsUrl: "http://localhost:25377",
          syncUrl: "http://localhost:25379",
        } satisfies IntegrationConfig;
      });
  }
  return cached;
}

/** Ask the Node sidecar for the email verification code (docker log poll). */
export async function verificationCode(email: string): Promise<string> {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(
        `http://127.0.0.1:25499/code?email=${encodeURIComponent(email)}`,
      );
      if (res.ok) {
        const body = (await res.json()) as { code: string };
        return body.code;
      }
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }
  throw new Error(`verification code not found for ${email}`);
}
