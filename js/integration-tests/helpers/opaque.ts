/**
 * OPAQUE client bindings — port of the accounts web app's web/src/lib/opaque.ts.
 * Base64 conventions: the server exchanges standard base64; the library
 * wants base64url. Same package, same conversions, same server identity.
 */
import * as opaque from "@serenity-kit/opaque";

const SERVER_IDENTITY = "betterbase-accounts";

function toStdBase64(input: string): string {
  let result = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = result.length % 4;
  if (pad) result += "=".repeat(4 - pad);
  return result;
}

function toBase64url(stdBase64: string): string {
  return stdBase64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function startRegistration(password: string) {
  await opaque.ready;
  const { clientRegistrationState, registrationRequest } =
    opaque.client.startRegistration({
      password,
    });
  return {
    clientRegistrationState,
    registrationRequest: toStdBase64(registrationRequest),
  };
}

export async function finishRegistration(
  clientRegistrationState: string,
  registrationResponse: string,
  password: string,
) {
  await opaque.ready;
  const { registrationRecord, exportKey } = opaque.client.finishRegistration({
    clientRegistrationState,
    registrationResponse: toBase64url(registrationResponse),
    password,
    identifiers: { server: SERVER_IDENTITY },
  });
  return { registrationRecord: toStdBase64(registrationRecord), exportKey };
}

export async function startLogin(password: string) {
  await opaque.ready;
  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
    password,
  });
  return { clientLoginState, ke1: toStdBase64(startLoginRequest) };
}

export async function finishLogin(
  clientLoginState: string,
  loginResponse: string,
  password: string,
): Promise<{ ke3: string; exportKey: string } | null> {
  await opaque.ready;
  const result = opaque.client.finishLogin({
    clientLoginState,
    loginResponse: toBase64url(loginResponse),
    password,
    identifiers: { server: SERVER_IDENTITY },
  });
  if (!result) return null;
  return {
    ke3: toStdBase64(result.finishLoginRequest),
    exportKey: result.exportKey,
  };
}
