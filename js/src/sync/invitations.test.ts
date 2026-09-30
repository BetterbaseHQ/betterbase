import { describe, it, expect, vi, afterEach } from "vitest";
import {
  InvitationClient,
  RecipientNotFoundError,
  RecipientNotProvisionedError,
} from "./invitations.js";

const CLIENT_ID = "11111111-1111-1111-1111-111111111111";

function makeClient(): InvitationClient {
  return new InvitationClient({
    ws: {} as never,
    accountsBaseUrl: "https://accounts.test",
    getToken: async () => "token",
  });
}

function stubFetch(status: number, body: unknown) {
  return vi.fn(
    async () =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("InvitationClient.fetchRecipientKey", () => {
  it("maps a 404 tagged user_key_not_provisioned to RecipientNotProvisionedError", async () => {
    vi.stubGlobal(
      "fetch",
      stubFetch(404, {
        error: "user has not connected this app",
        code: "user_key_not_provisioned",
      }),
    );

    const err = await makeClient()
      .fetchRecipientKey("alice@accounts.test", CLIENT_ID)
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(RecipientNotProvisionedError);
    expect((err as RecipientNotProvisionedError).handle).toBe(
      "alice@accounts.test",
    );
  });

  it("keeps mapping untagged 404s to RecipientNotFoundError (older servers)", async () => {
    vi.stubGlobal("fetch", stubFetch(404, { error: "not found" }));

    const err = await makeClient()
      .fetchRecipientKey("ghost@accounts.test", CLIENT_ID)
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(RecipientNotFoundError);
    expect(err).not.toBeInstanceOf(RecipientNotProvisionedError);
  });

  it("maps a non-JSON 404 body to RecipientNotFoundError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("nope", {
            status: 404,
            headers: { "content-type": "text/plain" },
          }),
      ),
    );

    await expect(
      makeClient().fetchRecipientKey("ghost@accounts.test", CLIENT_ID),
    ).rejects.toBeInstanceOf(RecipientNotFoundError);
  });

  it("throws a generic error for server failures", async () => {
    vi.stubGlobal("fetch", stubFetch(500, { error: "internal" }));

    await expect(
      makeClient().fetchRecipientKey("alice@accounts.test", CLIENT_ID),
    ).rejects.toThrow("status 500");
  });
});
