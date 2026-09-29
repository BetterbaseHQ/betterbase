import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchServerMetadata } from "../../src/discovery/metadata.js";
import { resolveUser } from "../../src/discovery/webfinger.js";

// No initWasm call here: discovery must remain usable before SDK bootstrap.
afterEach(() => vi.unstubAllGlobals());
const metadata = {
  version: 1,
  federation: true,
  accounts_endpoint: "https://accounts.example.com",
  sync_endpoint: "https://sync.example.com/api/v1",
  federation_ws: "wss://sync.example.com/federation",
  jwks_uri: "https://accounts.example.com/jwks",
  webfinger: "https://accounts.example.com/webfinger",
  protocols: ["betterbase-rpc-v1"],
  pow_required: true,
};
const browserFetch = globalThis.fetch.bind(globalThis);
function routeDiscovery(response: () => Response) {
  const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    // Standalone discovery initializes WASM through a genuine browser fetch.
    if (new URL(url, location.href).pathname.endsWith(".wasm"))
      return browserFetch(input, init);
    return response();
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}
function respond(body: unknown, status = 200) {
  return routeDiscovery(() => new Response(JSON.stringify(body), { status }));
}

describe("discovery fetch shell with real Rust validation", () => {
  it("initializes WASM itself and maps all server fields", async () => {
    const fetchMock = respond(metadata);
    expect(await fetchServerMetadata("example.com")).toEqual({
      version: 1,
      federation: true,
      accountsEndpoint: metadata.accounts_endpoint,
      syncEndpoint: metadata.sync_endpoint,
      federationWs: metadata.federation_ws,
      jwksUri: metadata.jwks_uri,
      webfinger: metadata.webfinger,
      protocols: metadata.protocols,
      powRequired: true,
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://example.com/.well-known/betterbase",
      { signal: expect.any(AbortSignal) },
    );
  });

  it("gets defaults for optional metadata from Rust", async () => {
    respond({
      version: 1,
      accounts_endpoint: "accounts",
      sync_endpoint: "sync",
    });
    expect(await fetchServerMetadata("localhost:25377")).toEqual({
      version: 1,
      accountsEndpoint: "accounts",
      syncEndpoint: "sync",
      federation: false,
      federationWs: "",
      jwksUri: "",
      webfinger: "",
      protocols: [],
      powRequired: false,
    });
  });

  it.each([
    null,
    [],
    {},
    { ...metadata, version: 2 },
    { ...metadata, accounts_endpoint: "" },
    { ...metadata, sync_endpoint: null },
  ])("rejects malformed metadata: %j", async (body) => {
    respond(body);
    await expect(fetchServerMetadata("example.com")).rejects.toThrow(Error);
  });

  it.each(["", "https://example.com", "http://localhost:25377"])(
    "rejects invalid domain %s before fetching",
    async (domain) => {
      const fetchMock = respond(metadata);
      await expect(fetchServerMetadata(domain)).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("keeps HTTP errors in the fetch shell", async () => {
    respond({}, 503);
    await expect(fetchServerMetadata("example.com")).rejects.toThrow(
      /HTTP 503/,
    );
    await expect(
      resolveUser("a@example.com", metadata.webfinger),
    ).rejects.toThrow(/HTTP 503/);
  });

  it("normalizes malformed JSON to an Error", async () => {
    routeDiscovery(() => new Response("not JSON"));
    await expect(fetchServerMetadata("example.com")).rejects.toThrow(Error);
    await expect(
      resolveUser("a@example.com", metadata.webfinger),
    ).rejects.toThrow(Error);
  });

  it("resolves a user through Rust, ignoring malformed/unrelated links", async () => {
    const fetchMock = respond({
      subject: "acct:alice@example.com",
      links: [
        null,
        { rel: "other", href: "elsewhere" },
        { rel: "https://betterbase.dev/ns/sync" },
        { rel: "https://betterbase.dev/ns/sync", href: metadata.sync_endpoint },
      ],
    });
    expect(
      await resolveUser("alice+device@example.com", metadata.webfinger),
    ).toEqual({
      subject: "acct:alice@example.com",
      syncEndpoint: metadata.sync_endpoint,
    });
    expect(fetchMock).toHaveBeenCalledWith(
      `${metadata.webfinger}?resource=acct:alice%2Bdevice%40example.com`,
      { signal: expect.any(AbortSignal) },
    );
  });

  it.each([
    null,
    [],
    {},
    { subject: "acct:a", links: null },
    { subject: "acct:a", links: [] },
    {
      subject: "acct:a",
      links: [{ rel: "https://betterbase.dev/ns/sync", href: 42 }],
    },
  ])("rejects malformed/unresolvable WebFinger: %j", async (body) => {
    respond(body);
    await expect(
      resolveUser("a@example.com", metadata.webfinger),
    ).rejects.toThrow(Error);
  });
});
