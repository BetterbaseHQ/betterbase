import { describe, it, expect, vi, beforeEach } from "vitest";
import { FilesClient } from "./files.js";
import { SyncClient } from "./client.js";

function ok(body?: ArrayBuffer, headers: Record<string, string> = {}) {
  return new Response(body ?? new ArrayBuffer(0), { status: 201, headers });
}

describe("FilesClient per-space routing", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  function makeClient(getUCANForSpace?: (spaceId: string) => string | null) {
    const client = new FilesClient(
      new SyncClient({
        baseUrl: "https://sync.test/api/v1",
        spaceId: "personal-space",
        getToken: async () => "token-1",
        ...(getUCANForSpace ? { getUCANForSpace } : {}),
      }),
    );
    return client;
  }

  it("defaults to the configured space", async () => {
    const fetchMock = vi.fn().mockResolvedValue(ok());
    vi.stubGlobal("fetch", fetchMock);
    await makeClient().upload("f", new Uint8Array(4), new Uint8Array(44), "r1");
    expect(fetchMock.mock.calls[0]![0]).toBe(
      "https://sync.test/api/v1/spaces/personal-space/files/f",
    );
    // No UCAN for the personal space unless one resolves.
    expect(fetchMock.mock.calls[0]![1].headers["X-UCAN"]).toBeUndefined();
  });

  it("routes upload/download/head to an explicit shared space with its UCAN", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(ok())
      .mockResolvedValueOnce(
        ok(new ArrayBuffer(4), {
          "X-Wrapped-DEK":
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        }),
      )
      .mockResolvedValueOnce(new Response(null, { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);
    const client = makeClient((spaceId) =>
      spaceId === "shared-1" ? "ucan-shared-1" : null,
    );

    await client.upload(
      "f",
      new Uint8Array(4),
      new Uint8Array(44),
      "r1",
      "shared-1",
    );
    expect(fetchMock.mock.calls[0]![0]).toBe(
      "https://sync.test/api/v1/spaces/shared-1/files/f",
    );
    expect(fetchMock.mock.calls[0]![1].headers["X-UCAN"]).toBe("ucan-shared-1");

    await client.download("f", "shared-1");
    expect(fetchMock.mock.calls[1]![0]).toBe(
      "https://sync.test/api/v1/spaces/shared-1/files/f",
    );
    expect(fetchMock.mock.calls[1]![1].headers["X-UCAN"]).toBe("ucan-shared-1");

    await client.head("f", "shared-1");
    expect(fetchMock.mock.calls[2]![0]).toBe(
      "https://sync.test/api/v1/spaces/shared-1/files/f",
    );
  });
});
