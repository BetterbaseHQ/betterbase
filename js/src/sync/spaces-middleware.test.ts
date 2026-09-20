import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  createSpacesMiddleware,
  isShared,
  reconstructState,
} from "./spaces-middleware.js";

// parseEditChain/reconstructState are WASM-bound; mock the boundary so the
// mapping logic around them runs in node. Real chain parsing is covered by
// the browser suite.
vi.mock("../crypto/index.js", () => ({
  parseEditChain: vi.fn(),
  reconstructState: vi.fn(),
}));

import {
  parseEditChain,
  reconstructState as cryptoReconstructState,
} from "../crypto/index.js";

const mockParseEditChain = vi.mocked(parseEditChain);
const mockCryptoReconstructState = vi.mocked(cryptoReconstructState);

beforeEach(() => {
  mockParseEditChain.mockReset();
  mockCryptoReconstructState.mockReset();
});

describe("isShared", () => {
  it("returns false for records without a _spaceId (local mode)", () => {
    expect(isShared({}, "personal-1")).toBe(false);
    expect(isShared({ _spaceId: undefined }, "personal-1")).toBe(false);
  });

  it("returns false when the record is in the personal space", () => {
    expect(isShared({ _spaceId: "personal-1" }, "personal-1")).toBe(false);
  });

  it("returns true when the record is in another space", () => {
    expect(isShared({ _spaceId: "shared-2" }, "personal-1")).toBe(true);
  });

  it("returns true when a _spaceId exists but personalSpaceId is null", () => {
    expect(isShared({ _spaceId: "shared-2" }, null)).toBe(true);
    expect(isShared({ _spaceId: "shared-2" }, undefined)).toBe(true);
  });
});

describe("createSpacesMiddleware space-scoped queries", () => {
  const mw = createSpacesMiddleware("personal-1");
  const onQuery = mw.onQuery!;

  it("matches records with an explicit space meta", () => {
    const filter = onQuery({ space: "shared-2" });
    expect(filter!({ spaceId: "shared-2" })).toBe(true);
    expect(filter!({ spaceId: "personal-1" })).toBe(false);
  });

  it("coalesces unstamped records to the default space, matching onRead", () => {
    // Records created before any space routing (offline, pre-first-sync)
    // read back with _spaceId = personal space; queries must agree, or
    // space-scoped discovery (deleteTree, sameSpaceAs) silently skips them.
    const filter = onQuery({ space: "personal-1" });
    expect(filter!({})).toBe(true);
    expect(filter!(undefined)).toBe(true);
    expect(filter!({ spaceId: "shared-2" })).toBe(false);
  });

  it("sameSpaceAs without _spaceId yields no filter (unscoped query)", () => {
    // Pin current behavior: unlike onWrite (which throws), onQuery degrades
    // to an unscoped query when the reference record has no space.
    const mw = createSpacesMiddleware("personal-1");
    expect(mw.onQuery!({ sameSpaceAs: {} })).toBeUndefined();
  });
});

describe("createSpacesMiddleware onRead", () => {
  const mw = createSpacesMiddleware("personal-1");
  const onRead = mw.onRead!;

  it("stamps _spaceId from record metadata", () => {
    const out = onRead({ id: "1", name: "a" }, { spaceId: "shared-2" });
    expect(out._spaceId).toBe("shared-2");
    expect(out.name).toBe("a");
  });

  it("defaults unstamped records to the personal space", () => {
    expect(onRead({ id: "1" }, {})._spaceId).toBe("personal-1");
    expect(onRead({ id: "1" }, { spaceId: null })._spaceId).toBe("personal-1");
  });

  it("meta wins over a stale _spaceId property on the record itself", () => {
    const out = onRead(
      { id: "1", _spaceId: "shared-2" },
      { spaceId: "shared-9" },
    );
    expect(out._spaceId).toBe("shared-9");
  });

  it("adds no edit-chain fields when the record has no chain", () => {
    const out = onRead({ id: "1" }, { spaceId: "s" });
    expect("_editChain" in out).toBe(false);
    expect("_editChainValid" in out).toBe(false);
  });

  it("maps a parsed wire chain to app-facing entries and carries the valid flag", () => {
    mockParseEditChain.mockReturnValue([
      {
        a: "did:key:z6Alice",
        t: 1234,
        d: [{ path: "name", from: null, to: "x" }],
      },
    ] as never);
    const out = onRead(
      { id: "1" },
      { spaceId: "s", _editChain: "opaque", _editChainValid: true },
    );
    expect(out._editChain).toEqual([
      {
        author: "did:key:z6Alice",
        timestamp: 1234,
        diffs: [{ path: "name", from: null, to: "x" }],
      },
    ]);
    expect(out._editChainValid).toBe(true);
  });

  it("defaults _editChainValid to false when the server sent no flag", () => {
    mockParseEditChain.mockReturnValue([] as never);
    const out = onRead({ id: "1" }, { spaceId: "s", _editChain: "opaque" });
    expect(out._editChainValid).toBe(false);
  });

  it("degrades to invalid on chain parse failure (corrupt or tampered chain)", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      mockParseEditChain.mockImplementation(() => {
        throw new Error("bad cbor");
      });
      const out = onRead({ id: "1" }, { spaceId: "s", _editChain: "garbage" });
      expect(out._editChain).toBeUndefined();
      expect(out._editChainValid).toBe(false);
      expect(warn).toHaveBeenCalledOnce();
    } finally {
      warn.mockRestore();
    }
  });
});

describe("createSpacesMiddleware onWrite", () => {
  const mw = createSpacesMiddleware("personal-1");
  const onWrite = mw.onWrite!;

  it("routes to the referenced record's space via sameSpaceAs", () => {
    expect(onWrite({ sameSpaceAs: { _spaceId: "shared-2" } })).toEqual({
      spaceId: "shared-2",
    });
  });

  it("throws when the referenced record has no _spaceId", () => {
    expect(() => onWrite({ sameSpaceAs: {} })).toThrowError(
      "Referenced record has no _spaceId",
    );
  });

  it("sameSpaceAs takes precedence over an explicit space option", () => {
    expect(onWrite({ sameSpaceAs: { _spaceId: "a" }, space: "b" })).toEqual({
      spaceId: "a",
    });
  });

  it("routes via explicit space when given", () => {
    expect(onWrite({ space: "shared-2" })).toEqual({ spaceId: "shared-2" });
  });

  it("routes to the engine default when no routing options are given", () => {
    expect(onWrite({})).toEqual({});
  });
});

describe("createSpacesMiddleware shouldResetSyncState", () => {
  const mw = createSpacesMiddleware("personal-1");
  const shouldReset = mw.shouldResetSyncState!;

  it("resets when the record gains a (new) space", () => {
    expect(shouldReset(undefined, { spaceId: "s" })).toBe(true);
    expect(shouldReset({ spaceId: "a" }, { spaceId: "s" })).toBe(true);
  });

  it("does not reset when the space is unchanged", () => {
    expect(shouldReset({ spaceId: "s" }, { spaceId: "s" })).toBe(false);
  });

  it("does not reset when the new state has no space (covers unset)", () => {
    expect(shouldReset({ spaceId: "s" }, {})).toBe(false);
    expect(shouldReset(undefined, {})).toBe(false);
  });
});

describe("reconstructState", () => {
  it("maps app-facing entries to wire shape and delegates", () => {
    mockCryptoReconstructState.mockReturnValue({ name: "v2" });
    const out = reconstructState(
      [
        {
          author: "a",
          timestamp: 1,
          diffs: [{ path: "name", from: "v1", to: "v2" }],
        },
      ],
      0,
    );
    expect(mockCryptoReconstructState).toHaveBeenCalledWith(
      [{ d: [{ path: "name", from: "v1", to: "v2" }] }],
      0,
    );
    expect(out).toEqual({ name: "v2" });
  });

  it("passes wire-format entries through untouched", () => {
    mockCryptoReconstructState.mockReturnValue({});
    reconstructState([{ d: [{ path: "x", from: null, to: 1 }] }], 5);
    expect(mockCryptoReconstructState).toHaveBeenCalledWith(
      [{ d: [{ path: "x", from: null, to: 1 }] }],
      5,
    );
  });
});
