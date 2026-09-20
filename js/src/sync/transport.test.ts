/**
 * Unit tests for SyncTransport's push failure semantics.
 *
 * The push function is the boundary (mocked). Tombstone-only pushes need
 * no key material, so the transport runs without crypto configuration.
 */

import { describe, it, expect, vi } from "vitest";
import { SyncTransport, PushRejectedError } from "./transport.js";

function tombstoneRecord(id: string, sequence: number) {
  return {
    id,
    _v: 1,
    crdt: null,
    deleted: true,
    sequence,
    meta: undefined,
  };
}

describe("SyncTransport.push", () => {
  it("returns acks stamped with the server cursor on success", async () => {
    const transport = new SyncTransport({
      push: async () => ({ ok: true, sequence: 9 }),
      spaceId: "space-1",
    });

    const acks = await transport.push("notes", [tombstoneRecord("n1", 3)]);
    expect(acks).toEqual([{ id: "n1", sequence: 9 }]);
  });

  it("throws PushRejectedError carrying the server code and cursor on rejection", async () => {
    const transport = new SyncTransport({
      push: async () => ({ ok: false, sequence: 0, error: "conflict" }),
      spaceId: "space-1",
    });

    let caught: unknown;
    try {
      await transport.push("notes", [tombstoneRecord("n1", 3)]);
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(PushRejectedError);
    const err = caught as PushRejectedError;
    expect(err.name).toBe("PushRejectedError");
    expect(err.code).toBe("conflict");
    expect(err.message).toContain("conflict");
    expect(err.serverSequence).toBe(0);
    expect(err.rejected).toBe(true);
  });

  it("marks rejections with no server reason as unknown", async () => {
    const transport = new SyncTransport({
      push: async () => ({ ok: false, sequence: 0 }),
      spaceId: "space-1",
    });

    await expect(
      transport.push("notes", [tombstoneRecord("n1", 0)]),
    ).rejects.toThrow(/unknown/);
  });

  it("returns an empty ack list without calling push when nothing is sendable", async () => {
    const push = vi.fn();
    const transport = new SyncTransport({ push, spaceId: "space-1" });

    const acks = await transport.push("notes", []);
    expect(acks).toEqual([]);
    expect(push).not.toHaveBeenCalled();
  });
});
