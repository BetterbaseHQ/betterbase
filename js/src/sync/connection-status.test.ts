import { describe, it, expect } from "vitest";
import { deriveConnectionStatus } from "./connection-status.js";

const ready = {
  online: true,
  phase: "ready" as const,
  syncing: false,
  error: null,
};

describe("deriveConnectionStatus", () => {
  it("offline wins over everything", () => {
    expect(
      deriveConnectionStatus({
        ...ready,
        online: false,
        error: "boom",
        syncing: true,
      }),
    ).toBe("offline");
  });

  it("error wins over syncing once online", () => {
    expect(
      deriveConnectionStatus({ ...ready, error: "boom", syncing: true }),
    ).toBe("error");
  });

  it("reports syncing while an operation is in flight", () => {
    expect(deriveConnectionStatus({ ...ready, syncing: true })).toBe("syncing");
  });

  it("reports syncing during the connecting and bootstrapping phases", () => {
    expect(deriveConnectionStatus({ ...ready, phase: "connecting" })).toBe(
      "syncing",
    );
    expect(deriveConnectionStatus({ ...ready, phase: "bootstrapping" })).toBe(
      "syncing",
    );
  });

  it("reports synced only when ready, idle, online, and error-free", () => {
    expect(deriveConnectionStatus(ready)).toBe("synced");
  });
});
