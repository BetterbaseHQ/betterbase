/** Explicit test-only WASM substitute. Never import from production modules. */
import { foldMembershipLogMock } from "./sync/membership-fold-mock.js";
import {
  rotationStartMock,
  rotationStepMock,
  rotationAbortMock,
  shouldRotateSpaceEpochMock,
} from "./sync/rotation-mock.js";
import {
  oauthCallbackStartMock,
  oauthCallbackStepMock,
} from "./auth/oauth-callback-mock.js";
import { parseSpacesRecordMirror } from "./sync/spaces-record-mock.js";
import {
  parseMailboxMessageMirror,
  serializeInvitationPayloadMirror,
} from "./sync/invitation-wire-mock.js";
import {
  encodeReplayWrapperMirror,
  parseReplayWrapperMirror,
  isReplayStaleMirror,
  PRESENCE_REPLAY_MAX_AGE_MS,
  EVENT_REPLAY_MAX_AGE_MS,
} from "./sync/replay-mock.js";
import type { InvitationPayloadWire } from "./wasm-init.js";

export function createProtocolWasmMock() {
  return {
    foldMembershipLog: (
      payloads: string[],
      spaceId: string,
      now: number,
      removedDid?: string,
    ) => foldMembershipLogMock(payloads, spaceId, { now, removedDid }),
    rotationStart: rotationStartMock,
    rotationStep: rotationStepMock,
    rotationAbort: rotationAbortMock,
    shouldRotateSpaceEpoch: (
      now: bigint,
      advanced: bigint | null,
      admin: boolean,
      interval: bigint | null,
    ) =>
      shouldRotateSpaceEpochMock(
        Number(now),
        advanced === null ? null : Number(advanced),
        admin,
        interval === null ? undefined : Number(interval),
      ),
    oauthCallbackStart: oauthCallbackStartMock,
    oauthCallbackStep: oauthCallbackStepMock,
    parseSpacesRecord: parseSpacesRecordMirror,
    parseMailboxMessage: parseMailboxMessageMirror,
    serializeInvitationPayload: (json: string) =>
      serializeInvitationPayloadMirror(
        JSON.parse(json) as InvitationPayloadWire,
      ),
    parseReplayWrapper: parseReplayWrapperMirror,
    encodeReplayWrapper: (bytes: Uint8Array, sent: bigint) =>
      encodeReplayWrapperMirror(bytes, Number(sent)),
    isReplayStale: (now: bigint, sent: bigint | null, age: bigint) =>
      isReplayStaleMirror(
        Number(now),
        sent === null ? null : Number(sent),
        Number(age),
      ),
    presenceReplayMaxAgeMs: () => BigInt(PRESENCE_REPLAY_MAX_AGE_MS),
    eventReplayMaxAgeMs: () => BigInt(EVENT_REPLAY_MAX_AGE_MS),
  };
}
