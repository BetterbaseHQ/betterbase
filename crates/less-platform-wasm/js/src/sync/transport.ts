/**
 * SyncTransport implementation that bridges @less-platform/db's sync system
 * to the less-sync server.
 *
 * Handles the blob envelope format for multi-collection support over our
 * single-space sync protocol, plus per-record DEK encryption at the sync boundary.
 *
 * Push: delegates to a caller-provided push function (WebSocket).
 * Pull: accepts pre-pulled changes from the outer transport (WSTransport).
 */

import type {
  SyncTransport,
  OutboundRecord,
  PushAck,
  PullResult,
  PullFailure,
  SyncResult,
  CollectionDef,
} from "@less-platform/db";
import type { RemoteRecord } from "@less-platform/db";
import type { SyncController } from "@less-platform/db";
import type {
  Change,
  PushResult,
  SyncEventData,
  EpochConfig,
} from "./types.js";
import { cborEncode, cborDecode } from "./cbor.js";
import {
  deriveNextEpochKey,
  DEFAULT_EPOCH_ADVANCE_INTERVAL_MS,
  signEditEntry,
  verifyEditChain,
  valueDiff,
  serializeEditChain,
  parseEditChain,
  type EditEntry,
} from "../crypto/index.js";
import {
  generateDEK,
  wrapDEK,
  unwrapDEK,
  encryptV4,
  decryptV4,
} from "../crypto/internals.js";
import { Model } from "json-joy/lib/json-crdt/index.js";

/**
 * Envelope format for wrapping collection context into encrypted blobs.
 * Each record's CRDT binary is wrapped with collection name and schema version
 * before encryption, enabling multi-collection support over a single sync space.
 */
interface BlobEnvelope {
  /** Collection name */
  c: string;
  /** Schema version */
  v: number;
  /** CRDT Model binary (raw bytes, encoded as CBOR byte string) */
  crdt: Uint8Array;
  /** Serialized edit chain (JSON string). */
  h?: string;
}

/**
 * Result of converting Change[] to RemoteRecord[].
 */
interface ConversionResult {
  records: RemoteRecord[];
  failures: Array<{ id: string; sequence: number; error: Error }>;
}

/**
 * Default padding bucket sizes in bytes.
 * Data is padded to the smallest bucket that fits.
 */
export const DEFAULT_PADDING_BUCKETS = [
  256, 1024, 4096, 16384, 65536, 262144, 1048576,
] as const;

/** Length prefix size for padding (4 bytes, u32 LE). */
const PADDING_LENGTH_PREFIX = 4;

/** Identity for signing edit chain entries. */
export interface EditChainIdentity {
  /** P-256 private key JWK for signing. */
  privateKeyJwk: JsonWebKey;
  /** Author did:key. */
  selfDID: string;
  /** Public key JWK (embedded in each signed entry for self-contained verification). */
  publicKeyJwk: JsonWebKey;
}

export interface LessSyncTransportConfig {
  /** Push function — sends encrypted changes to the server. */
  push: (changes: Change[]) => Promise<PushResult>;
  /** Space ID for AAD binding in encryption */
  spaceId?: string;
  /**
   * Padding bucket sizes in bytes. Data is padded to the smallest bucket that fits.
   * Default: standard buckets (256 to 1MB). Set to empty array to disable padding.
   * Padding is applied before encryption and removed after decryption.
   */
  paddingBuckets?: number[];
  /** Epoch-based forward secrecy configuration. */
  epochConfig?: EpochConfig;
  /** Identity for signing edit chain entries. */
  identity?: EditChainIdentity;
  /** Collections that have edit chain tracking enabled. */
  editChainCollections?: Set<string>;
}

/**
 * Bridges @less-platform/db's SyncTransport interface to the less-sync server.
 *
 * On push: OutboundRecord -> CRDT binary -> BlobEnvelope -> CBOR -> pad -> encrypt(DEK) -> Change{blob, dek}
 * On pull: Change{blob, dek} -> unwrap DEK -> decrypt(DEK) -> unpad -> CBOR -> BlobEnvelope -> RemoteRecord
 *
 * Pull accepts pre-pulled changes from the outer transport for decryption.
 */
export class LessSyncTransport implements SyncTransport {
  private pushFn: (changes: Change[]) => Promise<PushResult>;
  private spaceId?: string;
  private paddingBuckets: number[];
  private epochConfig?: EpochConfig;
  private identity?: EditChainIdentity;
  private editChainCollections?: Set<string>;
  private warnedIdentityMissing = false;

  /** Base KEK (Key Encryption Key) — the key at baseEpoch. Never mutated. */
  private baseKek?: Uint8Array;
  /** Base epoch — the epoch that baseKek corresponds to. Never mutated. */
  private baseEpoch: number;
  /** Encryption epoch — updated after rotation. New records are wrapped at this epoch. */
  private currentEpoch: number;
  /** Derived key cache: epoch → derived KEK. Avoids re-deriving for each record. */
  private derivedKeyCache = new Map<number, Uint8Array>();

  /** Pre-pulled changes set by WSTransport before pull() is called. */
  private prepulledChanges: Change[] | null = null;
  private prepulledSequence: number = 0;

  constructor(config: LessSyncTransportConfig) {
    this.pushFn = config.push;
    this.spaceId = config.spaceId;
    this.paddingBuckets = config.paddingBuckets ?? [...DEFAULT_PADDING_BUCKETS];
    this.epochConfig = config.epochConfig;
    this.identity = config.identity;
    this.editChainCollections = config.editChainCollections;
    this.baseKek = config.epochConfig?.epochKey;
    this.baseEpoch = config.epochConfig?.epoch ?? 0;
    this.currentEpoch = config.epochConfig?.epoch ?? 0;

    if (this.baseKek && !this.spaceId) {
      throw new Error(
        "LessSyncTransport: spaceId is required when epochConfig is provided. " +
          "AAD binding requires spaceId to prevent ciphertext relocation attacks.",
      );
    }
  }

  /** Current epoch number (0 if not using epoch-based encryption). */
  get epoch(): number {
    return this.currentEpoch;
  }

  /**
   * Advance the encryption epoch. New records will be wrapped at this epoch.
   * The base key is unchanged — forward derivation handles decryption of any epoch >= base.
   *
   * Call this after epoch rotation so new records use the latest epoch key.
   * Does NOT change the base key, so records from members who haven't synced
   * (still at an older epoch) remain decryptable.
   */
  updateEncryptionEpoch(epoch: number): void {
    if (epoch > this.currentEpoch) {
      this.currentEpoch = epoch;
    }
  }

  /**
   * Check whether the epoch advance threshold has been exceeded.
   * Returns true if re-encryption should be triggered.
   */
  shouldAdvanceEpoch(): boolean {
    if (!this.epochConfig) return false;
    const interval =
      this.epochConfig.epochAdvanceIntervalMs ??
      DEFAULT_EPOCH_ADVANCE_INTERVAL_MS;
    const advancedAt = this.epochConfig.epochAdvancedAt ?? 0;
    return Date.now() - advancedAt >= interval;
  }

  /**
   * Set pre-pulled changes for the next pull() call.
   * Called by WSTransport after a multiplexed pull.
   */
  setPrepulledChanges(changes: Change[], sequence: number): void {
    this.prepulledChanges = changes;
    this.prepulledSequence = sequence;
  }

  /**
   * Push dirty records to the server.
   */
  async push(
    collection: string,
    records: OutboundRecord[],
  ): Promise<PushAck[]> {
    if (records.length === 0) return [];

    const { changes, failedIds } = this.buildPushChanges(collection, records);

    if (changes.length === 0) return [];

    const pushResult = await this.pushFn(changes);

    if (!pushResult.ok) {
      return [];
    }

    // Only return acks for records that were actually sent
    return this.buildPushAcks(records, failedIds, pushResult.sequence);
  }

  private buildPushChanges(
    collection: string,
    records: OutboundRecord[],
  ): { changes: Change[]; failedIds: Set<string> } {
    const changes: Change[] = [];
    const failedIds = new Set<string>();

    for (const record of records) {
      const change = this.buildChangeForPush(collection, record, failedIds);
      if (change) changes.push(change);
    }

    return { changes, failedIds };
  }

  private buildChangeForPush(
    collection: string,
    record: OutboundRecord,
    failedIds: Set<string>,
  ): Change | null {
    if (record.deleted) {
      return {
        id: record.id,
        blob: null,
        sequence: record.sequence,
      };
    }

    try {
      const envelope: BlobEnvelope = {
        c: collection,
        v: record._v,
        crdt: record.crdt!,
      };

      // Warn once if edit chains are configured but identity is unavailable
      if (
        !this.identity &&
        this.editChainCollections?.has(collection) &&
        !this.warnedIdentityMissing
      ) {
        this.warnedIdentityMissing = true;
        console.warn(
          "[less-sync] editChainCollections configured but identity not available — edit chains will be omitted",
        );
      }

      // Append edit chain entry if this collection is tracked
      if (this.identity && this.editChainCollections?.has(collection)) {
        this.appendEditChainEntry(envelope, record, collection);
      }

      const { blob, wrappedDEK } = this.encryptEnvelope(envelope, record.id);
      return {
        id: record.id,
        blob,
        sequence: record.sequence,
        ...(wrappedDEK ? { dek: wrappedDEK } : {}),
      };
    } catch (err) {
      // Per-record encryption failure (e.g., padding overflow).
      // Skip this record but continue with others.
      failedIds.add(record.id);
      console.error(`Push: encryption failed for record ${record.id}:`, err);
      return null;
    }
  }

  /**
   * Append a signed edit chain entry to the envelope.
   * Computes the diff between the last known server view and the current CRDT view.
   */
  private appendEditChainEntry(
    envelope: BlobEnvelope,
    record: OutboundRecord,
    collection: string,
  ): void {
    const identity = this.identity!;
    const meta = record.meta as Record<string, unknown> | undefined;

    // Read existing chain from meta (treat parse failure as fresh chain)
    const existingChainStr = meta?._editChain as string | undefined;
    let chain: EditEntry[] = [];
    if (existingChainStr) {
      try {
        chain = parseEditChain(existingChainStr);
      } catch {
        console.warn(
          `[less-sync] Edit chain parse failed for ${record.id}; starting fresh chain`,
        );
      }
    }

    // Read last server view baseline
    const lastServerView =
      (meta?._lastServerView as Record<string, unknown>) ?? {};

    // Get current view from CRDT
    let currentView: Record<string, unknown>;
    try {
      const model = Model.fromBinary(envelope.crdt);
      currentView = model.view() as Record<string, unknown>;
    } catch {
      // If CRDT can't be decoded, skip edit chain
      return;
    }

    // Compute diff (creation uses {} baseline for consistent nested-object granularity)
    const diffs = valueDiff(lastServerView, currentView);

    // No changes — carry forward existing chain without new entry
    if (diffs.length === 0) {
      if (existingChainStr) envelope.h = existingChainStr;
      return;
    }

    const prevEntry = chain.length > 0 ? chain[chain.length - 1]! : null;
    const entry = signEditEntry(
      identity.privateKeyJwk,
      identity.publicKeyJwk,
      collection,
      record.id,
      identity.selfDID,
      Date.now(),
      diffs,
      prevEntry,
    );

    chain.push(entry);
    envelope.h = serializeEditChain(chain);
  }

  private buildPushAcks(
    records: OutboundRecord[],
    failedIds: Set<string>,
    sequence: number,
  ): PushAck[] {
    return records
      .filter((record) => !failedIds.has(record.id))
      .map((record) => ({ id: record.id, sequence }));
  }

  /**
   * Pull remote changes since the given sequence.
   *
   * If pre-pulled changes are available (from multiplexed pull),
   * uses those instead of making a network request.
   */
  async pull(collection: string, _since: number): Promise<PullResult> {
    let changes: Change[];
    let spaceSequence: number;

    if (this.prepulledChanges !== null) {
      changes = this.prepulledChanges;
      spaceSequence = this.prepulledSequence;
      this.prepulledChanges = null;
      this.prepulledSequence = 0;
    } else {
      // Fallback: should not happen in normal flow, but allows standalone use
      return { records: [], latestSequence: 0 };
    }

    const result = this.convertChangesToRemoteRecords(changes, collection);

    const pullFailures: PullFailure[] | undefined =
      result.failures.length > 0
        ? result.failures.map((f) => ({
            id: f.id,
            sequence: f.sequence,
            error: f.error,
            retryable: false, // Decryption failures are permanent
          }))
        : undefined;

    if (result.failures.length > 0) {
      const ids = result.failures.map((f) => f.id).join(", ");
      console.error(
        `Failed to decrypt ${result.failures.length} record(s) during pull: ${ids}`,
      );
    }

    return {
      records: result.records,
      latestSequence: spaceSequence,
      failures: pullFailures,
    };
  }

  /**
   * Convert update data to RemoteRecord[] for a specific collection.
   * Used for direct sync event application (fast-path).
   */
  convertSyncEventToRemoteRecords(
    eventData: SyncEventData,
    collection: string,
  ): RemoteRecord[] {
    const result = this.convertChangesToRemoteRecords(
      eventData.records,
      collection,
    );

    if (result.failures.length > 0) {
      const ids = result.failures.map((f) => f.id).join(", ");
      throw new Error(
        `Failed to decrypt ${result.failures.length} record(s) in sync event: ${ids}. ` +
          `Falling back to pull.`,
      );
    }

    return result.records;
  }

  /**
   * Handle a real-time sync event by applying records directly to all collections.
   *
   * @param eventData - The sync notification data
   * @param controller - SyncController to apply records and query sync state
   */
  async applySyncEvent(
    eventData: SyncEventData,
    controller: SyncController,
  ): Promise<SyncResult> {
    const collections = controller.getCollections();
    const first = collections[0];
    if (!first) return { pushed: 0, pulled: 0, merged: 0, errors: [] };

    let currentSeq: number;
    try {
      currentSeq = await controller.getLastSequence(first.name);
    } catch (e) {
      console.error(
        "Sync event: getLastSequence failed, falling back to pull",
        e,
      );
      return this.pullAllCollections(collections, controller);
    }

    // Only apply if prev matches current cursor (no gap)
    if (eventData.prev !== currentSeq) {
      return this.pullAllCollections(collections, controller);
    }

    // Reject stale events
    if (eventData.seq <= currentSeq) {
      return { pushed: 0, pulled: 0, merged: 0, errors: [] };
    }

    // Decrypt all records. Any failure → fall back to pull.
    const decrypted = this.decryptAllChanges(eventData.records);
    if (decrypted === null) {
      return this.pullAllCollections(collections, controller);
    }

    const result: SyncResult = { pushed: 0, pulled: 0, merged: 0, errors: [] };
    for (const def of collections) {
      const records = this.filterRecordsForCollection(decrypted, def.name);
      const applyResult = await controller.applyRemoteRecords(
        def,
        records,
        eventData.seq,
      );
      this.aggregateResult(result, applyResult);
    }
    return result;
  }

  /**
   * Decrypt and apply sync event records without gap/stale detection.
   * The caller (WSTransport) handles gap/stale checks using per-space cursors.
   */
  async decryptAndApply(
    eventData: SyncEventData,
    controller: SyncController,
  ): Promise<SyncResult> {
    const collections = controller.getCollections();

    // Decrypt all records. Any failure → fall back to pull.
    const decrypted = this.decryptAllChanges(eventData.records);
    if (decrypted === null) {
      return this.pullAllCollections(collections, controller);
    }

    const result: SyncResult = { pushed: 0, pulled: 0, merged: 0, errors: [] };
    for (const def of collections) {
      const records = this.filterRecordsForCollection(decrypted, def.name);
      const applyResult = await controller.applyRemoteRecords(
        def,
        records,
        eventData.seq,
      );
      this.aggregateResult(result, applyResult);
    }
    return result;
  }

  /**
   * Pull all collections. Used as the fallback when sync event fast-path can't apply.
   */
  private async pullAllCollections(
    collections: readonly CollectionDef[],
    controller: SyncController,
  ): Promise<SyncResult> {
    const result: SyncResult = { pushed: 0, pulled: 0, merged: 0, errors: [] };
    for (const def of collections) {
      const pullResult = await controller.pull(def);
      this.aggregateResult(result, pullResult);
    }
    return result;
  }

  /**
   * Decrypt and unwrap all changes. Returns null on any failure.
   */
  private decryptAllChanges(changes: Change[]): Array<{
    id: string;
    envelope: BlobEnvelope | null;
    sequence: number;
  }> | null {
    const results: Array<{
      id: string;
      envelope: BlobEnvelope | null;
      sequence: number;
    }> = [];

    for (const change of changes) {
      if (change.deleted ?? change.blob === null) {
        results.push({
          id: change.id,
          envelope: null,
          sequence: change.sequence,
        });
        continue;
      }

      try {
        const envelope = this.decryptEnvelope(
          change.blob!,
          change.id,
          change.dek,
        );
        results.push({ id: change.id, envelope, sequence: change.sequence });
      } catch (e) {
        console.error(
          `Sync event: decryption failed for record ${change.id}, falling back to pull`,
          e,
        );
        return null;
      }
    }

    return results;
  }

  private filterRecordsForCollection(
    decrypted: Array<{
      id: string;
      envelope: BlobEnvelope | null;
      sequence: number;
    }>,
    collection: string,
  ): RemoteRecord[] {
    const baseMeta = this.spaceId ? { spaceId: this.spaceId } : undefined;
    const records: RemoteRecord[] = [];
    for (const item of decrypted) {
      if (item.envelope === null) {
        records.push({
          id: item.id,
          _v: 1,
          crdt: null,
          deleted: true,
          sequence: item.sequence,
          meta: baseMeta,
        });
      } else if (item.envelope.c === collection) {
        records.push({
          id: item.id,
          _v: item.envelope.v,
          crdt: item.envelope.crdt,
          deleted: false,
          sequence: item.sequence,
          meta: this.buildPullMeta(
            item.envelope,
            item.id,
            collection,
            baseMeta,
          ),
        });
      }
    }
    return records;
  }

  private aggregateResult(target: SyncResult, source: SyncResult): void {
    target.pulled += source.pulled;
    target.merged += source.merged;
    target.errors.push(...source.errors);
  }

  /**
   * Build meta for a pulled record, including edit chain and last server view.
   */
  private buildPullMeta(
    envelope: BlobEnvelope,
    recordId: string,
    collection: string,
    baseMeta?: Record<string, unknown>,
  ): Record<string, unknown> | undefined {
    if (!envelope.h) return baseMeta;

    // Extract edit chain and compute current server view for next push baseline
    let lastServerView: Record<string, unknown> | undefined;
    try {
      const model = Model.fromBinary(envelope.crdt);
      lastServerView = model.view() as Record<string, unknown>;
    } catch {
      // Can't decode CRDT — still pass through the chain
    }

    // Verify chain integrity — store result in meta so app code can observe it
    let editChainValid = false;
    try {
      const chain = parseEditChain(envelope.h);
      editChainValid = verifyEditChain(chain, collection, recordId);
      if (!editChainValid) {
        console.warn(
          `[less-sync] Edit chain integrity check failed for record ${recordId}`,
        );
      }
    } catch (err) {
      console.warn(
        `[less-sync] Edit chain parse/verify error for record ${recordId}:`,
        err,
      );
    }

    return {
      ...baseMeta,
      _editChain: envelope.h,
      _editChainValid: editChainValid,
      ...(lastServerView !== undefined
        ? { _lastServerView: lastServerView }
        : {}),
    };
  }

  private convertChangesToRemoteRecords(
    changes: Change[],
    collection: string,
  ): ConversionResult {
    const baseMeta = this.spaceId ? { spaceId: this.spaceId } : undefined;
    const records: RemoteRecord[] = [];
    const failures: Array<{ id: string; sequence: number; error: Error }> = [];

    for (const change of changes) {
      if (change.deleted ?? change.blob === null) {
        records.push({
          id: change.id,
          _v: 1,
          crdt: null,
          deleted: true,
          sequence: change.sequence,
          meta: baseMeta,
        });
        continue;
      }

      let envelope: BlobEnvelope;
      try {
        envelope = this.decryptEnvelope(change.blob!, change.id, change.dek);
      } catch (err) {
        const message =
          err instanceof Error
            ? err.message
            : typeof err === "string"
              ? err
              : `Unknown error: ${JSON.stringify(err)}`;
        failures.push({
          id: change.id,
          sequence: change.sequence,
          error: new Error(message),
        });
        continue;
      }

      if (envelope.c !== collection) continue;

      records.push({
        id: change.id,
        _v: envelope.v,
        crdt: envelope.crdt,
        deleted: false,
        sequence: change.sequence,
        meta: this.buildPullMeta(envelope, change.id, collection, baseMeta),
      });
    }

    return { records, failures };
  }

  /**
   * Encrypt an envelope using a fresh per-record DEK.
   * Returns the encrypted blob and the wrapped DEK.
   */
  private encryptEnvelope(
    envelope: BlobEnvelope,
    recordId: string,
  ): { blob: Uint8Array; wrappedDEK?: Uint8Array } {
    const bytes = cborEncode(envelope);
    const padded = this.pad(bytes);

    if (this.baseKek) {
      // spaceId is guaranteed by constructor when kek is set
      const context = { spaceId: this.spaceId!, recordId };
      const encryptKey = this.getKEKForEpoch(this.currentEpoch);
      const dek = generateDEK();
      try {
        const blob = encryptV4(padded, dek, context);
        const wrappedDEK = wrapDEK(dek, encryptKey, this.currentEpoch);
        return { blob, wrappedDEK };
      } finally {
        dek.fill(0); // Zero plaintext DEK after use
      }
    }

    return { blob: padded };
  }

  /**
   * Maximum number of epoch steps to derive forward.
   * Prevents DoS from a malicious server sending a very high epoch number.
   * 1000 epochs at 30-day intervals covers ~82 years.
   */
  private static readonly MAX_EPOCH_ADVANCE = 1000;

  /**
   * Derive the KEK for a given epoch via forward derivation from the base key.
   *
   * Uses a non-destructive cache: the base key is never mutated, so keys for
   * ANY epoch >= baseEpoch can be derived. This is essential for shared spaces
   * where records from different members may arrive at different epochs.
   */
  private getKEKForEpoch(dekEpoch: number): Uint8Array {
    if (!this.baseKek || !this.spaceId) {
      throw new Error(`No KEK available for epoch ${dekEpoch}`);
    }

    // Fast path: exact match with base epoch
    if (dekEpoch === this.baseEpoch) {
      return this.baseKek;
    }

    // Can't derive backward from base
    if (dekEpoch < this.baseEpoch) {
      throw new Error(
        `Cannot derive KEK for epoch ${dekEpoch} (base: ${this.baseEpoch}). Forward secrecy prevents backward derivation.`,
      );
    }

    // Check cache
    const cached = this.derivedKeyCache.get(dekEpoch);
    if (cached) return cached;

    const distance = dekEpoch - this.baseEpoch;
    if (distance > LessSyncTransport.MAX_EPOCH_ADVANCE) {
      throw new Error(
        `Epoch ${dekEpoch} is too far ahead of base epoch ${this.baseEpoch} ` +
          `(distance: ${distance}, max: ${LessSyncTransport.MAX_EPOCH_ADVANCE}). ` +
          `This may indicate a corrupted or malicious wrapped DEK.`,
      );
    }

    // Derive forward from raw bytes
    let key: Uint8Array = this.baseKek;
    for (let e = this.baseEpoch + 1; e <= dekEpoch; e++) {
      const existing = this.derivedKeyCache.get(e);
      if (existing) {
        key = existing;
      } else {
        key = deriveNextEpochKey(key, this.spaceId, e);
        this.derivedKeyCache.set(e, key);
      }
    }

    return key;
  }

  /**
   * Decrypt an envelope using the record's DEK.
   */
  private decryptEnvelope(
    blob: Uint8Array,
    recordId: string,
    wrappedDEKBytes?: Uint8Array,
  ): BlobEnvelope {
    const raw = this.decryptBlob(blob, recordId, wrappedDEKBytes);
    const decrypted = this.unpad(raw);
    return this.decodeEnvelope(decrypted);
  }

  private decryptBlob(
    blob: Uint8Array,
    recordId: string,
    wrappedDEKBytes?: Uint8Array,
  ): Uint8Array {
    if (this.baseKek && wrappedDEKBytes) {
      // spaceId is guaranteed by constructor when kek is set
      const context = { spaceId: this.spaceId!, recordId };

      // Peek at epoch from wrapped DEK prefix (first 4 bytes, u32 BE)
      const dekEpoch = new DataView(
        wrappedDEKBytes.buffer,
        wrappedDEKBytes.byteOffset,
        wrappedDEKBytes.byteLength,
      ).getUint32(0, false);

      // Unwrap DEK — may need to derive KEK forward if epoch is newer
      const { dek, epoch: _dekEpoch } = unwrapDEK(
        wrappedDEKBytes,
        this.getKEKForEpoch(dekEpoch),
      );

      try {
        return decryptV4(blob, dek, context);
      } finally {
        dek.fill(0); // Zero plaintext DEK after use
      }
    }

    if (!this.baseKek) {
      // No encryption configured
      return blob;
    }

    throw new Error("Missing wrapped DEK for encrypted record");
  }

  private decodeEnvelope(decrypted: Uint8Array): BlobEnvelope {
    let parsed: unknown;
    try {
      parsed = cborDecode(decrypted);
    } catch {
      throw new Error(
        `Failed to decode CBOR envelope (${decrypted.length} bytes)`,
      );
    }

    const obj = parsed as Record<string, unknown>;
    if (
      parsed === null ||
      typeof parsed !== "object" ||
      !("c" in obj) ||
      !("v" in obj) ||
      !("crdt" in obj) ||
      typeof obj.c !== "string" ||
      typeof obj.v !== "number" ||
      !(obj.crdt instanceof Uint8Array)
    ) {
      throw new Error(
        `Invalid envelope structure: expected {c: string, v: number, crdt: Uint8Array}, ` +
          `got {c: ${typeof obj.c}, v: ${typeof obj.v}, crdt: ${obj.crdt?.constructor?.name ?? typeof obj.crdt}}`,
      );
    }

    const envelope: BlobEnvelope = {
      c: obj.c as string,
      v: obj.v as number,
      crdt: new Uint8Array(obj.crdt),
    };
    if (typeof obj.h === "string") {
      envelope.h = obj.h;
    }
    return envelope;
  }

  /**
   * Pad data to a fixed-size bucket.
   * Format: [4 bytes: u32 LE length][data][zero padding]
   * If no buckets are configured, returns the data with length prefix only.
   */
  private pad(data: Uint8Array): Uint8Array {
    if (this.paddingBuckets.length === 0) {
      return data;
    }

    const totalNeeded = PADDING_LENGTH_PREFIX + data.length;
    let bucketSize = 0;
    for (const bucket of this.paddingBuckets) {
      if (bucket >= totalNeeded) {
        bucketSize = bucket;
        break;
      }
    }
    if (bucketSize === 0) {
      throw new Error(
        `Data too large for padding: ${data.length} bytes exceeds max bucket ${this.paddingBuckets[this.paddingBuckets.length - 1]}`,
      );
    }

    const padded = new Uint8Array(bucketSize);
    // Write length prefix (u32 LE)
    const view = new DataView(
      padded.buffer,
      padded.byteOffset,
      padded.byteLength,
    );
    view.setUint32(0, data.length, true);
    padded.set(data, PADDING_LENGTH_PREFIX);
    // Remaining bytes are already zero
    return padded;
  }

  /**
   * Remove padding from data.
   * Reads the 4-byte length prefix and extracts the original data.
   * If no buckets are configured, returns the data as-is.
   */
  private unpad(data: Uint8Array): Uint8Array {
    if (this.paddingBuckets.length === 0) {
      return data;
    }

    if (data.length < PADDING_LENGTH_PREFIX) {
      throw new Error(`Padded data too short: ${data.length} bytes`);
    }

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const originalLength = view.getUint32(0, true);

    if (originalLength > data.length - PADDING_LENGTH_PREFIX) {
      throw new Error(
        `Invalid padding: claimed length ${originalLength} exceeds available data ${data.length - PADDING_LENGTH_PREFIX}`,
      );
    }

    return data.slice(
      PADDING_LENGTH_PREFIX,
      PADDING_LENGTH_PREFIX + originalLength,
    );
  }
}
