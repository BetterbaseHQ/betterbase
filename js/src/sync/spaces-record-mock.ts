/**
 * 1:1 JS mirror of `betterbase-sync-core::spaces::parse_spaces_record` for
 * node tests and the node fallback path (node tests never run wasm — see
 * `rotation-mock.ts` for the established pattern).
 *
 * This mirror must reproduce the Rust parser line-for-line: the check
 * order (unknown fields alphabetically, required fields in declaration
 * order, enum values, then field types — with `membershipLogSeq` before
 * `members`), the acceptance rules (integer-valued counters in any notation
 * up to 2^53 − 1; lenient optional scalars), and the exact error strings.
 * The committed vectors
 * (`crates/betterbase-sync-core/test-vectors/spaces-record.json`) pin this
 * mirror, the Rust parser, and the real wasm
 * (`browser-tests/sync/spaces-record.test.ts`) to the same contract.
 */

const SPACES_FIELDS: readonly string[] = [
  "spaceId",
  "name",
  "status",
  "role",
  "invitedBy",
  "spaceKey",
  "ucanChain",
  "rootPublicKey",
  "serverInvitationId",
  "epoch",
  "epochAdvancedAt",
  "members",
  "membershipLogSeq",
];

const REQUIRED_FIELDS = [
  "spaceId",
  "name",
  "status",
  "role",
  "spaceKey",
  "ucanChain",
  "rootPublicKey",
  "epoch",
] as const;

/** Counter fields are capped at JS Number.MAX_SAFE_INTEGER (2^53 - 1) so
 * acceptance matches the Rust `MAX_COUNTER`. */
const MAX_COUNTER = Number.MAX_SAFE_INTEGER;

const ERR = (msg: string) => new Error(`invalid __spaces record: ${msg}`);

function valueList(values: readonly string[]): string {
  return values
    .map((v, i) =>
      i === 0 ? `'${v}'` : i === values.length - 1 ? `, or '${v}'` : `, '${v}'`,
    )
    .join("");
}

function enumMessage(field: string, values: readonly string[]): string {
  return `field '${field}' must be ${valueList(values)}`;
}

const STATUSES: readonly string[] = ["invited", "active", "removed"];
const ROLES: readonly string[] = ["admin", "write", "read"];
const MEMBER_STATUSES: readonly string[] = [
  "joined",
  "pending",
  "declined",
  "revoked",
];
const MEMBER_FIELDS: readonly string[] = ["did", "role", "status", "handle"];

function isString(v: unknown): v is string {
  return typeof v === "string";
}

/**
 * Code-point-order comparison — matches Rust's byte-wise `String` sort (UTF-8
 * byte order == code-point order). `Array.prototype.sort`'s default compares
 * UTF-16 code units, which differs for astral (U+10000+) vs U+E000–U+FFFF
 * names; the contract is "exact error strings", so pin the order here.
 */
function codePointCompare(a: string, b: string): number {
  const aCp = Array.from(a);
  const bCp = Array.from(b);
  const len = Math.min(aCp.length, bCp.length);
  for (let i = 0; i < len; i++) {
    const d = (aCp[i]!.codePointAt(0) ?? 0) - (bCp[i]!.codePointAt(0) ?? 0);
    if (d !== 0) return d;
  }
  return aCp.length - bCp.length;
}

function unknownFields(
  obj: Record<string, unknown>,
  known: readonly string[],
): string | null {
  const unknown = Object.keys(obj).filter((k) => !known.includes(k));
  unknown.sort(codePointCompare);
  return unknown[0] ?? null;
}

function requireString(obj: Record<string, unknown>, name: string): string {
  const v = obj[name];
  if (!isString(v)) throw ERR(`field '${name}' must be a string`);
  return v;
}

/** Lenient optional: null or a non-string value reads as absent. */
function optString(
  obj: Record<string, unknown>,
  name: string,
): string | undefined {
  const v = obj[name];
  return v !== undefined && v !== null && isString(v) ? v : undefined;
}

function parseCounter(
  obj: Record<string, unknown>,
  name: string,
  required: boolean,
): number | undefined {
  const v = obj[name];
  if (v === undefined || v === null) {
    if (required) throw ERR(`missing required field '${name}'`);
    return undefined;
  }
  if (
    typeof v !== "number" ||
    !Number.isInteger(v) ||
    v < 0 ||
    v > MAX_COUNTER
  ) {
    throw ERR(`field '${name}' must be a non-negative integer`);
  }
  return v;
}

export interface ParsedSpacesMember {
  did: string;
  role: string;
  status: string;
  handle?: string;
}

export interface ParsedSpacesRecord {
  spaceId: string;
  name: string;
  status: string;
  role: string;
  invitedBy?: string;
  spaceKey: string;
  ucanChain: string;
  rootPublicKey: string;
  serverInvitationId?: string;
  epoch: number;
  epochAdvancedAt?: number;
  members?: ParsedSpacesMember[];
  membershipLogSeq?: number;
}

/**
 * 1:1 mirror of `parse_spaces_record`. Throws `Error` with the exact Rust
 * message on any contract violation.
 */
export function parseSpacesRecordMirror(json: string): ParsedSpacesRecord {
  const v: unknown = JSON.parse(json); // malformed JSON: engine-specific message, not pinned
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw ERR("record must be a JSON object");
  }
  const obj = v as Record<string, unknown>;

  // Unknown fields — Rust reports the alphabetically first one (deterministic
  // regardless of JSON key order / serde_json feature flags).
  const unknown = unknownFields(obj, SPACES_FIELDS);
  if (unknown !== null) {
    throw ERR(`unknown field '${unknown}'`);
  }
  for (const field of REQUIRED_FIELDS) {
    if (!(field in obj)) {
      throw ERR(`missing required field '${field}'`);
    }
  }

  // Enum values (checked before field types, matching Rust).
  if (!STATUSES.includes(obj["status"] as string)) {
    throw ERR(enumMessage("status", STATUSES));
  }
  if (!ROLES.includes(obj["role"] as string)) {
    throw ERR(enumMessage("role", ROLES));
  }

  // Field types, in the Rust struct's construction order.
  const spaceId = requireString(obj, "spaceId");
  const name = requireString(obj, "name");
  const spaceKey = requireString(obj, "spaceKey");
  const ucanChain = requireString(obj, "ucanChain");
  const rootPublicKey = requireString(obj, "rootPublicKey");
  const epoch = parseCounter(obj, "epoch", true) as number;
  const epochAdvancedAt = parseCounter(obj, "epochAdvancedAt", false);
  const membershipLogSeq = parseCounter(obj, "membershipLogSeq", false);

  const record: ParsedSpacesRecord = {
    spaceId,
    name,
    status: obj["status"] as string,
    role: obj["role"] as string,
    spaceKey,
    ucanChain,
    rootPublicKey,
    epoch,
  };
  const invitedBy = optString(obj, "invitedBy");
  if (invitedBy !== undefined) record.invitedBy = invitedBy;
  const serverInvitationId = optString(obj, "serverInvitationId");
  if (serverInvitationId !== undefined)
    record.serverInvitationId = serverInvitationId;
  if (epochAdvancedAt !== undefined) record.epochAdvancedAt = epochAdvancedAt;
  if (membershipLogSeq !== undefined)
    record.membershipLogSeq = membershipLogSeq;

  if (obj["members"] !== undefined && obj["members"] !== null) {
    const arr = obj["members"];
    if (!Array.isArray(arr)) throw ERR("field 'members' must be an array");
    const parsed: ParsedSpacesMember[] = [];
    for (let i = 0; i < arr.length; i++) {
      const m = arr[i];
      if (typeof m !== "object" || m === null || Array.isArray(m)) {
        throw ERR(`members[${i}] must be an object`);
      }
      const mobj = m as Record<string, unknown>;
      const memberUnknown = unknownFields(mobj, MEMBER_FIELDS);
      if (memberUnknown !== null) {
        throw ERR(`members[${i}]: unknown field '${memberUnknown}'`);
      }
      for (const field of ["did", "role", "status"]) {
        if (!(field in mobj)) {
          throw ERR(`members[${i}]: missing required field '${field}'`);
        }
      }
      const did = mobj["did"];
      if (!isString(did)) {
        throw ERR(`members[${i}]: field 'did' must be a string`);
      }
      if (!ROLES.includes(mobj["role"] as string)) {
        throw ERR(`members[${i}]: ${enumMessage("role", ROLES)}`);
      }
      if (!MEMBER_STATUSES.includes(mobj["status"] as string)) {
        throw ERR(`members[${i}]: ${enumMessage("status", MEMBER_STATUSES)}`);
      }
      const handle = optString(mobj, "handle");
      parsed.push({
        did,
        role: mobj["role"] as string,
        status: mobj["status"] as string,
        ...(handle !== undefined ? { handle } : {}),
      });
    }
    record.members = parsed;
  }

  return record;
}
