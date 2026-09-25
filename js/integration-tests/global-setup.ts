/**
 * Node-side setup for the SDK integration suite.
 *
 * Browser tests cannot exec docker or read container logs, so this
 * globalSetup runs in Node and provides two things over a localhost
 * sidecar:
 *
 *   GET /config        — stack availability, URLs, harness OAuth client id
 *   GET /code?email=…  — email verification codes polled from the accounts
 *                        container log (SMTP_DEV_MODE prints them)
 *
 * It also ensures the harness OAuth client exists (created via the
 * accounts image's `oauth-client` CLI, same mechanism as the examples'
 * setup-clients.sh). When the stack is down the sidecar still runs and
 * reports unavailable — tests skip instead of failing.
 */

import { execFile } from "node:child_process";
import { createServer, type Server } from "node:http";
import { setTimeout as sleep } from "node:timers/promises";

const ACCOUNTS_URL =
  process.env.BB_INTEGRATION_ACCOUNTS ?? "http://localhost:25377";
const SYNC_URL =
  process.env.BB_INTEGRATION_SYNC ?? "http://localhost:25379/api/v1";
const SIDECAR_PORT = Number(process.env.BB_INTEGRATION_SIDECAR ?? 25499);
const ACCOUNTS_CONTAINER =
  process.env.BB_INTEGRATION_ACCOUNTS_CONTAINER ?? "betterbase-e2e-accounts-1";
const CLIENT_NAME = "sdk-integration";
const CLIENT_REDIRECT = "http://localhost:25400/";
const CLIENT_SCOPES = ["sync", "files"];

interface StackConfig {
  available: boolean;
  reason?: string;
  accountsUrl: string;
  syncUrl: string;
  clientId?: string;
  /** PID of the Node process owning this sidecar (zombie detection). */
  ownerPid?: number;
}

function exec(
  cmd: string,
  args: string[],
  timeoutMs = 15_000,
): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs }, (err, stdout, stderr) => {
      resolve({ ok: !err, stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

async function probe(url: string, timeoutMs = 3_000): Promise<boolean> {
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await fetch(`${url}/health`, { signal: ac.signal });
      return res.ok;
    } finally {
      clearTimeout(t);
    }
  } catch {
    return false;
  }
}

/** Idempotent harness client registration via the accounts CLI. */
async function ensureOAuthClient(): Promise<string | undefined> {
  const list = await exec("docker", [
    "exec",
    ACCOUNTS_CONTAINER,
    "/app/oauth-client",
    "list",
  ]);
  if (!list.ok) {
    console.warn(
      `[sdk-integration] oauth-client list failed: ${list.stderr.trim()}`,
    );
    return undefined;
  }
  let clientId: string | undefined;
  let current: string | undefined;
  for (const line of list.stdout.split("\n")) {
    if (line.startsWith("ID:")) current = line.slice(3).trim();
    if (line.startsWith("Name:") && line.slice(5).trim() === CLIENT_NAME) {
      clientId = current;
    }
  }
  if (clientId) return clientId;

  const create = await exec("docker", [
    "exec",
    ACCOUNTS_CONTAINER,
    "/app/oauth-client",
    "create",
    "--name",
    CLIENT_NAME,
    "--redirect-uri",
    CLIENT_REDIRECT,
    ...CLIENT_SCOPES.flatMap((s) => ["--scope", s]),
  ]);
  if (!create.ok) {
    console.warn(
      `[sdk-integration] client create failed: ${create.stderr.trim()}`,
    );
    return undefined;
  }
  const m = create.stdout.match(/^Client ID:\s*(\S+)/m);
  return m?.[1];
}

/** Poll the accounts container log for the verification code sent to email. */
async function findCode(
  email: string,
  budgetMs: number,
): Promise<string | null> {
  // The [\s\S] gap is bounded by a negative lookahead so a message for a
  // DIFFERENT recipient cannot be crossed (concurrent provisions interleave
  // in the container log).
  const pattern = new RegExp(
    `To: ${email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:(?!To:)[\\s\\S])*?Your verification code is: (\\d{6})`,
  );
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    const logs = await exec(
      "docker",
      ["logs", "--since", "3m", ACCOUNTS_CONTAINER],
      10_000,
    );
    const m = logs.stdout.match(pattern);
    if (m?.[1]) return m[1];
    await sleep(500);
  }
  return null;
}

export async function setup(): Promise<() => Promise<void>> {
  const config: StackConfig = {
    available: false,
    accountsUrl: ACCOUNTS_URL,
    syncUrl: SYNC_URL,
  };

  // The sync API base carries a path (/api/v1) but health sits at the root
  const syncOrigin = new URL(SYNC_URL).origin;
  const accountsUp = await probe(ACCOUNTS_URL);
  const syncUp = await probe(syncOrigin);
  if (accountsUp && syncUp) {
    const clientId = await ensureOAuthClient();
    if (clientId) {
      config.available = true;
      config.clientId = clientId;
    } else {
      config.reason =
        "stack is up but the harness OAuth client could not be registered";
    }
  } else {
    config.reason = `stack not reachable (accounts: ${accountsUp}, sync: ${syncUp}) — start it with \`just e2e-up\``;
  }

  config.ownerPid = process.pid;
  if (!config.available) {
    console.warn(`[sdk-integration] skipping: ${config.reason}`);
  }

  let server: Server | null = null;
  server = createServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    if (req.method === "OPTIONS") {
      res.writeHead(204).end();
      return;
    }
    const url = new URL(req.url ?? "/", `http://localhost:${SIDECAR_PORT}`);
    if (url.pathname === "/config") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(config));
      return;
    }
    if (url.pathname === "/code") {
      const email = url.searchParams.get("email");
      if (!email) {
        res.writeHead(400).end("email required");
        return;
      }
      void findCode(email, 30_000).then((code) => {
        if (code) {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ code }));
        } else {
          res.writeHead(404).end("code not found in container logs");
        }
      });
      return;
    }
    res.writeHead(404).end();
  });

  await new Promise<void>((resolve) => {
    server!.once("error", async (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        try {
          const res = await fetch(`http://127.0.0.1:${SIDECAR_PORT}/config`);
          const existing = (await res.json()) as StackConfig;
          // A crashed run can leave a zombie sidecar holding the port
          // with a stale config — reuse only a LIVE owner's sidecar.
          const ownerAlive = existing.ownerPid
            ? process.kill(existing.ownerPid, 0) === true
            : false;
          if (res.ok && ownerAlive) {
            // Same-run second globalSetup invocation (browser
            // environments): reuse the healthy sidecar.
            console.log("[sdk-integration] reusing live sidecar");
            resolve();
            return;
          }
          if (existing.ownerPid) {
            console.warn(
              "[sdk-integration] stale sidecar (owner gone) holds the port; run `lsof -ti :25499 | xargs kill` and retry",
            );
          }
        } catch {
          // No healthy sidecar answered — fall through to the hard error.
        }
      }
      throw err;
    });
    server!.listen(SIDECAR_PORT, "127.0.0.1", () => resolve());
  });
  console.log(
    `[sdk-integration] sidecar on http://127.0.0.1:${SIDECAR_PORT} (available: ${config.available})`,
  );

  return async () => {
    await new Promise<void>((resolve) => {
      if (!server) return resolve();
      server.close(() => resolve());
    });
  };
}
