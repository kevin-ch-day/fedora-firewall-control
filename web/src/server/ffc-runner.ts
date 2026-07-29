import { execFile as execFileCallback } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { promisify } from "node:util";

import {
  EXECUTION_TIMEOUT_MS,
  MAX_STDERR_BYTES,
  MAX_STDOUT_BYTES,
  REPOSITORY_ROOT,
} from "./config.js";
import { ApiError, sanitizeDiagnostic } from "./errors.js";

const execFile = promisify(execFileCallback);

export interface FfcRunnerOptions {
  readonly timeoutMs?: number;
  readonly maxStdoutBytes?: number;
  readonly maxStderrBytes?: number;
  readonly repositoryRoot?: string;
  readonly environment?: NodeJS.ProcessEnv;
  readonly diagnosticLogger?: (message: string) => void;
}

export interface FfcRunResult {
  readonly stdout: string;
}

interface ExecFileFailure extends Error {
  readonly code?: string | number;
  readonly killed?: boolean;
  readonly signal?: NodeJS.Signals;
  readonly stdout?: string | Buffer;
  readonly stderr?: string | Buffer;
}

function isExecFileFailure(value: unknown): value is ExecFileFailure {
  return value instanceof Error;
}

function diagnosticFromFailure(error: ExecFileFailure): string {
  const stderr = error.stderr === undefined ? "" : String(error.stderr);
  return sanitizeDiagnostic(stderr.length > 0 ? stderr : error.message);
}

function boundedEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {
    PATH: "/usr/bin:/bin",
    LANG: "C",
    LC_ALL: "C",
  };
  for (const key of [
    "HOME",
    "USER",
    "LOGNAME",
    "XDG_CONFIG_HOME",
    "XDG_STATE_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
  ] as const) {
    const value = source[key];
    if (value !== undefined) {
      environment[key] = value;
    }
  }
  return environment;
}

export async function resolveFfcExecutable(candidate: string): Promise<string> {
  if (!isAbsolute(candidate) || candidate.includes("\0") || /[\r\n]/u.test(candidate)) {
    throw new ApiError("ffc_unavailable", 503, {
      diagnostic: "FFC_BIN must be one absolute path without control characters.",
    });
  }

  let canonical: string;
  try {
    canonical = await realpath(candidate);
  } catch (error: unknown) {
    throw new ApiError("ffc_unavailable", 503, {
      cause: error,
      diagnostic: sanitizeDiagnostic(error),
    });
  }

  try {
    const metadata = await stat(canonical);
    if (!metadata.isFile() || (metadata.mode & 0o002) !== 0) {
      throw new ApiError("ffc_unavailable", 503, {
        diagnostic: "FFC executable is not a regular trusted file.",
      });
    }
    await access(canonical, fsConstants.X_OK);
  } catch (error: unknown) {
    if (error instanceof ApiError) {
      throw error;
    }
    const code = isExecFileFailure(error) ? error.code : undefined;
    throw new ApiError(code === "EACCES" ? "ffc_permission_denied" : "ffc_unavailable", 503, {
      cause: error,
      diagnostic: sanitizeDiagnostic(error),
    });
  }
  return canonical;
}

export class FfcRunner {
  readonly #executable: string;
  readonly #timeoutMs: number;
  readonly #maxStdoutBytes: number;
  readonly #maxStderrBytes: number;
  readonly #repositoryRoot: string;
  readonly #environment: NodeJS.ProcessEnv;
  readonly #diagnosticLogger: (message: string) => void;

  public constructor(executable: string, options: FfcRunnerOptions = {}) {
    this.#executable = executable;
    this.#timeoutMs = options.timeoutMs ?? EXECUTION_TIMEOUT_MS;
    this.#maxStdoutBytes = options.maxStdoutBytes ?? MAX_STDOUT_BYTES;
    this.#maxStderrBytes = options.maxStderrBytes ?? MAX_STDERR_BYTES;
    this.#repositoryRoot = options.repositoryRoot ?? REPOSITORY_ROOT;
    this.#environment = boundedEnvironment(options.environment ?? process.env);
    this.#diagnosticLogger = options.diagnosticLogger ?? ((message) => console.error(message));
  }

  public async runSnapshot(): Promise<FfcRunResult> {
    try {
      const result = await execFile(this.#executable, ["--snapshot-json"], {
        cwd: this.#repositoryRoot,
        encoding: "utf8",
        env: this.#environment,
        timeout: this.#timeoutMs,
        killSignal: "SIGKILL",
        maxBuffer: Math.max(this.#maxStdoutBytes, this.#maxStderrBytes),
        windowsHide: true,
      });
      const stdout = String(result.stdout);
      const stderr = String(result.stderr);
      if (Buffer.byteLength(stdout, "utf8") > this.#maxStdoutBytes) {
        throw new ApiError("ffc_output_limit", 502);
      }
      if (Buffer.byteLength(stderr, "utf8") > this.#maxStderrBytes) {
        throw new ApiError("ffc_output_limit", 502);
      }
      if (stderr.trim().length > 0) {
        this.#diagnosticLogger(`FFC snapshot diagnostic: ${sanitizeDiagnostic(stderr)}`);
      }
      if (stdout.trim().length === 0) {
        throw new ApiError("ffc_empty_output", 502);
      }
      return { stdout };
    } catch (error: unknown) {
      if (error instanceof ApiError) {
        throw error;
      }
      if (!isExecFileFailure(error)) {
        throw new ApiError("ffc_failed", 503, { cause: error });
      }
      const diagnostic = diagnosticFromFailure(error);
      this.#diagnosticLogger(`FFC snapshot failed: ${diagnostic}`);
      if (error.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" || /maxBuffer/iu.test(error.message)) {
        throw new ApiError("ffc_output_limit", 502, { cause: error, diagnostic });
      }
      if (error.killed === true || error.signal === "SIGKILL") {
        throw new ApiError("ffc_timeout", 504, { cause: error, diagnostic });
      }
      if (error.code === "ENOENT") {
        throw new ApiError("ffc_unavailable", 503, { cause: error, diagnostic });
      }
      if (error.code === "EACCES") {
        throw new ApiError("ffc_permission_denied", 503, { cause: error, diagnostic });
      }
      throw new ApiError("ffc_failed", 503, { cause: error, diagnostic });
    }
  }
}
