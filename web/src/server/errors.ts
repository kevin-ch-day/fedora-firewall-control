export type ApiErrorCode =
  | "ffc_unavailable"
  | "ffc_permission_denied"
  | "ffc_failed"
  | "ffc_timeout"
  | "ffc_output_limit"
  | "ffc_empty_output"
  | "ffc_malformed_output"
  | "ffc_schema_invalid"
  | "server_initialization_failed";

const SAFE_MESSAGES: Readonly<Record<ApiErrorCode, string>> = {
  ffc_unavailable: "The native posture service is unavailable.",
  ffc_permission_denied: "The native posture service cannot be executed.",
  ffc_failed: "The native posture snapshot could not be collected.",
  ffc_timeout: "The native posture snapshot did not complete in time.",
  ffc_output_limit: "The native posture snapshot exceeded its output limit.",
  ffc_empty_output: "The native posture service returned no snapshot.",
  ffc_malformed_output: "The native posture service returned malformed data.",
  ffc_schema_invalid: "The native posture snapshot failed validation.",
  server_initialization_failed: "The web API could not initialize.",
};

export class ApiError extends Error {
  public readonly code: ApiErrorCode;
  public readonly statusCode: number;
  public readonly diagnostic?: string;

  public constructor(
    code: ApiErrorCode,
    statusCode: number,
    options: { cause?: unknown; diagnostic?: string } = {},
  ) {
    super(SAFE_MESSAGES[code], { cause: options.cause });
    this.name = "ApiError";
    this.code = code;
    this.statusCode = statusCode;
    if (options.diagnostic !== undefined) {
      this.diagnostic = options.diagnostic;
    }
  }
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}

export function sanitizeDiagnostic(value: unknown, limit = 2_048): string {
  const source = value instanceof Error ? value.message : String(value);
  const printable = source
    .replaceAll(/\x1B\[[0-?]*[ -/]*[@-~]/gu, "")
    .replaceAll(/[^\t\n\r\x20-\x7E]/gu, "?")
    .replaceAll(/[\r\n]+/gu, " ")
    .trim();
  return printable.length <= limit ? printable : `${printable.slice(0, limit)} [truncated]`;
}

export function errorDocument(error: ApiError): {
  error: { code: ApiErrorCode; message: string };
} {
  return { error: { code: error.code, message: error.message } };
}
