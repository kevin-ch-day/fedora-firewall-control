import { readFile } from "node:fs/promises";

import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";

import { DASHBOARD_SCHEMA_PATH, SNAPSHOT_SCHEMA_ID } from "./config.js";
import { ApiError, sanitizeDiagnostic } from "./errors.js";

type JsonPrimitive = boolean | number | string | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { readonly [key: string]: JsonValue };
export type ValidatedSnapshot = Readonly<Record<string, JsonValue>>;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export class SnapshotValidator {
  readonly #validate: ValidateFunction;

  private constructor(validate: ValidateFunction) {
    this.#validate = validate;
  }

  public static async create(schemaPath = DASHBOARD_SCHEMA_PATH): Promise<SnapshotValidator> {
    let schema: unknown;
    try {
      schema = JSON.parse(await readFile(schemaPath, "utf8")) as unknown;
    } catch (error: unknown) {
      throw new ApiError("server_initialization_failed", 500, {
        cause: error,
        diagnostic: sanitizeDiagnostic(error),
      });
    }
    if (!isObject(schema) || schema["$schema"] !== "https://json-schema.org/draft/2020-12/schema") {
      throw new ApiError("server_initialization_failed", 500, {
        diagnostic: "Dashboard schema must declare JSON Schema draft 2020-12.",
      });
    }
    try {
      const ajv = new Ajv2020({ allErrors: false, strict: true });
      return new SnapshotValidator(ajv.compile(schema));
    } catch (error: unknown) {
      throw new ApiError("server_initialization_failed", 500, {
        cause: error,
        diagnostic: sanitizeDiagnostic(error),
      });
    }
  }

  public parseAndValidate(raw: string): ValidatedSnapshot {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw) as unknown;
    } catch (error: unknown) {
      throw new ApiError("ffc_malformed_output", 502, { cause: error });
    }
    if (!this.#validate(parsed) || !isObject(parsed) || parsed["schema"] !== SNAPSHOT_SCHEMA_ID) {
      throw new ApiError("ffc_schema_invalid", 502);
    }
    return parsed as ValidatedSnapshot;
  }
}
