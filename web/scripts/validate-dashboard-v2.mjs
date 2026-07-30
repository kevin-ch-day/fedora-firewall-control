import { readFile } from "node:fs/promises";

import { Ajv2020 } from "ajv/dist/2020.js";

if (process.argv.length !== 4) {
  console.error("Usage: node validate-dashboard-v2.mjs <schema> <snapshot>");
  process.exit(2);
}

try {
  const [schemaText, snapshotText] = await Promise.all([
    readFile(process.argv[2], "utf8"),
    readFile(process.argv[3], "utf8"),
  ]);
  const schema = JSON.parse(schemaText);
  const snapshot = JSON.parse(snapshotText);
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  if (!validate(snapshot)) {
    console.error("dashboard-v2 snapshot failed schema validation");
    process.exit(1);
  }
  const contradictory = structuredClone(snapshot);
  contradictory.listeners.status = snapshot.listeners.status === "unavailable"
    ? "available"
    : "unavailable";
  if (validate(contradictory)) {
    console.error("dashboard-v2 schema accepted contradictory listener evidence");
    process.exit(1);
  }
} catch {
  console.error("dashboard-v2 schema validation could not be completed");
  process.exit(1);
}
