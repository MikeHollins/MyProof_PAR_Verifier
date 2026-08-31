import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  getPublicRecordCheckJsonSchema,
  getPublicRecordCoherenceReportJsonSchema,
  getVerifyProofAssetInputJsonSchema,
} from "../src/contracts/json-schema.js";

const directory = dirname(fileURLToPath(import.meta.url));

const artifacts = [
  {
    name: "myproof.par.public-record-input.v1.json",
    schema: getVerifyProofAssetInputJsonSchema,
  },
  {
    name: "myproof.par.public-record-check.v1.json",
    schema: getPublicRecordCheckJsonSchema,
  },
  {
    name: "myproof.par.public-record-coherence.v1.json",
    schema: getPublicRecordCoherenceReportJsonSchema,
  },
] as const;

const check = process.argv.includes("--check");
mkdirSync(directory, { recursive: true });

for (const artifact of artifacts) {
  const target = resolve(directory, artifact.name);
  const expected = `${JSON.stringify(artifact.schema(), null, 2)}\n`;
  let actual: string | undefined;
  try {
    actual = readFileSync(target, "utf8");
  } catch {
    actual = undefined;
  }

  if (check) {
    if (actual !== expected) {
      process.stderr.write(`schema artifact out of date: ${artifact.name}\n`);
      process.exitCode = 1;
    }
    continue;
  }

  if (actual !== expected) writeFileSync(target, expected, "utf8");
}

if (check && process.exitCode === 1) process.exit(1);
