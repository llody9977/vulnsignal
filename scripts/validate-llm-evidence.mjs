import { readFile } from "node:fs/promises";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaPath = new URL("../data/llm-discovery-evidence.schema.json", import.meta.url);
const evidencePath = new URL("../data/llm-discovery-evidence.json", import.meta.url);

const [schema, evidence] = await Promise.all(
  [schemaPath, evidencePath].map(async (path) => JSON.parse(await readFile(path, "utf8"))),
);

const validator = new Ajv2020({ allErrors: true, strict: true });
addFormats(validator);
const validate = validator.compile(schema);

if (!validate(evidence)) {
  for (const error of validate.errors ?? []) {
    console.error(`${error.instancePath || "/"}: ${error.message}`);
  }
  process.exitCode = 1;
} else {
  console.log("validated data/llm-discovery-evidence.json against its JSON Schema");
}
