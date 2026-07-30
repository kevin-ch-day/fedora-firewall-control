import { cp, mkdir, rm } from "node:fs/promises";

const source = new URL("../src/client/", import.meta.url);
const destination = new URL("../dist/client/", import.meta.url);

await rm(destination, { force: true, recursive: true });
await mkdir(destination, { recursive: true });
await cp(source, destination, { recursive: true });
