import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface ExecutableFixture {
  readonly directory: string;
  readonly executable: string;
  cleanup(): Promise<void>;
}

export async function createExecutableFixture(
  body: string,
  options: { name?: string; mode?: number } = {},
): Promise<ExecutableFixture> {
  const directory = await mkdtemp(join(tmpdir(), "ffc-web-test-"));
  const executable = join(directory, options.name ?? "ffc-fixture");
  await writeFile(executable, `#!/usr/bin/node\n${body}\n`, { mode: options.mode ?? 0o700 });
  await chmod(executable, options.mode ?? 0o700);
  return {
    directory,
    executable,
    cleanup: async () => rm(directory, { recursive: true, force: true }),
  };
}
