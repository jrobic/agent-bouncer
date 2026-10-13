// Bun resolves `process.execPath` through symlinks (a Homebrew install
// reports its versioned Cellar path); `argv0` keeps the path bouncer was
// started through. Kept only when it is the running file, never realpath'd.

import { accessSync, constants as fsConstants, realpathSync, statSync } from 'node:fs';
import { delimiter, join, resolve } from 'node:path';

export interface InvokedPathInputs {
  readonly argv0: string;
  readonly execPath: string;
  readonly path: string | undefined;
  readonly cwd: string;
}

function findOnPath(name: string, path: string | undefined, cwd: string): string | undefined {
  if (path === undefined) return undefined;
  for (const entry of path.split(delimiter)) {
    const candidate = join(resolve(cwd, entry), name);
    try {
      if (!statSync(candidate).isFile()) continue;
      accessSync(candidate, fsConstants.X_OK);
      return candidate;
    } catch {
      // Absent or not executable: the shell skips it too.
    }
  }
  return undefined;
}

export function invokedBouncerPath({ argv0, execPath, path, cwd }: InvokedPathInputs): string {
  if (argv0 === '') return execPath;
  try {
    const candidate = argv0.includes('/') ? resolve(cwd, argv0) : findOnPath(argv0, path, cwd);
    if (candidate !== undefined && realpathSync(candidate) === realpathSync(execPath)) return candidate;
  } catch {
    // Unresolvable: fall back to execPath.
  }
  return execPath;
}
