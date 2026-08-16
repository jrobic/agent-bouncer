// Path canonicalization before checkPath. Adapter-only (needs real
// filesystem I/O, which the engine deliberately does not touch).
//
// Closes the workstation's documented symlink bypass: `checkPath` matches
// on the literal path string, so `ln -s ~/.ssh/id_rsa innocent.txt` followed
// by `Read innocent.txt` would sail past a guard that never resolves the
// symlink. `realpath()` handles the common case (the target exists); when it
// doesn't (a new `Write` target, say), the symlink could still be on the
// PARENT directory, so the fallback resolves the parent and rejoins the
// basename rather than giving up and checking the literal path verbatim.

import { realpath } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';

export async function canonicalizePath(path: string): Promise<string> {
  try {
    return await realpath(path);
  } catch {
    try {
      const canonicalDir = await realpath(dirname(path));
      return join(canonicalDir, basename(path));
    } catch {
      // Neither the path nor its parent exist (or aren't reachable) —
      // nothing left to resolve; fall back to the lexical path so a
      // relative input still normalizes to something checkPath can match.
      return resolve(path);
    }
  }
}
