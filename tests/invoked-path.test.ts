import { describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { invokedBouncerPath } from '../src/invoked-path.ts';
import { tmpDir } from './tmp.ts';

function executable(path: string): string {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, '#!/bin/sh\nexit 0\n', 'utf8');
  chmodSync(path, 0o755);
  return path;
}

interface Layout {
  readonly root: string;
  readonly execPath: string;
  readonly link: string;
}

function layout(): Layout {
  const root = tmpDir('bouncer-invoked-path-test-');
  const real = executable(join(root, 'real', 'bin', 'p'));
  const link = join(root, 'bin', 'p');
  mkdirSync(join(root, 'bin'), { recursive: true });
  symlinkSync(real, link);
  return { root, execPath: realpathSync(real), link };
}

describe('invokedBouncerPath', () => {
  test('an absolute symlink argv0 is kept as the symlink, not its target', () => {
    const { root, execPath, link } = layout();

    expect(invokedBouncerPath({ argv0: link, execPath, path: '', cwd: root })).toBe(link);
  });

  test('a relative argv0 is resolved against the cwd, still not followed', () => {
    const { root, execPath, link } = layout();

    expect(invokedBouncerPath({ argv0: './bin/p', execPath, path: '', cwd: root })).toBe(link);
  });

  test('a bare name is the first PATH entry holding an executable file of that name', () => {
    const { root, execPath, link } = layout();
    mkdirSync(join(root, 'plain'), { recursive: true });
    writeFileSync(join(root, 'plain', 'p'), 'not executable', 'utf8');
    executable(join(root, 'later', 'p'));
    const path = [join(root, 'absent'), join(root, 'plain'), join(root, 'bin'), join(root, 'later')].join(':');

    expect(invokedBouncerPath({ argv0: 'p', execPath, path, cwd: root })).toBe(link);
  });

  test('an empty or relative PATH entry means the cwd', () => {
    const { root, execPath, link } = layout();

    expect(invokedBouncerPath({ argv0: 'p', execPath, path: join(root, 'absent') + ':', cwd: join(root, 'bin') })).toBe(link);
    expect(invokedBouncerPath({ argv0: 'p', execPath, path: 'bin', cwd: root })).toBe(link);
  });

  test('an argv0 that is another file than execPath falls back to execPath', () => {
    const { root, execPath } = layout();
    const other = executable(join(root, 'other', 'p'));

    expect(invokedBouncerPath({ argv0: other, execPath, path: '', cwd: root })).toBe(execPath);
    expect(invokedBouncerPath({ argv0: 'p', execPath, path: join(other, '..'), cwd: root })).toBe(execPath);
  });

  test('an argv0 that does not resolve falls back to execPath', () => {
    const { root, execPath } = layout();

    expect(invokedBouncerPath({ argv0: join(root, 'missing', 'p'), execPath, path: '', cwd: root })).toBe(execPath);
    expect(invokedBouncerPath({ argv0: 'p', execPath, path: join(root, 'absent'), cwd: root })).toBe(execPath);
    expect(invokedBouncerPath({ argv0: 'p', execPath, path: undefined, cwd: root })).toBe(execPath);
    expect(invokedBouncerPath({ argv0: '', execPath, path: join(root, 'bin'), cwd: root })).toBe(execPath);
  });
});
