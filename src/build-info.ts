import packageJson from '../package.json';
import { HOOK_NAME } from './adapter/constants.ts';
import { BASELINE } from './policy/baseline.ts';
import { policyDigest } from './policy/digest.ts';

export interface SourceBuildInfo {
  readonly sha: 'source';
  readonly dirty: null;
  readonly date: null;
}

export interface CompiledBuildInfo {
  readonly sha: string;
  readonly dirty: boolean;
  readonly date: string;
}
declare const BOUNCER_BUILD: Readonly<CompiledBuildInfo & { readonly version: string; }> | undefined;

export type BuildInfo = SourceBuildInfo | CompiledBuildInfo;

export interface VersionInfo {
  readonly name: string;
  readonly version: string;
  readonly build: BuildInfo;
  readonly policy: { readonly baseline: string; };
}

export function currentBuild(): BuildInfo {
  if (typeof BOUNCER_BUILD === 'undefined') return { sha: 'source', dirty: null, date: null };
  return { sha: BOUNCER_BUILD.sha, dirty: BOUNCER_BUILD.dirty, date: BOUNCER_BUILD.date };
}

export function buildIdentity(build: BuildInfo): string {
  if (build.sha === 'source') return build.sha;
  return `${build.sha}${build.dirty ? '-dirty' : ''}`;
}

export function formatBuild(build: BuildInfo): string {
  return build.sha === 'source'
    ? 'source, uncommitted build info'
    : `${buildIdentity(build)}, built ${build.date}`;
}

export const BOUNCER_VERSION = typeof BOUNCER_BUILD === 'undefined' ? packageJson.version : BOUNCER_BUILD.version;

export function versionInfo(): VersionInfo {
  return {
    name: HOOK_NAME,
    version: BOUNCER_VERSION,
    build: currentBuild(),
    policy: { baseline: policyDigest(BASELINE.rules, [], []) },
  };
}

export function formatVersion(info: VersionInfo): string {
  return `${info.name} ${info.version} (${formatBuild(info.build)}) baseline ${info.policy.baseline}`;
}
