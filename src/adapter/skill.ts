// Embedded printed skills. `bouncer skill <id>` returns an agent-facing
// workflow from the same binary whose CLI grammar it cites, so redirects
// install a version-matched source without a separate package.
import policySkillSourceModule from '../../skills/bouncer-policy/SKILL.md' with { type: 'text' };

// Bun's `type: "text"` import attribute resolves this module to raw file
// text at runtime, but tsc infers the Markdown module's declared shape.
// The cast records that static-analysis gap; the runtime value is a string.
const policySkillSource = policySkillSourceModule as unknown as string;

const VERSION_PLACEHOLDER = 'bouncer_version: __BOUNCER_VERSION__';

const SKILL_SOURCES: Readonly<Record<string, string>> = {
  policy: policySkillSource,
};

export function hasSkill(id: string): boolean {
  return Object.hasOwn(SKILL_SOURCES, id);
}

export function renderSkill(id: string, version: string): string | undefined {
  if (!hasSkill(id)) return undefined;
  const source = SKILL_SOURCES[id];
  if (source === undefined) return undefined;
  return source.replace(VERSION_PLACEHOLDER, () => `bouncer_version: ${version}`);
}
