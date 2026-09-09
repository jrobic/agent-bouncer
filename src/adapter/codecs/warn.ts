// Review round 1 S-9c: the identical `warn` helper existed three times
// (src/adapter/neutral-call.ts, codecs/input/apply-patch.ts, codecs/input/
// hashline.ts) — one stderr-diagnostic convention every codec and
// selector reader shares (`[<hookName>] <message>`), extracted once so a
// future fourth copy never drifts from it.

/** Every codec's and selector reader's own stderr diagnostic shape: `[<hookName>] <message>`. */
export function warn(hookName: string, message: string): void {
  console.error(`[${hookName}] ${message}`);
}
