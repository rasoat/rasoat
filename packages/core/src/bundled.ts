// The committed datasets as one snapshot. The only place that names the data files; not in the barrel, so a caller
// that takes its data from elsewhere does not load 1 MB of JSON.
import next from "../../../data/next-advisories.json";
import wordpress from "../../../data/wordpress-core.json";
import node from "../../../data/runtimes/node.json";
import php from "../../../data/runtimes/php.json";
import bun from "../../../data/runtimes/bun.json";
import requirements from "../../../data/framework-runtimes.json";
import { makeSnapshot, type NextData } from "./snapshot.ts";
import type { FrameworkRuntimes } from "./checker/runtime.ts";
import type { RtData, RuntimeId } from "./runtimes.ts";
import type { WpData } from "./wordpress.ts";

export const BUNDLED = makeSnapshot({
  next: next as NextData,
  wordpress: wordpress as unknown as WpData,
  runtimes: { node, php, bun } as unknown as Record<RuntimeId, RtData>,
  requirements: requirements as FrameworkRuntimes,
});
