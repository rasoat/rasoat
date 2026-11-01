// Which frameworks a crawled page runs, and their exact versions. One module per framework under frameworks/;
// each reads only what any visitor's browser downloads.
import type { Crawl } from "./crawl.ts";
import { next } from "./frameworks/next.ts";
import { wordpress } from "./frameworks/wordpress.ts";

export type FrameworkId = "next" | "wordpress";

export interface Finding {
  framework: FrameworkId;
  version: string | null;
  how: string | null; // which pattern found the version
  where: string | null; // URL it was found in
  signals: string[]; // why we think the framework is there
}

export interface Framework {
  id: FrameworkId;
  detect(crawl: Crawl): Finding | null; // null = no sign of this framework
}

export const FRAMEWORKS: Framework[] = [next, wordpress];

/** Every framework found on the page, in FRAMEWORKS order. */
export function detect(crawl: Crawl): Finding[] {
  return FRAMEWORKS.map((f) => f.detect(crawl)).filter((f): f is Finding => f !== null);
}
