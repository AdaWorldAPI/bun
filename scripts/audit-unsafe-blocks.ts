#!/usr/bin/env bun
// audit-unsafe-blocks.ts — count `unsafe { ... }` blocks without a preceding
// `// SAFETY:` comment. Pre-build static auditor that approximates what
// `clippy::undocumented_unsafe_blocks` would flag, without needing the full
// `vendor/` + cross-target setup populated.
//
// Why this is its own script: clippy needs the full build environment, while
// this runs in <1s on the source tree alone — cheap enough for a pre-commit
// sanity check or a baseline tracker.
//
// Why the bare `// SAFETY:` vs `unsafe {` count ratio is misleading: the
// workspace shows roughly 1:1 in aggregate, masking that some files
// over-annotate (multiple SAFETY comments per block) while others under-
// annotate completely. This script reports the per-file distribution, which
// is what the lint actually sees.
//
// Usage:
//   bun run scripts/audit-unsafe-blocks.ts          # summary + top 15 files
//   bun run scripts/audit-unsafe-blocks.ts --json   # machine-readable
//   bun run scripts/audit-unsafe-blocks.ts <path>   # scope to a subtree
//
// Heuristic (close to clippy's lint semantics, not exact):
//   - Scans every .rs file under src/ (or the path argument).
//   - Detects `unsafe {` block openers at line-start whitespace OR after a
//     syntactic boundary (`= ( { , ; return => & *`). Excludes `unsafe fn`/
//     `impl`/`trait`/`extern` headers and `///`-doc-comment prose.
//   - Looks back up to 4 non-blank lines for `// SAFETY:`, `/* SAFETY:`, or
//     `//! SAFETY:`. Any match counts as documented.
//
// False-positive sources (~3-5% based on spot-check):
//   - SAFETY comments placed >4 lines above their block are missed by the
//     lookback (clippy itself walks attributes/cfg-gates rigorously).
//   - Doc-comment prose mentioning `unsafe { ... }` is mostly filtered by
//     the `///`/`//!` checks.

const UNSAFE_OPEN = /(?:^[ \t]*|[=({,;]\s*|=>\s*|&\s*|\*\s*|\breturn\s+)unsafe\s*\{/;
const SAFETY = /^[ \t]*(?:\/\/\s*SAFETY:|\/\*\s*SAFETY:|\/\/!\s*SAFETY:)/i;
const SKIP_PARENT = /^[ \t]*(?:pub\s+)?(?:async\s+)?unsafe\s+(?:fn|impl|trait|extern)\b/;
const LOOKBACK = 4;

type Hit = { file: string; line: number; snippet: string };

function audit(root: string): { total: number; flagged: Hit[] } {
  const total = { n: 0 };
  const flagged: Hit[] = [];
  const glob = new Bun.Glob("**/*.rs");
  const fs = require("fs") as typeof import("fs");

  for (const rel of glob.scanSync({ cwd: root, onlyFiles: true })) {
    const file = `${root}/${rel}`;
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const lines = text.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (SKIP_PARENT.test(line)) continue;
      if (!UNSAFE_OPEN.test(line)) continue;
      const stripped = line.trim();
      if (stripped.startsWith("///") || stripped.startsWith("//!")) continue;
      if (!/\bunsafe\s*\{/.test(stripped)) continue;
      total.n += 1;

      let documented = false;
      let scanned = 0;
      for (let j = i - 1; j >= 0 && scanned < LOOKBACK; j--) {
        const prev = lines[j].trim();
        if (!prev) continue;
        if (SAFETY.test(lines[j])) {
          documented = true;
          break;
        }
        scanned += 1;
      }
      if (!documented) {
        flagged.push({ file: rel, line: i + 1, snippet: line.trimEnd().slice(0, 110) });
      }
    }
  }

  return { total: total.n, flagged };
}

function main() {
  const args = process.argv.slice(2);
  const wantJson = args.includes("--json");
  const path = args.find(a => !a.startsWith("--")) ?? "src";
  const repoRoot = require("path").resolve(__dirname, "..");
  const target = require("path").resolve(repoRoot, path);

  const { total, flagged } = audit(target);

  if (wantJson) {
    const byFile: Record<string, number> = {};
    for (const h of flagged) byFile[h.file] = (byFile[h.file] ?? 0) + 1;
    console.log(JSON.stringify({
      scanned_root: path,
      total_unsafe_blocks: total,
      undocumented: flagged.length,
      ratio: flagged.length / Math.max(total, 1),
      top_files: Object.entries(byFile).sort(([, a], [, b]) => b - a).slice(0, 25),
    }, null, 2));
    return;
  }

  console.log(`audit-unsafe-blocks — scope: ${path}`);
  console.log(`  total unsafe { … } blocks scanned : ${total}`);
  console.log(`  undocumented (lint would flag)    : ${flagged.length}`);
  console.log(`  ratio                              : ${(flagged.length / Math.max(total, 1) * 100).toFixed(2)}%`);
  console.log("");

  const byFile = new Map<string, number>();
  for (const h of flagged) byFile.set(h.file, (byFile.get(h.file) ?? 0) + 1);
  const sorted = [...byFile.entries()].sort(([, a], [, b]) => b - a);

  console.log(`Top 15 files by undocumented count:`);
  for (const [f, n] of sorted.slice(0, 15)) {
    console.log(`  ${String(n).padStart(4)}  ${f}`);
  }

  if (flagged.length > 0) {
    console.log("");
    console.log("Sample 5 hits:");
    for (const h of flagged.slice(0, 5)) {
      console.log(`  ${h.file}:${h.line}  ${h.snippet}`);
    }
  }
}

main();
