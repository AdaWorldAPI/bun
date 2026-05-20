#!/usr/bin/env bun
// audit-unsafe-blocks.ts — count `unsafe { ... }` blocks without a preceding
// `// SAFETY:` comment. Approximates what `clippy::undocumented_unsafe_blocks`
// (added to `[workspace.lints.clippy]`) will flag once a full build runs.
//
// Why this is its own script:
//   - clippy needs the full `vendor/` + cross-target setup; this is a static
//     audit that runs in <1 s on the source tree alone, so it's CI-cheap and
//     useful as a pre-build sanity check / baseline tracker.
//   - The bare unsafe-vs-SAFETY ratio (10.5k blocks / 10.7k comments) hides
//     the real distribution: over-annotated files mask under-annotated ones.
//     This script gives the actual per-file gap, which is what the lint sees.
//
// Usage:
//   bun run scripts/audit-unsafe-blocks.ts          # summary + top 15 files
//   bun run scripts/audit-unsafe-blocks.ts --json   # JSON for CI baselining
//   bun run scripts/audit-unsafe-blocks.ts <path>   # scope to a subtree
//
// Heuristic (matches clippy's lint semantics closely, not exactly):
//   - Scans every .rs under src/ (or the path argument).
//   - Counts lines opening an `unsafe {` block (includes `let x = unsafe {`,
//     trailing-`unsafe { ... }` on a binding RHS, etc.).
//   - Skips `unsafe fn` / `unsafe impl` / `unsafe trait` / `unsafe extern`
//     headers (those are governed by other lints).
//   - Looks back up to 4 non-blank lines for `// SAFETY:`, `/* SAFETY:`, or
//     `//! SAFETY:`. Anything found within that window counts as documented.
//
// False-positive sources (~3-5% based on spot-check):
//   - Doc-comments mentioning `unsafe { ... }` in prose pass the open-block
//     regex; the leading `///` makes them harmless at the lint level too.
//   - SAFETY comments more than 4 lines above the block are missed; the
//     real lint walks attributes / cfg-gates correctly.
//
// Output stable across runs — suitable for git-tracked baselines.

const UNSAFE_OPEN = /^[ \t]*(?:[a-zA-Z_]\w*\s*[:=]\s*.*|let\s+\w.*[:=]\s*|return\s+|.*[=({,]\s*)?unsafe\s*\{/;
const SAFETY = /^[ \t]*(?:\/\/\s*SAFETY:|\/\*\s*SAFETY:|\/\/!\s*SAFETY:)/i;
const SKIP_PARENT = /^[ \t]*(?:pub\s+)?(?:async\s+)?unsafe\s+(?:fn|impl|trait|extern)\b/;
const LOOKBACK = 4;

type Hit = { file: string; line: number; snippet: string };

function audit(root: string): { total: number; flagged: Hit[] } {
  const total = { n: 0 };
  const flagged: Hit[] = [];
  const glob = new Bun.Glob("**/*.rs");

  for (const rel of glob.scanSync({ cwd: root, onlyFiles: true })) {
    const file = `${root}/${rel}`;
    let text: string;
    try {
      text = Bun.file(file).text() as unknown as string;
    } catch {
      continue;
    }
    // Bun.file.text() is async — fall back to sync read via Node's fs for
    // simplicity (this script is fast enough that sync IO doesn't matter).
    text = require("fs").readFileSync(file, "utf8");
    const lines = text.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (SKIP_PARENT.test(line)) continue;
      if (!UNSAFE_OPEN.test(line)) continue;
      // Require the literal `unsafe` keyword (filter doc/comment FPs)
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
