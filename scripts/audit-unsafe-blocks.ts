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
//   bun run scripts/audit-unsafe-blocks.ts                  # summary + top 15
//   bun run scripts/audit-unsafe-blocks.ts --json           # raw JSON
//   bun run scripts/audit-unsafe-blocks.ts <path>           # scope a subtree
//   bun run scripts/audit-unsafe-blocks.ts --write-baseline # snapshot current
//                                                          state to .baseline.json
//   bun run scripts/audit-unsafe-blocks.ts --check          # diff against
//                                                          baseline; exit 1
//                                                          on any per-file
//                                                          regression
//
// Intended workflow: deny-promote whichever fully-clean crates you can
// (per PR #3 pattern), and leave the still-warn ones tracked in the
// baseline. `--check` makes the baseline a regression gate without
// requiring all warn-crates to be denied at once.
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

// Matches an `unsafe { … }` block opener. Anchored to require `unsafe`
// either at line start (modulo whitespace) or immediately after a syntactic
// boundary (`=`, `(`, `{`, `,`, `;`, `return`, `=>`, `&`, `*`). Deliberately
// strict: the previous wildcard form `.*[=({,]` could match doc-comment
// prose like `// uses unsafe { ... }`, inflating the count.
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

function loadBaseline(repoRoot: string): Record<string, number> | null {
  const fs = require("fs") as typeof import("fs");
  const path = `${repoRoot}/scripts/audit-unsafe-blocks.baseline.json`;
  if (!fs.existsSync(path)) return null;
  const raw = JSON.parse(fs.readFileSync(path, "utf8"));
  // Baseline shape: { "by_file": { "rel/path.rs": N } }
  return raw.by_file ?? {};
}

function checkAgainstBaseline(
  flagged: Hit[],
  baseline: Record<string, number>,
): { regressions: Array<{ file: string; was: number; now: number }>; improvements: Array<{ file: string; was: number; now: number }> } {
  const now: Record<string, number> = {};
  for (const h of flagged) now[h.file] = (now[h.file] ?? 0) + 1;
  const regressions: Array<{ file: string; was: number; now: number }> = [];
  const improvements: Array<{ file: string; was: number; now: number }> = [];
  for (const f of new Set([...Object.keys(baseline), ...Object.keys(now)])) {
    const was = baseline[f] ?? 0;
    const nowN = now[f] ?? 0;
    if (nowN > was) regressions.push({ file: f, was, now: nowN });
    else if (nowN < was) improvements.push({ file: f, was, now: nowN });
  }
  return { regressions, improvements };
}

function main() {
  const args = process.argv.slice(2);
  const wantJson = args.includes("--json");
  const wantCheck = args.includes("--check");
  const wantWriteBaseline = args.includes("--write-baseline");
  const path = args.find(a => !a.startsWith("--")) ?? "src";
  const repoRoot = require("path").resolve(__dirname, "..");
  const target = require("path").resolve(repoRoot, path);

  const { total, flagged } = audit(target);

  if (wantWriteBaseline) {
    const fs = require("fs") as typeof import("fs");
    const byFile: Record<string, number> = {};
    for (const h of flagged) byFile[h.file] = (byFile[h.file] ?? 0) + 1;
    const sorted: Record<string, number> = {};
    for (const k of Object.keys(byFile).sort()) sorted[k] = byFile[k];
    const payload = {
      generated_by: "scripts/audit-unsafe-blocks.ts --write-baseline",
      generated_at: new Date().toISOString().slice(0, 10),
      scanned_root: path,
      total_unsafe_blocks: total,
      undocumented: flagged.length,
      ratio: Number((flagged.length / Math.max(total, 1)).toFixed(4)),
      by_file: sorted,
    };
    fs.writeFileSync(
      `${repoRoot}/scripts/audit-unsafe-blocks.baseline.json`,
      JSON.stringify(payload, null, 2) + "\n",
    );
    console.log(`wrote baseline: ${flagged.length} undocumented across ${Object.keys(sorted).length} files`);
    return;
  }

  if (wantCheck) {
    const baseline = loadBaseline(repoRoot);
    if (!baseline) {
      console.error("no baseline at scripts/audit-unsafe-blocks.baseline.json; run with --write-baseline to seed");
      process.exit(2);
    }
    const { regressions, improvements } = checkAgainstBaseline(flagged, baseline);
    if (regressions.length === 0) {
      console.log(`audit-unsafe-blocks --check: OK (${improvements.length} file(s) improved, 0 regressed)`);
      for (const i of improvements.slice(0, 10)) {
        console.log(`  ↓  ${i.file}: ${i.was} → ${i.now}`);
      }
      return;
    }
    console.error(`audit-unsafe-blocks --check: REGRESSION in ${regressions.length} file(s)`);
    for (const r of regressions) {
      console.error(`  ↑  ${r.file}: ${r.was} → ${r.now}`);
    }
    console.error("");
    console.error("Either annotate the new unsafe blocks with `// SAFETY:` or, if the");
    console.error("change is intentional, refresh the baseline with --write-baseline.");
    process.exit(1);
  }

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
