// rust-dto-check — syn-based AST harvester for DTO/SoC/SoA candidate detection
// Mirror of ruff_python_dto_check pattern: NDJSON bundles + grouped indices.
//
// Five signal classes (same as Python prototype but proper AST):
//   1. DTO duplicates    — structs with identical sorted field-shape hash
//   2. Trait fan-out     — traits with 5+ implementors
//   3. Large match exprs — match with 6+ arms (dispatch-table candidates)
//   4. Heavy functions   — body stmt count ≥ 30 with mixed concerns
//   5. Enum sprawl       — enums with 10+ variants (PHF candidates)

use proc_macro2::TokenStream;
use quote::ToTokens;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use syn::visit::Visit;
use syn::{Attribute, ExprMatch, Fields, ItemEnum, ItemFn, ItemImpl, ItemStruct, Type, Visibility};

fn type_to_string(t: &Type) -> String {
    t.to_token_stream().to_string()
}

fn path_str(p: &syn::Path) -> String {
    p.to_token_stream().to_string().replace(' ', "")
}

fn derives(attrs: &[Attribute]) -> Vec<String> {
    let mut out = Vec::new();
    for a in attrs {
        if a.path().is_ident("derive") {
            let _ = a.parse_nested_meta(|m| {
                let s = m.path.to_token_stream().to_string().replace(' ', "");
                out.push(s);
                Ok(())
            });
        }
    }
    out
}

#[derive(Serialize, Clone)]
struct StructFinding {
    name: String,
    file: String,
    shape_hash: String,
    field_count: usize,
    fields: Vec<(String, String)>,
    derives: Vec<String>,
    generics: usize,
    is_pub: bool,
}

#[derive(Serialize, Clone)]
struct EnumFinding {
    name: String,
    file: String,
    variant_count: usize,
    variants_with_data: usize,
    has_repr_int: bool,
    derives: Vec<String>,
    is_pub: bool,
}

#[derive(Serialize, Clone)]
struct ImplFinding {
    trait_name: Option<String>,
    type_name: String,
    file: String,
    method_count: usize,
}

#[derive(Serialize, Clone)]
struct FnFinding {
    name: String,
    file: String,
    body_stmts: usize,
    unsafe_blocks: usize,
    match_exprs: usize,
    nested_calls: usize,
    is_async: bool,
    is_unsafe: bool,
}

#[derive(Serialize, Clone)]
struct MatchFinding {
    file: String,
    arm_count: usize,
    has_guard_arms: bool,
    scrutinee_str: String,
}

struct Harvester {
    file: String,
    structs: Vec<StructFinding>,
    enums: Vec<EnumFinding>,
    impls: Vec<ImplFinding>,
    fns: Vec<FnFinding>,
    matches: Vec<MatchFinding>,
}

// Inner visitor that counts unsafe blocks, match expressions, and call sites in a fn body
struct BodyStats {
    unsafe_blocks: usize,
    match_exprs: usize,
    calls: usize,
}

impl<'ast> Visit<'ast> for BodyStats {
    fn visit_expr_unsafe(&mut self, e: &'ast syn::ExprUnsafe) {
        self.unsafe_blocks += 1;
        syn::visit::visit_expr_unsafe(self, e);
    }
    fn visit_expr_match(&mut self, e: &'ast syn::ExprMatch) {
        self.match_exprs += 1;
        syn::visit::visit_expr_match(self, e);
    }
    fn visit_expr_call(&mut self, e: &'ast syn::ExprCall) {
        self.calls += 1;
        syn::visit::visit_expr_call(self, e);
    }
    fn visit_expr_method_call(&mut self, e: &'ast syn::ExprMethodCall) {
        self.calls += 1;
        syn::visit::visit_expr_method_call(self, e);
    }
}

impl<'ast> Visit<'ast> for Harvester {
    fn visit_item_struct(&mut self, s: &'ast ItemStruct) {
        if let Fields::Named(named) = &s.fields {
            let fields: Vec<(String, String)> = named
                .named
                .iter()
                .filter_map(|f| f.ident.as_ref().map(|i| (i.to_string(), type_to_string(&f.ty))))
                .collect();
            if fields.len() >= 2 {
                let mut sorted = fields.clone();
                sorted.sort();
                let shape_str = sorted
                    .iter()
                    .map(|(n, t)| format!("{}:{}", n, t))
                    .collect::<Vec<_>>()
                    .join("|");
                let mut h = Sha256::new();
                h.update(shape_str.as_bytes());
                let shape_hash = format!("{:x}", h.finalize())[..12].to_string();
                self.structs.push(StructFinding {
                    name: s.ident.to_string(),
                    file: self.file.clone(),
                    shape_hash,
                    field_count: fields.len(),
                    fields,
                    derives: derives(&s.attrs),
                    generics: s.generics.params.len(),
                    is_pub: matches!(s.vis, Visibility::Public(_)),
                });
            }
        }
        syn::visit::visit_item_struct(self, s);
    }

    fn visit_item_enum(&mut self, e: &'ast ItemEnum) {
        let variant_count = e.variants.len();
        if variant_count >= 5 {
            let variants_with_data = e
                .variants
                .iter()
                .filter(|v| !matches!(v.fields, Fields::Unit))
                .count();
            let has_repr_int = e
                .attrs
                .iter()
                .any(|a| a.path().is_ident("repr") && a.to_token_stream().to_string().contains("u"));
            self.enums.push(EnumFinding {
                name: e.ident.to_string(),
                file: self.file.clone(),
                variant_count,
                variants_with_data,
                has_repr_int,
                derives: derives(&e.attrs),
                is_pub: matches!(e.vis, Visibility::Public(_)),
            });
        }
        syn::visit::visit_item_enum(self, e);
    }

    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        let trait_name = i.trait_.as_ref().map(|(_, p, _)| path_str(p));
        let type_name = i.self_ty.to_token_stream().to_string().replace(' ', "");
        let method_count = i
            .items
            .iter()
            .filter(|item| matches!(item, syn::ImplItem::Fn(_)))
            .count();
        self.impls.push(ImplFinding {
            trait_name,
            type_name,
            file: self.file.clone(),
            method_count,
        });
        syn::visit::visit_item_impl(self, i);
    }

    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        let body_stmts = f.block.stmts.len();
        if body_stmts >= 30 {
            let mut bs = BodyStats { unsafe_blocks: 0, match_exprs: 0, calls: 0 };
            bs.visit_block(&f.block);
            self.fns.push(FnFinding {
                name: f.sig.ident.to_string(),
                file: self.file.clone(),
                body_stmts,
                unsafe_blocks: bs.unsafe_blocks,
                match_exprs: bs.match_exprs,
                nested_calls: bs.calls,
                is_async: f.sig.asyncness.is_some(),
                is_unsafe: f.sig.unsafety.is_some(),
            });
        }
        syn::visit::visit_item_fn(self, f);
    }

    fn visit_expr_match(&mut self, m: &'ast ExprMatch) {
        let arm_count = m.arms.len();
        if arm_count >= 6 {
            let has_guard = m.arms.iter().any(|a| a.guard.is_some());
            let scrutinee_str = m.expr.to_token_stream().to_string();
            let trimmed = if scrutinee_str.len() > 80 {
                format!("{}...", &scrutinee_str[..77])
            } else {
                scrutinee_str
            };
            self.matches.push(MatchFinding {
                file: self.file.clone(),
                arm_count,
                has_guard_arms: has_guard,
                scrutinee_str: trimmed,
            });
        }
        syn::visit::visit_expr_match(self, m);
    }
}

fn main() {
    let root = std::env::args().nth(1).unwrap_or_else(|| "src".to_string());
    let root = PathBuf::from(root);

    let mut all_structs = Vec::new();
    let mut all_enums = Vec::new();
    let mut all_impls = Vec::new();
    let mut all_fns = Vec::new();
    let mut all_matches = Vec::new();
    let mut file_count = 0;
    let mut parse_failures: Vec<String> = Vec::new();

    for entry in walkdir::WalkDir::new(&root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().is_none_or(|e| e != "rs") {
            continue;
        }
        file_count += 1;
        let rel = entry
            .path()
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .to_string();
        let text = match fs::read_to_string(entry.path()) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let file = match syn::parse_file(&text) {
            Ok(f) => f,
            Err(_) => {
                parse_failures.push(rel);
                continue;
            }
        };
        let mut h = Harvester {
            file: rel,
            structs: Vec::new(),
            enums: Vec::new(),
            impls: Vec::new(),
            fns: Vec::new(),
            matches: Vec::new(),
        };
        h.visit_file(&file);
        all_structs.extend(h.structs);
        all_enums.extend(h.enums);
        all_impls.extend(h.impls);
        all_fns.extend(h.fns);
        all_matches.extend(h.matches);
    }

    // Group structs by shape_hash
    let mut by_shape: HashMap<String, Vec<StructFinding>> = HashMap::new();
    for s in &all_structs {
        by_shape.entry(s.shape_hash.clone()).or_default().push(s.clone());
    }
    let mut dto_dupes: Vec<Vec<StructFinding>> =
        by_shape.into_values().filter(|g| g.len() >= 2).collect();
    dto_dupes.sort_by_key(|g| std::cmp::Reverse((g.len(), g[0].field_count)));

    // Group impls by trait_name
    let mut by_trait: HashMap<String, Vec<ImplFinding>> = HashMap::new();
    for i in &all_impls {
        if let Some(t) = &i.trait_name {
            by_trait.entry(t.clone()).or_default().push(i.clone());
        }
    }
    let mut trait_fanout: Vec<(String, Vec<ImplFinding>)> = by_trait
        .into_iter()
        .filter(|(_, v)| v.len() >= 5)
        .collect();
    trait_fanout.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));

    all_fns.sort_by_key(|f| {
        std::cmp::Reverse((f.unsafe_blocks * 200 + f.match_exprs * 50 + f.body_stmts) as i64)
    });
    all_matches.sort_by_key(|m| std::cmp::Reverse(m.arm_count));
    all_enums.sort_by_key(|e| std::cmp::Reverse(e.variant_count));

    // Report
    println!("=== AST scan: {} files, {} parse failures ===", file_count, parse_failures.len());
    println!("  structs (named, ≥2 fields):  {}", all_structs.len());
    println!("  enums (≥5 variants):         {}", all_enums.len());
    println!("  impls:                       {}", all_impls.len());
    println!("  fns (body ≥30 stmts):        {}", all_fns.len());
    println!("  matches (≥6 arms):           {}", all_matches.len());
    println!("  DTO duplicate groups (≥2):   {}", dto_dupes.len());
    println!("  trait fan-out groups (≥5):   {}", trait_fanout.len());
    println!();

    println!("=== DTO duplicates (top 15 by group size × field count) ===");
    for g in dto_dupes.iter().take(15) {
        let s = &g[0];
        let fields: Vec<&str> = s.fields.iter().take(5).map(|(n, _)| n.as_str()).collect();
        println!(
            "  {}× {} fields  shape={}  derives={:?}",
            g.len(),
            s.field_count,
            s.shape_hash,
            s.derives
        );
        println!("    fields: {:?}", fields);
        for x in g.iter().take(4) {
            println!("     - {:<40}  {}", x.name, x.file);
        }
        if g.len() > 4 {
            println!("     ... +{} more", g.len() - 4);
        }
    }
    println!();

    println!("=== Trait fan-out (top 15) ===");
    for (t, sites) in trait_fanout.iter().take(15) {
        let types: std::collections::BTreeSet<&str> =
            sites.iter().map(|i| i.type_name.as_str()).collect();
        let sample: Vec<&&str> = types.iter().take(5).collect();
        println!(
            "  {:>3}× impl {:<35} for: {} types ({}{})",
            sites.len(),
            t,
            types.len(),
            sample
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            if types.len() > 5 { ", ..." } else { "" }
        );
    }
    println!();

    println!("=== Large match blocks (top 15) ===");
    for m in all_matches.iter().take(15) {
        println!(
            "  {:>4} arms  guards={}  scrutinee={}  {}",
            m.arm_count, m.has_guard_arms, m.scrutinee_str, m.file
        );
    }
    println!();

    println!("=== Heavy functions (top 15, ranked by unsafe+match weight) ===");
    for f in all_fns.iter().take(15) {
        println!(
            "  stmts={:>4}  unsafe={:<2} match={:<2} calls={:<4}  {}{}  {}::{}",
            f.body_stmts,
            f.unsafe_blocks,
            f.match_exprs,
            f.nested_calls,
            if f.is_async { "A" } else { " " },
            if f.is_unsafe { "U" } else { " " },
            f.file,
            f.name,
        );
    }
    println!();

    println!("=== Enum sprawl (top 10) ===");
    for e in all_enums.iter().take(10) {
        println!(
            "  {:>3} variants ({} with data, repr-int={})  {}::{}  derives={:?}",
            e.variant_count, e.variants_with_data, e.has_repr_int, e.file, e.name, e.derives
        );
    }
    println!();

    if !parse_failures.is_empty() {
        println!("=== Parse failures ({} files) ===", parse_failures.len());
        for f in parse_failures.iter().take(5) {
            println!("  {}", f);
        }
        if parse_failures.len() > 5 {
            println!("  ... +{} more", parse_failures.len() - 5);
        }
    }

    let findings = serde_json::json!({
        "meta": {
            "files": file_count,
            "parse_failures": parse_failures.len(),
            "structs": all_structs.len(),
            "enums": all_enums.len(),
            "impls": all_impls.len(),
            "fns_ge30_stmts": all_fns.len(),
            "matches_ge6_arms": all_matches.len(),
        },
        "dto_duplicates": dto_dupes.iter().take(40).collect::<Vec<_>>(),
        "trait_fanout": trait_fanout.iter().take(25).map(|(t, sites)| {
            serde_json::json!({"trait": t, "count": sites.len(), "sites": sites})
        }).collect::<Vec<_>>(),
        "heavy_fns": all_fns.iter().take(40).collect::<Vec<_>>(),
        "large_matches": all_matches.iter().take(40).collect::<Vec<_>>(),
        "large_enums": all_enums.iter().take(25).collect::<Vec<_>>(),
    });
    fs::write(
        "/tmp/dto_findings_ast.json",
        serde_json::to_string_pretty(&findings).unwrap(),
    )
    .unwrap();
    let _: TokenStream; // suppress unused warning on imports if compiler insists
}
