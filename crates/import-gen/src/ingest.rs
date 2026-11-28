// SPDX-License-Identifier: GPL-3.0-or-later

//! Automated C / POSIX header parser for metadata ingestion.
//!
//! Ingests standard system headers (e.g. `/usr/include/math.h`, `_string.h`)
//! and extracts function signatures into typed `FunctionSignature` definitions.
//!
//! Preserves clean-room provenance and licensing attribution.

use crate::metadata::{AbiType, CallingConvention, FunctionSignature, MetadataCatalog, ParamDesc};
use std::collections::btree_map::Entry;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub struct SkippedDeclaration {
    pub line: usize,
    pub declaration: String,
    pub reason: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct HeaderIngestReport {
    pub header: String,
    pub added: usize,
    pub skipped: Vec<SkippedDeclaration>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderSource {
    Windows,
    Host,
}

/// Ingest simple C prototypes from a Win64 header and count the new entries.
pub fn ingest_header_file(
    catalog: &mut MetadataCatalog,
    module: &str,
    header_path: &Path,
) -> Result<usize, String> {
    ingest_header_file_with_report(catalog, module, header_path).map(|report| report.added)
}

/// Ingest a Win64 header and report considered declarations that were skipped.
///
/// The parser accepts single-line, fixed-arity C prototypes. It preserves
/// existing catalog entries and leaves types it cannot represent for review.
/// Preprocess conditional declarations first. Only an ordinary outer include
/// guard is handled while reading a raw header.
pub fn ingest_header_file_with_report(
    catalog: &mut MetadataCatalog,
    module: &str,
    header_path: &Path,
) -> Result<HeaderIngestReport, String> {
    read_header(catalog, module, header_path, HeaderSource::Windows)
}

fn read_header(
    catalog: &mut MetadataCatalog,
    module: &str,
    header_path: &Path,
    source: HeaderSource,
) -> Result<HeaderIngestReport, String> {
    let content = std::fs::read_to_string(header_path)
        .map_err(|e| format!("cannot read {}: {e}", header_path.display()))?;

    let filename = header_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("header.h");

    Ok(parse_c_declarations(
        catalog, module, filename, &content, source,
    ))
}

/// Ingest standard macOS SDK math and string headers if available.
pub fn ingest_standard_system_headers(catalog: &mut MetadataCatalog) -> usize {
    let candidates = [
        (
            "ucrtbase.dll",
            "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/math.h",
        ),
        (
            "ucrtbase.dll",
            "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/_string.h",
        ),
    ];

    let mut total = 0;
    for (mod_name, path_str) in candidates {
        let p = Path::new(path_str);
        if p.exists()
            && let Ok(report) = read_header(catalog, mod_name, p, HeaderSource::Host)
        {
            total += report.added;
        }
    }
    total
}

/// Parse C function prototypes from `content`.
fn parse_c_declarations(
    catalog: &mut MetadataCatalog,
    module: &str,
    header_name: &str,
    content: &str,
    source: HeaderSource,
) -> HeaderIngestReport {
    let mut report = HeaderIngestReport {
        header: header_name.to_owned(),
        added: 0,
        skipped: Vec::new(),
    };
    let module = module.to_ascii_lowercase();
    let mut in_comment = false;
    let lines: Vec<_> = content
        .lines()
        .map(|line| (line, without_comments(line, &mut in_comment)))
        .collect();
    let guard = include_guard_line(&lines);
    let mut guard_active = false;
    let mut conditional_depth = 0usize;
    let mut directive_continues = false;

    for (index, (original, line)) in lines.iter().enumerate() {
        let line = line.trim();
        if directive_continues {
            directive_continues = line.ends_with('\\');
            continue;
        }
        if let Some((directive, _)) = preprocessor_directive(line) {
            directive_continues = line.ends_with('\\');
            match directive {
                "if" | "ifdef" | "ifndef" => {
                    conditional_depth += 1;
                    if guard == Some(index) {
                        guard_active = true;
                    }
                }
                "endif" => {
                    if conditional_depth == 1 {
                        guard_active = false;
                    }
                    conditional_depth = conditional_depth.saturating_sub(1);
                }
                "else" | "elif" | "elifdef" | "elifndef" if conditional_depth == 1 => {
                    guard_active = false;
                }
                _ => {}
            }
            continue;
        }
        if !line.contains('(') || line.starts_with('*') {
            continue;
        }

        let signature = if conditional_depth > usize::from(guard_active) {
            Err("conditional declaration requires preprocessing".to_owned())
        } else {
            parse_signature(line, header_name, source)
        };
        let reason = match signature {
            Ok(signature) => match catalog
                .entries
                .entry((module.clone(), signature.name.clone()))
            {
                Entry::Vacant(entry) => {
                    entry.insert(signature);
                    report.added += 1;
                    continue;
                }
                Entry::Occupied(_) => "existing exact signature takes precedence".to_owned(),
            },
            Err(reason) => reason,
        };
        report.skipped.push(SkippedDeclaration {
            line: index + 1,
            declaration: original.trim().to_owned(),
            reason,
        });
    }

    report
}

fn without_comments(line: &str, in_comment: &mut bool) -> String {
    let mut rest = line;
    let mut result = String::new();
    loop {
        if *in_comment {
            let Some((_, after)) = rest.split_once("*/") else {
                break;
            };
            rest = after;
            *in_comment = false;
        }
        let line_end = rest.find("//").unwrap_or(rest.len());
        let Some(block) = rest.find("/*").filter(|offset| *offset < line_end) else {
            result.push_str(&rest[..line_end]);
            break;
        };
        result.push_str(&rest[..block]);
        result.push(' ');
        rest = &rest[block + 2..];
        *in_comment = true;
    }
    result
}

fn preprocessor_directive(line: &str) -> Option<(&str, &str)> {
    let directive = line.strip_prefix('#')?.trim_start();
    let arguments = directive.trim_start_matches(is_c_identifier_continue);
    Some((
        &directive[..directive.len() - arguments.len()],
        arguments.trim(),
    ))
}

fn include_guard_line(lines: &[(&str, String)]) -> Option<usize> {
    let mut nonempty = lines
        .iter()
        .enumerate()
        .map(|(index, (_, line))| (index, line.trim()))
        .filter(|(_, line)| !line.is_empty());
    let (index, start) = nonempty.next()?;
    let (_, define) = nonempty.next()?;
    let ("ifndef", guard) = preprocessor_directive(start)? else {
        return None;
    };
    (is_c_identifier(guard) && preprocessor_directive(define) == Some(("define", guard)))
        .then_some(index)
}

fn parse_signature(
    declaration: &str,
    header_name: &str,
    source: HeaderSource,
) -> Result<FunctionSignature, String> {
    let declaration = declaration
        .trim_end()
        .strip_suffix(';')
        .ok_or("expected a single-line function prototype ending in ';'")?;
    let declaration = declaration
        .strip_prefix("extern")
        .filter(|rest| rest.starts_with(char::is_whitespace))
        .map_or(declaration, str::trim_start);
    let cleaned = strip_pointer_annotations(declaration);
    if cleaned
        .split(|ch| !is_c_identifier_continue(ch))
        .any(|word| {
            matches!(
                word,
                "__ptr32"
                    | "__ptr64"
                    | "__sptr"
                    | "__uptr"
                    | "__cdecl"
                    | "__stdcall"
                    | "__fastcall"
                    | "__thiscall"
                    | "__vectorcall"
                    | "__regcall"
            )
        })
    {
        return Err("explicit ABI modifier requires review".to_owned());
    }
    let (declarator, suffix) = cleaned.split_once('(').ok_or("missing parameter list")?;
    if declarator.split_whitespace().any(|word| {
        matches!(
            word,
            "static" | "inline" | "__inline" | "__inline__" | "typedef"
        )
    }) {
        return Err("non-exported declarator requires review".to_owned());
    }
    let (parameters, trailing) = suffix.split_once(')').ok_or("incomplete parameter list")?;
    if parameters.contains('(') {
        return Err("nested or callback declarator requires review".to_owned());
    }
    let trailing = trailing.trim();
    if !trailing.is_empty() && !(source == HeaderSource::Host && is_darwin_alias(trailing)) {
        return Err("unsupported trailing declarator or annotation".to_owned());
    }
    let (ret, name) =
        split_named_declarator(declarator.trim()).ok_or("unsupported function declarator")?;
    let return_type =
        parse_c_type(ret, source).ok_or_else(|| format!("unsupported return type: {ret}"))?;
    let parameters = parameters.trim();
    if parameters.is_empty() {
        return Err("unspecified parameter list".to_owned());
    }
    let mut params = Vec::new();
    if parameters != "void" {
        for (index, parameter) in parameters.split(',').map(str::trim).enumerate() {
            if parameter.is_empty() || parameter == "..." {
                return Err("empty or variadic parameter requires review".to_owned());
            }
            let (typ, name) = split_named_declarator(parameter).map_or_else(
                || (parameter, format!("arg{index}")),
                |(typ, name)| (typ, name.to_owned()),
            );
            let abi_type = parse_c_type(typ, source)
                .filter(|kind| *kind != AbiType::Void)
                .ok_or_else(|| format!("unsupported parameter {}: {typ}", index + 1))?;
            params.push(ParamDesc { name, abi_type });
        }
    }
    Ok(FunctionSignature {
        name: name.to_owned(),
        return_type,
        params,
        convention: CallingConvention::Win64,
        header_source: format!("<{header_name}>"),
        doc: format!("Ingested from {header_name}"),
    })
}

fn is_darwin_alias(annotation: &str) -> bool {
    annotation
        .strip_prefix("__DARWIN_ALIAS(")
        .or_else(|| annotation.strip_prefix("__DARWIN_ALIAS_C("))
        .and_then(|name| name.strip_suffix(')'))
        .is_some_and(is_c_identifier)
}

fn is_c_identifier(word: &str) -> bool {
    word.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_')
        && word.chars().all(is_c_identifier_continue)
}

fn is_c_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn strip_pointer_annotations(line: &str) -> String {
    line.split_inclusive(|ch| !is_c_identifier_continue(ch))
        .map(|segment| {
            let word = segment.trim_end_matches(|ch| !is_c_identifier_continue(ch));
            match word {
                "_LIBC_CSTR" | "_LIBC_UNSAFE_INDEXABLE" => &segment[word.len()..],
                _ => segment,
            }
        })
        .collect()
}

/// Split the trailing identifier from a simple named declarator and keep any
/// pointer stars with the type, including when a star touches the name.
fn split_named_declarator(declaration: &str) -> Option<(&str, &str)> {
    let type_end = declaration.trim_end_matches(is_c_identifier_continue).len();
    let (type_str, name) = declaration.split_at(type_end);
    if !type_str.ends_with(|ch: char| ch.is_whitespace() || ch == '*')
        || !is_c_identifier(name)
        || is_c_qualifier(name)
        || matches!(
            name,
            "void"
                | "char"
                | "short"
                | "int"
                | "long"
                | "signed"
                | "unsigned"
                | "float"
                | "double"
                | "_Bool"
        )
    {
        return None;
    }
    Some((type_str.trim_end(), name))
}

fn is_c_qualifier(word: &str) -> bool {
    matches!(
        word,
        "const"
            | "volatile"
            | "restrict"
            | "__restrict"
            | "__restrict__"
            | "_Nullable"
            | "_Nonnull"
            | "_Null_unspecified"
            | "__nullable"
            | "__nonnull"
            | "__null_unspecified"
    )
}

fn parse_c_type(s: &str, source: HeaderSource) -> Option<AbiType> {
    if let Some((pointee, _)) = s.rsplit_once('*') {
        let mut layers = s.split('*');
        let base = normalize_type(layers.next()?);
        if !is_pointer_base(&base)
            || !layers.all(|layer| layer.split_whitespace().all(is_c_qualifier))
        {
            return None;
        }
        // The catalog models a single pointer to plain char as an ANSI string.
        // Additional indirection has to keep the generic pointer category.
        if pointee
            .split_whitespace()
            .filter(|word| !is_c_qualifier(word))
            .eq(["char"])
        {
            return Some(AbiType::StringAnsi);
        }

        // In `int *const *`, the immediate pointee is the const-qualified
        // inner pointer. In `const int **`, that inner pointer is mutable.
        let immediate = pointee.rsplit('*').next().unwrap_or(pointee);
        return Some(AbiType::Pointer {
            is_const: immediate.split_whitespace().any(|word| word == "const"),
            pointee: "void".into(),
        });
    }

    scalar_type(&normalize_type(s), source)
}

fn normalize_type(s: &str) -> String {
    s.split_whitespace()
        .filter(|word| !is_c_qualifier(word))
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_pointer_base(base: &str) -> bool {
    is_c_identifier(base)
        || scalar_type(base, HeaderSource::Windows).is_some()
        || matches!(
            base,
            "signed char"
                | "unsigned char"
                | "short int"
                | "signed short"
                | "signed short int"
                | "unsigned short"
                | "unsigned short int"
                | "long double"
        )
        || base.split_once(' ').is_some_and(|(kind, tag)| {
            matches!(kind, "struct" | "union" | "enum") && is_c_identifier(tag)
        })
}

fn scalar_type(normalized: &str, source: HeaderSource) -> Option<AbiType> {
    match normalized {
        "void" => Some(AbiType::Void),
        "int" | "signed" | "signed int" | "int32_t" => Some(AbiType::I32),
        "unsigned int" | "uint32_t" | "unsigned" => Some(AbiType::U32),
        "long" | "long int" | "signed long" | "signed long int"
            if source == HeaderSource::Windows =>
        {
            Some(AbiType::I32)
        }
        "unsigned long" | "unsigned long int" if source == HeaderSource::Windows => {
            Some(AbiType::U32)
        }
        "long long" | "long long int" | "signed long long" | "signed long long int" | "int64_t" => {
            Some(AbiType::I64)
        }
        "size_t" | "unsigned long long" | "unsigned long long int" | "uint64_t" => {
            Some(AbiType::U64)
        }
        "float" => Some(AbiType::F32),
        "double" => Some(AbiType::F64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_pointer_declarators_preserve_stars_across_spacing() {
        let mut catalog = MetadataCatalog::new();
        let declarations = "
            int *attached(int *out);
            int * separated(int * out);
            int*compact(int*out);
            int **indirect(int * *out);
        ";
        assert_eq!(
            parse_c_declarations(
                &mut catalog,
                "example.dll",
                "test.h",
                declarations,
                HeaderSource::Windows
            )
            .added,
            4
        );
        let pointer = AbiType::Pointer {
            is_const: false,
            pointee: "void".into(),
        };
        for symbol in ["attached", "separated", "compact", "indirect"] {
            let signature = catalog.lookup("example.dll", symbol).unwrap();
            assert_eq!(signature.return_type, pointer, "{symbol}");
            assert_eq!(signature.params.len(), 1, "{symbol}");
            assert_eq!(signature.params[0].name, "out", "{symbol}");
            assert_eq!(signature.params[0].abi_type, pointer, "{symbol}");
        }
    }

    #[test]
    fn unnamed_supported_parameters_keep_their_complete_types() {
        let mut catalog = MetadataCatalog::new();
        let declarations = "void inspect(unsigned  int, long long, unsigned long long, double, int *, unsigned int named);";
        assert_eq!(
            parse_c_declarations(
                &mut catalog,
                "example.dll",
                "test.h",
                declarations,
                HeaderSource::Windows
            )
            .added,
            1
        );
        let signature = catalog.lookup("example.dll", "inspect").unwrap();
        let expected = vec![
            ("arg0", AbiType::U32),
            ("arg1", AbiType::I64),
            ("arg2", AbiType::U64),
            ("arg3", AbiType::F64),
            (
                "arg4",
                AbiType::Pointer {
                    is_const: false,
                    pointee: "void".into(),
                },
            ),
            ("named", AbiType::U32),
        ];
        let actual: Vec<_> = signature
            .params
            .iter()
            .map(|param| (param.name.as_str(), param.abi_type.clone()))
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn postfix_qualified_scalars_keep_their_abi_types() {
        let mut catalog = MetadataCatalog::new();
        let declarations = "void inspect(double const, float const, int const, unsigned int const, long long const, double const named);";
        assert_eq!(
            parse_c_declarations(
                &mut catalog,
                "example.dll",
                "test.h",
                declarations,
                HeaderSource::Windows
            )
            .added,
            1
        );
        let signature = catalog.lookup("example.dll", "inspect").unwrap();
        let expected = vec![
            ("arg0", AbiType::F64),
            ("arg1", AbiType::F32),
            ("arg2", AbiType::I32),
            ("arg3", AbiType::U32),
            ("arg4", AbiType::I64),
            ("named", AbiType::F64),
        ];
        let actual: Vec<_> = signature
            .params
            .iter()
            .map(|param| (param.name.as_str(), param.abi_type.clone()))
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn sdk_nullability_annotations_do_not_become_parameter_names() {
        let mut catalog = MetadataCatalog::new();
        let declarations = "void inspect(char * _Nullable, int * _Nonnull);";
        assert_eq!(
            parse_c_declarations(
                &mut catalog,
                "example.dll",
                "test.h",
                declarations,
                HeaderSource::Windows
            )
            .added,
            1
        );
        let signature = catalog.lookup("example.dll", "inspect").unwrap();
        let pointer = AbiType::Pointer {
            is_const: false,
            pointee: "void".into(),
        };
        assert_eq!(
            signature
                .params
                .iter()
                .map(|param| (param.name.as_str(), param.abi_type.clone()))
                .collect::<Vec<_>>(),
            vec![("arg0", AbiType::StringAnsi), ("arg1", pointer)]
        );
    }

    #[test]
    fn pointer_return_types_are_ingested() {
        let mut catalog = MetadataCatalog::new();
        let declarations = "void *opaque(void);\nchar **table(void);\nstruct record *record(void);";
        assert_eq!(
            parse_c_declarations(
                &mut catalog,
                "example.dll",
                "test.h",
                declarations,
                HeaderSource::Windows
            )
            .added,
            3
        );
        let pointer = AbiType::Pointer {
            is_const: false,
            pointee: "void".into(),
        };
        for symbol in ["opaque", "table", "record"] {
            assert_eq!(
                catalog.lookup("example.dll", symbol).unwrap().return_type,
                pointer,
                "{symbol}"
            );
        }
    }

    #[test]
    fn public_ingestion_preserves_character_and_indirect_pointer_types() {
        let declarations = "
            typedef int constant_t;
            struct char_record;
            char*text(const char*input, char const * suffix);
            const char **strings(char **mutable_table, const char **table);
            void pointers(const int *value, int *const top, int *const *slot, const int **table, int * const, int * __restrict);
            void opaque(constant_t *value, struct char_record *record);
        ";
        let header = std::env::temp_dir().join(format!(
            "xenora-import-gen-pointer-types-{}.h",
            std::process::id()
        ));
        std::fs::write(&header, declarations).unwrap();
        let mut catalog = MetadataCatalog::new();
        let ingested = ingest_header_file(&mut catalog, "example.dll", &header);
        std::fs::remove_file(header).unwrap();
        assert_eq!(ingested.unwrap(), 4);

        let generic_pointer = |is_const| AbiType::Pointer {
            is_const,
            pointee: "void".into(),
        };
        let return_types = [
            ("text", AbiType::StringAnsi),
            ("strings", generic_pointer(false)),
            ("pointers", AbiType::Void),
            ("opaque", AbiType::Void),
        ];
        let param_types = [
            vec![AbiType::StringAnsi, AbiType::StringAnsi],
            vec![generic_pointer(false), generic_pointer(false)],
            vec![
                generic_pointer(true),
                generic_pointer(false),
                generic_pointer(true),
                generic_pointer(false),
                generic_pointer(false),
                generic_pointer(false),
            ],
            vec![generic_pointer(false), generic_pointer(false)],
        ];
        for ((symbol, ret), params) in return_types.into_iter().zip(param_types) {
            let signature = catalog.lookup("example.dll", symbol).unwrap();
            assert_eq!(signature.return_type, ret, "{symbol}");
            assert_eq!(
                signature
                    .params
                    .iter()
                    .map(|param| param.abi_type.clone())
                    .collect::<Vec<_>>(),
                params,
                "{symbol}"
            );
        }
        let pointers = catalog.lookup("example.dll", "pointers").unwrap();
        assert_eq!(pointers.params[4].name, "arg4");
        assert_eq!(pointers.params[5].name, "arg5");
    }

    #[test]
    fn header_pointer_annotations_do_not_change_the_type_or_symbol() {
        let mut catalog = MetadataCatalog::new();
        let declarations = "
            char *_LIBC_CSTR find_LIBC_CSTR(char *_LIBC_CSTR input);
        ";
        assert_eq!(
            parse_c_declarations(
                &mut catalog,
                "example.dll",
                "test.h",
                declarations,
                HeaderSource::Windows
            )
            .added,
            1
        );
        let signature = catalog.lookup("example.dll", "find_LIBC_CSTR").unwrap();
        assert_eq!(signature.return_type, AbiType::StringAnsi);
        assert_eq!(signature.params[0].name, "input");
        assert_eq!(signature.params[0].abi_type, AbiType::StringAnsi);
    }

    #[test]
    fn test_parse_declarations_from_string() {
        let mut cat = MetadataCatalog::new();
        let c_code = r#"
            extern double cos(double x);
            extern double atan2(double y, double x);
            int strcmp(const char *s1, const char *s2);
        "#;
        let count = parse_c_declarations(
            &mut cat,
            "ucrtbase.dll",
            "test.h",
            c_code,
            HeaderSource::Windows,
        )
        .added;
        assert_eq!(count, 3);
        assert!(cat.lookup("ucrtbase.dll", "cos").is_some());
        assert!(cat.lookup("ucrtbase.dll", "atan2").is_some());
        assert!(cat.lookup("ucrtbase.dll", "strcmp").is_some());
    }

    #[test]
    fn explicit_header_reports_unsupported_declarations_without_inventing_types() {
        let declarations = [
            "int before(void);",
            "int unknown(enum_value_t value);",
            "double variadic(const char *format, ...);",
            "int callback(int (*function)(int));",
            "int array(int values[4]);",
            "int unspecified();",
            "int malformed(int value,);",
            "int after(const char *message, int count);",
        ];
        let header = std::env::temp_dir().join(format!(
            "xenora-import-gen-unsupported-{}.h",
            std::process::id()
        ));
        std::fs::write(&header, declarations.join("\n")).unwrap();
        let mut catalog = MetadataCatalog::new();
        let report = ingest_header_file_with_report(&mut catalog, "Example.DLL", &header);
        std::fs::remove_file(&header).unwrap();
        let report = report.unwrap();

        assert_eq!(report.header, header.file_name().unwrap().to_str().unwrap());
        assert_eq!(report.added, 2);
        assert_eq!(report.skipped.len(), 6);
        for ((index, source), skipped) in declarations
            .iter()
            .enumerate()
            .skip(1)
            .take(6)
            .zip(&report.skipped)
        {
            assert_eq!(skipped.line, index + 1);
            assert_eq!(&skipped.declaration, source);
            assert!(!skipped.reason.trim().is_empty(), "{source}");
        }
        assert_eq!(catalog.entries.len(), 2);
        assert!(catalog.lookup("example.dll", "before").is_some());
        let after = catalog.lookup("example.dll", "after").unwrap();
        assert_eq!(after.params[0].abi_type, AbiType::StringAnsi);
        assert_eq!(after.params[1].abi_type, AbiType::I32);
    }

    #[test]
    fn ingestion_retains_reviewed_entries_and_distinguishes_symbol_case() {
        let mut catalog = MetadataCatalog::new();
        let reviewed = FunctionSignature {
            name: "SameName".into(),
            return_type: AbiType::F64,
            params: vec![],
            convention: CallingConvention::Win64,
            header_source: "reviewed".into(),
            doc: "reviewed signature".into(),
        };
        catalog
            .entries
            .insert(("example.dll".into(), "SameName".into()), reviewed.clone());
        let report = parse_c_declarations(
            &mut catalog,
            "Example.DLL",
            "incoming.h",
            "int SameName(void);\nint samename(void);",
            HeaderSource::Windows,
        );

        assert_eq!(report.added, 1);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].line, 1);
        assert_eq!(catalog.lookup("EXAMPLE.DLL", "SameName"), Some(&reviewed));
        assert_eq!(
            catalog
                .lookup("example.dll", "samename")
                .unwrap()
                .return_type,
            AbiType::I32
        );
        assert!(catalog.lookup("example.dll", "SAMENAME").is_none());
    }

    #[test]
    fn windows_long_is_32_bits_and_host_long_only_qualifies_behind_a_pointer() {
        let declarations = "long signed_value(unsigned long value);\n\
                            unsigned long unsigned_value(long value);\n\
                            void through_pointer(const unsigned long *value);";
        let mut windows = MetadataCatalog::new();
        let report = parse_c_declarations(
            &mut windows,
            "example.dll",
            "windows.h",
            declarations,
            HeaderSource::Windows,
        );
        assert_eq!(report.added, 3);
        assert!(report.skipped.is_empty());
        let signed = windows.lookup("example.dll", "signed_value").unwrap();
        let unsigned = windows.lookup("example.dll", "unsigned_value").unwrap();
        assert_eq!(signed.return_type, AbiType::I32);
        assert_eq!(signed.params[0].abi_type, AbiType::U32);
        assert_eq!(unsigned.return_type, AbiType::U32);
        assert_eq!(unsigned.params[0].abi_type, AbiType::I32);

        let mut host = MetadataCatalog::new();
        let report = parse_c_declarations(
            &mut host,
            "example.dll",
            "host.h",
            declarations,
            HeaderSource::Host,
        );
        assert_eq!(report.added, 1);
        assert_eq!(report.skipped.len(), 2);
        assert!(host.lookup("example.dll", "signed_value").is_none());
        assert!(host.lookup("example.dll", "unsigned_value").is_none());
        for catalog in [&windows, &host] {
            let pointer = catalog.lookup("example.dll", "through_pointer").unwrap();
            assert_eq!(
                pointer.params[0].abi_type,
                AbiType::Pointer {
                    is_const: true,
                    pointee: "void".into(),
                }
            );
        }
    }

    #[test]
    fn raw_headers_do_not_publish_commented_or_conditional_signatures() {
        let input = concat!(
            "/* Header notice // comment marker\n",
            "double commented(double);\n",
            "*/\n",
            "#ifndef SAMPLE_H\n",
            "#define SAMPLE_H\n",
            "#if(0)\n",
            "double resolution(double);\n",
            "#endif\n",
            "int resolution(int); /* explanation */\n",
            "#define DECLARATION \\\n",
            "int macro_body(int);\n",
            "#endif\n",
        );
        let mut catalog = MetadataCatalog::new();
        let report = parse_c_declarations(
            &mut catalog,
            "sample.dll",
            "sample.h",
            input,
            HeaderSource::Windows,
        );
        assert_eq!(report.added, 1);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].line, 7);
        assert!(catalog.lookup("sample.dll", "commented").is_none());
        assert!(catalog.lookup("sample.dll", "macro_body").is_none());
        let resolution = catalog.lookup("sample.dll", "resolution").unwrap();
        assert_eq!(resolution.return_type, AbiType::I32);
        assert_eq!(resolution.params[0].abi_type, AbiType::I32);
    }

    #[test]
    fn unmodeled_modifiers_and_invalid_pointer_bases_require_review() {
        let input = concat!(
            "void bad_width(char * __ptr32);\n",
            "__vectorcall int *different_convention(float value);\n",
            "void invalid_type(unsigned float *value);\n",
            "void good(struct record *value, unsigned short *units);\n",
        );
        let mut catalog = MetadataCatalog::new();
        let report = parse_c_declarations(
            &mut catalog,
            "sample.dll",
            "sample.h",
            input,
            HeaderSource::Windows,
        );
        assert_eq!(report.added, 1);
        assert_eq!(report.skipped.len(), 3);
        assert_eq!(
            catalog.lookup("sample.dll", "good").unwrap().params.len(),
            2
        );
    }
}
