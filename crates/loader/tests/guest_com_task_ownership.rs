// SPDX-License-Identifier: GPL-3.0-or-later

//! Build the original package on Apple Silicon with
//! `fixtures/pe/com-task-ownership/build.sh artifacts/com-task-ownership`.
//! Run `cargo test --locked --target aarch64-apple-darwin -p xenora-loader
//! --test guest_com_task_ownership` for both optimization levels.
//!
//! Microsoft specifies COM allocator [ownership], [resize failure], and
//! [variant cleanup]. VirtualQuery checks the guest's mapping independently
//! of the allocation calls, using Xenora's committed-region query contract.
//!
//! [ownership]: https://learn.microsoft.com/en-us/windows/win32/com/memory-management-rules
//! [resize failure]: https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cotaskmemrealloc
//! [variant cleanup]: https://learn.microsoft.com/en-us/windows/win32/api/propidl/nf-propidl-propvariantclear

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use xenora_loader::import_table::ImportName;
use xenora_loader::module_graph::PackageModule;
use xenora_loader::module_layout::ModuleLayoutArena;
use xenora_loader::package::{
    ImportDisposition, ImportFailure, PackageEntryEvent, PackageStartupError, PackageStartupLayout,
    run_package_startup_with_entry_observer,
};
use xenora_loader::{
    ExitReason, ImportRegistry, MockClock, ServicesState, register_standard_services,
};

const APP: &str = "com-task-ownership.exe";
const PRODUCER: &str = "task_producer.dll";
const CONSUMER: &str = "task_consumer.dll";
const COM_IMPORTS: [(&str, &str, &str); 4] = [
    (PRODUCER, "ole32.dll", "CoTaskMemAlloc"),
    (CONSUMER, "combase.dll", "CoTaskMemRealloc"),
    (CONSUMER, "combase.dll", "PropVariantClear"),
    (APP, "api-ms-win-core-com-l1-1-0.dll", "CoTaskMemFree"),
];

#[test]
fn com_task_memory_remains_owned_across_modules_and_aliases() {
    let out = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("com-task-ownership-{}", std::process::id()));
    let builder =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pe/com-task-ownership/build.sh");
    let build = Command::new("sh").arg(&builder).arg(&out).output().unwrap();
    assert!(
        build.status.success(),
        "{} failed:\n{}\n{}",
        builder.display(),
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    for optimization in ["O1", "O2"] {
        let names = [APP, PRODUCER, CONSUMER];
        let bytes = names.map(|name| std::fs::read(out.join(optimization).join(name)).unwrap());
        let package = std::array::from_fn::<_, 3, _>(|index| PackageModule {
            file_name: names[index],
            bytes: &bytes[index],
        });
        let mut completed = Vec::new();

        for image_count in [3, 2, 3] {
            let state = Arc::new(ServicesState::new(Arc::new(MockClock::new(0))));
            let mut imports = ImportRegistry::new();
            register_standard_services(&mut imports, Arc::clone(&state));
            for (_, requested, symbol) in COM_IMPORTS {
                let key = ImportName::Name(symbol.to_owned());
                let resolved = imports.binding_key(requested, &key).unwrap();
                assert_eq!(resolved.module, "combase.dll");
                assert_eq!(resolved.symbol, symbol);
            }
            let mut entry_events = Vec::new();
            let result = run_package_startup_with_entry_observer(
                &package[..image_count],
                PackageStartupLayout {
                    arena: ModuleLayoutArena {
                        base: 0x1_0000_0000,
                        size: 0x1000_0000,
                    },
                    stack_top: 0x2_0001_0000,
                    thread_tls_base: 0x3_0000_0000,
                },
                0,
                imports,
                1_000_000,
                None,
                |event| entry_events.push(event),
            );

            if image_count == 2 {
                let Err(PackageStartupError::UnresolvedImports(diagnostics)) = result else {
                    panic!("{optimization}: expected missing consumer DLL, got {result:?}");
                };
                let unresolved = diagnostics.unresolved_imports().collect::<Vec<_>>();
                assert_eq!(unresolved.len(), 2, "{optimization}: {unresolved:?}");
                for symbol in ["ClearVariant", "GrowText"] {
                    assert!(
                        unresolved.iter().any(|binding| {
                            binding.file_name == APP
                                && binding.requested_module == CONSUMER
                                && binding.symbol == ImportName::Name(symbol.to_owned())
                                && matches!(&binding.disposition, ImportDisposition::Unresolved(
                                ImportFailure::MissingModule { module }
                            ) if module == CONSUMER)
                        }),
                        "{optimization}: {unresolved:?}"
                    );
                }
                assert!(diagnostics.initialization.is_empty());
                assert!(entry_events.is_empty());
                assert_eq!(state.exit_status(), None);
                continue;
            }

            let result = result.unwrap_or_else(|error| panic!("{optimization}: {error:?}"));
            assert_eq!(
                result.execution.exit_reason,
                ExitReason::ProcessExit(0),
                "{optimization}"
            );
            assert!(result.dbt_metrics.native_bytes_emitted > 0);
            assert!(matches!(
                entry_events.as_slice(),
                [
                    PackageEntryEvent::Entering { image_index: 0, .. },
                    PackageEntryEvent::Leaving
                ]
            ));
            for (file, requested, symbol) in COM_IMPORTS {
                assert!(
                    result.diagnostics.imports.iter().any(|binding| {
                        binding.file_name == file
                            && binding.requested_module == requested
                            && binding.symbol == ImportName::Name(symbol.to_owned())
                            && matches!(&binding.disposition, ImportDisposition::Service {
                            module,
                            symbol: service,
                            data: false,
                            ..
                        } if module == requested && service == symbol)
                    }),
                    "{optimization}: expected {file} to bind {requested}!{symbol}"
                );
            }
            for (provider, index, symbol) in [
                (PRODUCER, 1, "ProduceText"),
                (PRODUCER, 1, "ProduceVariant"),
                (CONSUMER, 2, "GrowText"),
                (CONSUMER, 2, "ClearVariant"),
            ] {
                assert!(
                    result.diagnostics.imports.iter().any(|binding| {
                        binding.file_name == APP
                            && binding.requested_module == provider
                            && binding.symbol == ImportName::Name(symbol.to_owned())
                            && matches!(&binding.disposition, ImportDisposition::Package {
                            provider_index,
                            ..
                        } if *provider_index == index)
                    }),
                    "{optimization}: expected {provider}!{symbol}"
                );
            }
            completed.push(state);
        }

        for state in completed {
            assert_eq!(state.exit_status(), Some(0));
            assert!(state.standard_error().is_empty());
            assert_eq!(state.open_handle_count(), 0);
        }
    }
}
