use clap::{Arg, Command, CommandFactory};

use super::Cli;

pub(super) fn capabilities_json() -> serde_json::Value {
    let command = Cli::command();
    let commands = command
        .get_subcommands()
        .map(|command| command_descriptor(command, false))
        .collect::<Vec<_>>();

    serde_json::json!({
        "schema_version": 1,
        "tool": "tracemiku-cli",
        "version": env!("CARGO_PKG_VERSION"),
        "output_contract": {
            "stdout": "one JSON document for analysis commands; list requires --json; completions emits shell source",
            "stderr": "diagnostics only",
            "success_exit_code": 0,
            "analysis_error": {"exit_code": 1, "stdout": "{status: error, error: {code, message, details?}}"},
            "usage_error": {"exit_code": 2, "stderr": "argument parser diagnostic"},
            "address_default": "hexadecimal; use the command help for explicit decimal syntax",
            "preferred_interface": "specialized commands through ./tracemiku"
        },
        "commands": commands,
        "analysis_resources": {
            "memory_budget_env": "TRACEMIKU_MEMORY_BUDGET_MB",
            "memory_budget_default_mb": 1024,
            "memory_budget_scope": "CFG and MemShadow construction; zero disables these heavy builds",
            "thread_env": "TRACEMIKU_ANALYSIS_THREADS and component-specific overrides",
            "build_concurrency_env": "TRACEMIKU_BUILD_CONCURRENCY",
            "build_wait_env": "TRACEMIKU_BUILD_WAIT_MS",
            "cross_process_build": "serialized per trace through trace.bin.analysis-build.lock",
            "memshadow_sidecar": "v8 compact mmap sections with atomic replacement"
        },
        "capture_extensions": {
            "schema_version": 2,
            "command": "trace",
            "implementation": "host",
            "profile_argument": "--target-profile",
            "profile_schema_version": 1,
            "transport": "adb-gzip",
            "recovery_command": "recover",
            "completion_boundary": "function-return",
            "default_complete_calls": 1,
            "capture_output_schema_version": 1,
            "call_limit_argument": "--max-calls",
            "agent_plugin_api_version": 1,
            "host_plugin_api_version": 1,
            "trusted_code_only": true
        },
    })
}

fn command_descriptor(command: &Command, experimental: bool) -> serde_json::Value {
    let experimental = experimental || command.get_name() == "experimental";
    let args = command
        .get_arguments()
        .filter(|arg| !matches!(arg.get_id().as_str(), "help" | "version"))
        .map(argument_descriptor)
        .collect::<Vec<_>>();
    let subcommands = command
        .get_subcommands()
        .map(|command| command_descriptor(command, experimental))
        .collect::<Vec<_>>();

    serde_json::json!({
        "name": command.get_name(),
        "stability": if experimental { "experimental" } else { "stable" },
        "about": command.get_about().map(ToString::to_string),
        "args": args,
        "subcommands": subcommands,
    })
}

fn argument_descriptor(arg: &Arg) -> serde_json::Value {
    serde_json::json!({
        "id": arg.get_id().as_str(),
        "long": arg.get_long(),
        "short": arg.get_short().map(|value| value.to_string()),
        "positional": arg.get_long().is_none() && arg.get_short().is_none(),
        "required": arg.is_required_set(),
        "action": format!("{:?}", arg.get_action()),
        "help": arg.get_help().map(ToString::to_string),
        "default_values": arg
            .get_default_values()
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>(),
        "possible_values": arg
            .get_possible_values()
            .iter()
            .map(|value| value.get_name())
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_expose_specialized_commands_and_output_contract() {
        let value = capabilities_json();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["output_contract"]["success_exit_code"], 0);

        let commands = value["commands"].as_array().expect("commands array");
        for expected in ["records", "backtrace", "byte-lineage", "experimental"] {
            assert!(
                commands.iter().any(|command| command["name"] == expected),
                "missing {expected} from capabilities"
            );
        }
    }
}
