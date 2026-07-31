use clap::{Arg, Command, CommandFactory};

use super::Cli;

pub(super) fn capabilities_json() -> serde_json::Value {
    let command = Cli::command();
    let commands = command
        .get_subcommands()
        .map(command_descriptor)
        .collect::<Vec<_>>();

    serde_json::json!({
        "schema_version": 1,
        "tool": "tracemiku-cli",
        "version": env!("CARGO_PKG_VERSION"),
        "output_contract": {
            "stdout": "one JSON document for analysis commands",
            "stderr": "diagnostics only",
            "success_exit_code": 0,
            "address_default": "hexadecimal; use the command help for explicit decimal syntax",
            "preferred_interface": "specialized commands; api is a fallback only"
        },
        "commands": commands,
    })
}

fn command_descriptor(command: &Command) -> serde_json::Value {
    let args = command
        .get_arguments()
        .filter(|arg| !matches!(arg.get_id().as_str(), "help" | "version"))
        .map(argument_descriptor)
        .collect::<Vec<_>>();
    let subcommands = command
        .get_subcommands()
        .map(command_descriptor)
        .collect::<Vec<_>>();

    serde_json::json!({
        "name": command.get_name(),
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
        for expected in ["records", "backtrace", "byte-lineage", "vm-ops"] {
            assert!(
                commands.iter().any(|command| command["name"] == expected),
                "missing {expected} from capabilities"
            );
        }
    }
}
