fn main() -> std::process::ExitCode {
    match tracemiku_cli::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let error = if let Some(analysis) =
                error.downcast_ref::<tracemiku_core::analysis::AnalysisError>()
            {
                serde_json::to_value(analysis).expect("serializable analysis error")
            } else {
                serde_json::json!({"code": "command_failed", "message": format!("{error:#}")})
            };
            println!("{}", serde_json::json!({"status": "error", "error": error}));
            std::process::ExitCode::FAILURE
        }
    }
}
