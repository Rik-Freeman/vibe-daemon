use serde_json::json;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

async fn read_next_response_matching_id(
    stdout_reader: &mut tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    expected_id: i64,
) -> serde_json::Value {
    loop {
        let line = stdout_reader
            .next_line()
            .await
            .unwrap()
            .expect("Line from stdout");
        let val: serde_json::Value = serde_json::from_str(&line).unwrap();
        if val.get("id").and_then(|id| id.as_i64()) == Some(expected_id) {
            return val;
        }
    }
}

#[tokio::test]
async fn test_cli_stdio_handshake() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    // Setup temporary configuration directory for testing read_server_config
    let temp_dir = std::env::temp_dir().join(format!("vibe_integ_test_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .expect("Failed to create temp test dir");

    let test_conf_file = temp_dir.join("test_server.conf");
    let test_conf_content = "server { listen 80; server_name localhost; }";
    tokio::fs::write(&test_conf_file, test_conf_content)
        .await
        .expect("Failed to write test config");

    let mut child = Command::new(bin_path)
        .arg("--log-level")
        .arg("debug")
        .env("VIBE_ALLOWED_CONFIG_DIRS", temp_dir.to_str().unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon binary");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let stderr = child.stderr.take().expect("Failed to open stderr");

    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Send `initialize` request
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "integration-test-client",
                "version": "1.0.0"
            }
        }
    });

    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .expect("Failed to write initialize to stdin");
    stdin.flush().await.expect("Failed to flush stdin");

    let init_resp_line = stdout_reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("Unexpected EOF on stdout");

    // Verify response is valid JSON-RPC 2.0 initialize response
    let init_resp: serde_json::Value =
        serde_json::from_str(&init_resp_line).expect("Stdout must contain valid JSON");

    assert_eq!(init_resp["jsonrpc"], "2.0");
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "vibe-daemon");
    assert_eq!(init_resp["result"]["serverInfo"]["version"], "0.1.0");
    assert_eq!(init_resp["result"]["protocolVersion"], "2024-11-05");
    assert!(
        init_resp["result"]["capabilities"]["tools"].is_object(),
        "Tools capability must be present"
    );

    // 2. Send `notifications/initialized`
    let initialized_notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });

    stdin
        .write_all(format!("{initialized_notify}\n").as_bytes())
        .await
        .expect("Failed to write initialized notification");
    stdin.flush().await.expect("Failed to flush stdin");

    // 3. Send `tools/list`
    let tools_list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });

    stdin
        .write_all(format!("{tools_list_req}\n").as_bytes())
        .await
        .expect("Failed to write tools/list request");
    stdin.flush().await.expect("Failed to flush stdin");

    let tools_resp_line = stdout_reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("Unexpected EOF on stdout");

    let tools_resp: serde_json::Value =
        serde_json::from_str(&tools_resp_line).expect("Stdout must contain valid JSON");

    assert_eq!(tools_resp["jsonrpc"], "2.0");
    assert_eq!(tools_resp["id"], 2);

    let tools_list = tools_resp["result"]["tools"]
        .as_array()
        .expect("result.tools must be an array");
    assert_eq!(tools_list.len(), 33, "Must return 33 registered tools");

    let tool_names: Vec<&str> = tools_list
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(tool_names.contains(&"get_system_status"));
    assert!(tool_names.contains(&"read_server_config"));
    assert!(tool_names.contains(&"execute_safe_command"));
    assert!(tool_names.contains(&"manage_port"));
    assert!(tool_names.contains(&"manage_service"));
    assert!(tool_names.contains(&"list_directory"));
    assert!(tool_names.contains(&"read_file"));
    assert!(tool_names.contains(&"write_file"));
    assert!(tool_names.contains(&"search_files"));
    assert!(tool_names.contains(&"tail_logs"));
    assert!(tool_names.contains(&"write_server_config"));
    assert!(tool_names.contains(&"get_disk_usage"));
    assert!(tool_names.contains(&"get_cpu_info"));
    assert!(tool_names.contains(&"get_top_processes"));
    assert!(tool_names.contains(&"get_network_stats"));
    assert!(tool_names.contains(&"tail_service_logs"));
    assert!(tool_names.contains(&"start_background_task"));
    assert!(tool_names.contains(&"check_task_status"));
    assert!(tool_names.contains(&"get_task_output"));
    assert!(tool_names.contains(&"cancel_task"));
    assert!(tool_names.contains(&"docker_ps"));
    assert!(tool_names.contains(&"docker_logs"));
    assert!(tool_names.contains(&"docker_restart"));
    assert!(tool_names.contains(&"docker_compose_up"));
    assert!(tool_names.contains(&"docker_stats"));
    assert!(tool_names.contains(&"nginx_test_config"));
    assert!(tool_names.contains(&"nginx_reload"));
    assert!(tool_names.contains(&"nginx_list_sites"));
    assert!(tool_names.contains(&"nginx_enable_site"));
    assert!(tool_names.contains(&"nginx_disable_site"));
    assert!(tool_names.contains(&"ssl_check_expiry"));
    assert!(tool_names.contains(&"ssl_list_certs"));
    assert!(tool_names.contains(&"ssl_certbot_renew"));

    // 4. Send `tools/call` for `get_system_status`
    let call_status_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get_system_status",
            "arguments": {}
        }
    });

    stdin
        .write_all(format!("{call_status_req}\n").as_bytes())
        .await
        .expect("Failed to write tools/call get_system_status");
    stdin.flush().await.expect("Failed to flush stdin");

    let status_resp_line = stdout_reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("Unexpected EOF on stdout");

    let status_resp: serde_json::Value =
        serde_json::from_str(&status_resp_line).expect("Stdout must contain valid JSON");

    assert_eq!(status_resp["jsonrpc"], "2.0");
    assert_eq!(status_resp["id"], 3);

    let text_content = status_resp["result"]["content"][0]["text"]
        .as_str()
        .expect("Tool result text content missing");

    let parsed_status: serde_json::Value =
        serde_json::from_str(text_content).expect("Status text must be valid JSON");
    assert!(parsed_status.get("hostname").is_some());
    assert!(parsed_status.get("memory").is_some());
    assert!(parsed_status.get("services").is_some());
    assert!(parsed_status.get("listening_ports").is_some());

    // 5. Send `tools/call` for `read_server_config` (valid path)
    let call_read_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "read_server_config",
            "arguments": {
                "path": test_conf_file.to_str().unwrap()
            }
        }
    });

    stdin
        .write_all(format!("{call_read_req}\n").as_bytes())
        .await
        .expect("Failed to write tools/call read_server_config");
    stdin.flush().await.expect("Failed to flush stdin");

    let read_resp_line = stdout_reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("Unexpected EOF on stdout");

    let read_resp: serde_json::Value =
        serde_json::from_str(&read_resp_line).expect("Stdout must contain valid JSON");

    assert_eq!(read_resp["jsonrpc"], "2.0");
    assert_eq!(read_resp["id"], 4);
    assert_eq!(
        read_resp["result"]["content"][0]["text"].as_str().unwrap(),
        test_conf_content
    );

    // 6. Send `tools/call` for `read_server_config` (path traversal attempt)
    let traversal_path = format!("{}/../../etc/shadow", temp_dir.display());
    let call_trav_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "read_server_config",
            "arguments": {
                "path": traversal_path
            }
        }
    });

    stdin
        .write_all(format!("{call_trav_req}\n").as_bytes())
        .await
        .expect("Failed to write tools/call with path traversal");
    stdin.flush().await.expect("Failed to flush stdin");

    let trav_resp_line = stdout_reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("Unexpected EOF on stdout");

    let trav_resp: serde_json::Value =
        serde_json::from_str(&trav_resp_line).expect("Stdout must contain valid JSON");

    assert_eq!(trav_resp["jsonrpc"], "2.0");
    assert_eq!(trav_resp["id"], 5);
    assert_eq!(trav_resp["result"]["isError"], true);

    // 7. Send `tools/call` for `execute_safe_command` (dangerous command: rm -rf /)
    let call_danger_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "execute_safe_command",
            "arguments": {
                "command": "rm -rf /"
            }
        }
    });

    stdin
        .write_all(format!("{call_danger_req}\n").as_bytes())
        .await
        .expect("Failed to write dangerous execute_safe_command");
    stdin.flush().await.expect("Failed to flush stdin");

    let danger_resp_line = stdout_reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("Unexpected EOF on stdout");

    let danger_resp: serde_json::Value =
        serde_json::from_str(&danger_resp_line).expect("Stdout must contain valid JSON");

    assert_eq!(danger_resp["jsonrpc"], "2.0");
    assert_eq!(danger_resp["id"], 6);
    assert_eq!(danger_resp["result"]["isError"], true);
    let danger_text = danger_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(
        danger_text.contains("Security Violation"),
        "Dangerous command must be blocked with Security Violation"
    );

    // 8. Send `tools/call` for `execute_safe_command` (safe command: echo)
    let call_safe_req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "execute_safe_command",
            "arguments": {
                "command": "echo vibe_integ_test_passed"
            }
        }
    });

    stdin
        .write_all(format!("{call_safe_req}\n").as_bytes())
        .await
        .expect("Failed to write safe execute_safe_command");
    stdin.flush().await.expect("Failed to flush stdin");

    let safe_resp_line = stdout_reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("Unexpected EOF on stdout");

    let safe_resp: serde_json::Value =
        serde_json::from_str(&safe_resp_line).expect("Stdout must contain valid JSON");

    assert_eq!(safe_resp["jsonrpc"], "2.0");
    assert_eq!(safe_resp["id"], 7);
    assert!(safe_resp["result"]["isError"].is_null() || safe_resp["result"]["isError"] == false);
    assert!(
        safe_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("vibe_integ_test_passed")
    );

    // 9. Send `tools/call` for `execute_safe_command` with multi-line output to verify smart compression
    let multiline_cmd = if cfg!(windows) {
        "for /L %i in (1,1,25) do @echo item %i"
    } else {
        "seq 1 25"
    };

    let call_compress_req = json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "execute_safe_command",
            "arguments": {
                "command": multiline_cmd
            }
        }
    });

    stdin
        .write_all(format!("{call_compress_req}\n").as_bytes())
        .await
        .expect("Failed to write multiline execute_safe_command");
    stdin.flush().await.expect("Failed to flush stdin");

    let compress_resp_line = stdout_reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("Unexpected EOF on stdout");

    let compress_resp: serde_json::Value =
        serde_json::from_str(&compress_resp_line).expect("Stdout must contain valid JSON");

    assert_eq!(compress_resp["jsonrpc"], "2.0");
    assert_eq!(compress_resp["id"], 8);
    let compress_text = compress_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(
        compress_text.contains("SUCCESS: Command completed in"),
        "Must contain SUCCESS header"
    );
    assert!(
        compress_text.contains("[Output suppressed, no errors detected]"),
        "Must suppress long multi-line output"
    );

    // 10. Send `tools/call` for `manage_port` (attempting to close critical SSH port 22)
    let call_port_close_22 = json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "manage_port",
            "arguments": {
                "action": "close",
                "port": 22
            }
        }
    });

    stdin
        .write_all(format!("{call_port_close_22}\n").as_bytes())
        .await
        .expect("Failed to write manage_port close 22 request");
    stdin.flush().await.expect("Failed to flush stdin");

    let port_resp_line = stdout_reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("Unexpected EOF on stdout");

    let port_resp: serde_json::Value =
        serde_json::from_str(&port_resp_line).expect("Stdout must contain valid JSON");

    assert_eq!(port_resp["jsonrpc"], "2.0");
    assert_eq!(port_resp["id"], 9);
    assert_eq!(port_resp["result"]["isError"], true);
    let port_err_text = port_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        port_err_text.contains("Security Violation"),
        "Closing port 22 must be rejected with Security Violation"
    );
    assert!(
        port_err_text.contains("Closing critical SSH port (22) is strictly prohibited"),
        "Must specify that SSH port 22 cannot be closed"
    );

    // 11. Send `tools/call` for `manage_service` (attempting to restart protected vibe-daemon service)
    let call_service_vibe = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "manage_service",
            "arguments": {
                "service_name": "vibe-daemon",
                "action": "restart"
            }
        }
    });

    stdin
        .write_all(format!("{call_service_vibe}\n").as_bytes())
        .await
        .expect("Failed to write manage_service vibe-daemon restart request");
    stdin.flush().await.expect("Failed to flush stdin");

    let service_resp_line = stdout_reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("Unexpected EOF on stdout");

    let service_resp: serde_json::Value =
        serde_json::from_str(&service_resp_line).expect("Stdout must contain valid JSON");

    assert_eq!(service_resp["jsonrpc"], "2.0");
    assert_eq!(service_resp["id"], 10);
    assert_eq!(service_resp["result"]["isError"], true);
    let service_err_text = service_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(
        service_err_text.contains("Security Violation"),
        "Restarting vibe-daemon must be rejected with Security Violation"
    );

    // 12. Send `tools/call` for `manage_service` (allowed status check on nginx)
    let call_service_status = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "manage_service",
            "arguments": {
                "service_name": "nginx",
                "action": "status"
            }
        }
    });

    stdin
        .write_all(format!("{call_service_status}\n").as_bytes())
        .await
        .expect("Failed to write manage_service nginx status request");
    stdin.flush().await.expect("Failed to flush stdin");

    let status_check_line = stdout_reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("Unexpected EOF on stdout");

    let status_check_resp: serde_json::Value =
        serde_json::from_str(&status_check_line).expect("Stdout must contain valid JSON");

    assert_eq!(status_check_resp["jsonrpc"], "2.0");
    assert_eq!(status_check_resp["id"], 11);
    assert!(
        status_check_resp["result"]["isError"].is_null()
            || status_check_resp["result"]["isError"] == false
    );

    // 13. Close stdin and wait for child process to terminate
    drop(stdin);

    let status = child.wait().await.expect("Child process failed to exit");
    assert!(status.success());

    // 8. Verify stderr received logs without corrupting stdout
    let mut stderr_reader = BufReader::new(stderr).lines();
    let mut found_log = false;
    while let Ok(Some(line)) = stderr_reader.next_line().await {
        if line.contains("vibe-daemon")
            || line.contains("initialize")
            || line.contains("tools/call")
        {
            found_log = true;
            break;
        }
    }

    assert!(
        found_log,
        "Expected tracing logs to be emitted to stderr, keeping stdout clean"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_cli_with_custom_config_flag() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let temp_dir =
        std::env::temp_dir().join(format!("vibe_integ_custom_cfg_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .expect("Failed to create temp dir");

    let config_file = temp_dir.join("test_config.toml");
    let test_conf_file = temp_dir.join("app.conf");
    let test_conf_content = "app_setting = true";
    tokio::fs::write(&test_conf_file, test_conf_content)
        .await
        .expect("Failed to write app config");

    let temp_dir_str = temp_dir.to_str().unwrap().replace('\\', "/");
    let toml_content = format!(
        r#"
[daemon]
log_level = "debug"
default_command_timeout_secs = 20

[security]
protected_ports = [22, 9999]
protected_services = ["vibe-daemon", "sshd", "custom-db"]

[inspector]
allowed_config_dirs = ["{temp_dir_str}"]
"#
    );
    tokio::fs::write(&config_file, toml_content)
        .await
        .expect("Failed to write TOML config");

    let mut child = Command::new(bin_path)
        .arg("--config")
        .arg(&config_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon with --config");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let _stderr = child.stderr.take().expect("Failed to open stderr");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let init_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let init_resp: serde_json::Value = serde_json::from_str(&init_resp_line).unwrap();
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "vibe-daemon");
    assert_eq!(
        init_resp["result"]["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );

    // 2. Call manage_port close 9999 (must be blocked by custom protected_ports)
    let call_port = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "manage_port",
            "arguments": {
                "action": "close",
                "port": 9999
            }
        }
    });
    stdin
        .write_all(format!("{call_port}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let port_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let port_resp: serde_json::Value = serde_json::from_str(&port_resp_line).unwrap();
    assert_eq!(port_resp["result"]["isError"], true);
    assert!(
        port_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Closing protected port (9999)")
    );

    // 3. Call manage_service restart custom-db (must be blocked by custom protected_services)
    let call_svc = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "manage_service",
            "arguments": {
                "service_name": "custom-db",
                "action": "restart"
            }
        }
    });
    stdin
        .write_all(format!("{call_svc}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let svc_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let svc_resp: serde_json::Value = serde_json::from_str(&svc_resp_line).unwrap();
    assert_eq!(svc_resp["result"]["isError"], true);
    assert!(
        svc_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Managing critical service 'custom-db'")
    );

    // 4. Read config from allowed_config_dirs
    let call_read = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "read_server_config",
            "arguments": {
                "path": test_conf_file.to_str().unwrap()
            }
        }
    });
    stdin
        .write_all(format!("{call_read}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let read_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let read_resp: serde_json::Value = serde_json::from_str(&read_resp_line).unwrap();
    assert_eq!(
        read_resp["result"]["content"][0]["text"].as_str().unwrap(),
        test_conf_content
    );

    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_cli_audit_trail_logging() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let temp_dir = std::env::temp_dir().join(format!("vibe_integ_audit_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .expect("Failed to create temp dir");

    let audit_file = temp_dir.join("audit_trail.jsonl");

    let mut child = Command::new(bin_path)
        .arg("--audit-log")
        .arg(&audit_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon with --audit-log");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let _stderr = child.stderr.take().expect("Failed to open stderr");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Initialize with specific client info
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "clientInfo": {
                "name": "claude-desktop",
                "version": "1.2.3"
            }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _init_resp = stdout_reader.next_line().await.unwrap().unwrap();

    // 2. Call successful tool: execute_safe_command
    let call_echo = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "execute_safe_command",
            "arguments": {
                "command": "echo audit_record_success"
            }
        }
    });
    stdin
        .write_all(format!("{call_echo}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _echo_resp = stdout_reader.next_line().await.unwrap().unwrap();

    // 3. Call blocked/error tool: manage_port closing port 22
    let call_blocked = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "manage_port",
            "arguments": {
                "action": "close",
                "port": 22
            }
        }
    });
    stdin
        .write_all(format!("{call_blocked}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _blocked_resp = stdout_reader.next_line().await.unwrap().unwrap();

    // Close stdin and wait for clean exit so all background writes flush
    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success());

    // Small delay to ensure async file flush if needed
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify audit log file exists and contains valid JSONL
    assert!(
        audit_file.exists(),
        "Audit log file must be created on disk"
    );
    let content = tokio::fs::read_to_string(&audit_file).await.unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        2,
        "Expected exactly 2 audit log records in JSONL"
    );

    let rec1: serde_json::Value =
        serde_json::from_str(lines[0]).expect("Line 1 must be valid JSON");
    assert_eq!(rec1["tool"], "execute_safe_command");
    assert_eq!(rec1["status"], "success");
    assert_eq!(rec1["client"], "claude-desktop");
    assert_eq!(rec1["arguments"]["command"], "echo audit_record_success");
    assert_eq!(rec1["sequence"], 1);
    assert_eq!(rec1["previous_hash"], vibe_daemon::audit::GENESIS_HASH);
    assert!(rec1["record_hash"].is_string());
    assert!(rec1["duration_ms"].is_number());
    assert!(rec1["timestamp"].as_str().unwrap().contains("T"));

    let rec2: serde_json::Value =
        serde_json::from_str(lines[1]).expect("Line 2 must be valid JSON");
    assert_eq!(rec2["tool"], "manage_port");
    assert_eq!(rec2["status"], "error");
    assert_eq!(rec2["client"], "claude-desktop");
    assert_eq!(rec2["arguments"]["action"], "close");
    assert_eq!(rec2["arguments"]["port"], 22);
    assert_eq!(rec2["sequence"], 2);
    assert_eq!(rec2["previous_hash"], rec1["record_hash"]);
    assert!(rec2["record_hash"].is_string());
    assert!(rec2["duration_ms"].is_number());

    // Verify entire hash chain integrity via library function
    let report = vibe_daemon::audit::verify_audit_log_file(&audit_file)
        .await
        .unwrap();
    assert_eq!(report.total_records, 2);
    assert_eq!(report.last_sequence, 2);
    assert_eq!(report.last_hash, rec2["record_hash"].as_str().unwrap());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_cli_audit_trail_tamper_evident_and_redaction() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let temp_dir =
        std::env::temp_dir().join(format!("vibe_integ_audit_redact_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .expect("Failed to create temp dir");

    let audit_file = temp_dir.join("audit_redact.jsonl");

    let mut child = Command::new(bin_path)
        .arg("--audit-log")
        .arg(&audit_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon with --audit-log");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {},
            "clientInfo": {
                "name": "redaction-test-client",
                "version": "1.0.0"
            }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _ = stdout_reader.next_line().await.unwrap().unwrap();

    // 2. Call tool with secret tokens in arguments
    let call_secret = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "execute_safe_command",
            "arguments": {
                "command": "echo Authorization: Bearer secret_jwt_token_999 --password=my_db_secret_pass"
            }
        }
    });
    stdin
        .write_all(format!("{call_secret}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _ = stdout_reader.next_line().await.unwrap().unwrap();

    // Close stdin to trigger graceful shutdown and audit flush
    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success());

    // Verify audit log content
    assert!(audit_file.exists());
    let content = tokio::fs::read_to_string(&audit_file).await.unwrap();

    // Sensitive secrets MUST be redacted, NOT in cleartext
    assert!(
        !content.contains("secret_jwt_token_999"),
        "Bearer token must not leak into audit log"
    );
    assert!(
        !content.contains("my_db_secret_pass"),
        "Password must not leak into audit log"
    );
    assert!(
        content.contains("Bearer [REDACTED]"),
        "Bearer token must be masked with [REDACTED]"
    );
    assert!(
        content.contains("--password=[REDACTED]"),
        "Password param must be masked with [REDACTED]"
    );

    // Verify cryptographic integrity of the redacted audit record
    let report = vibe_daemon::audit::verify_audit_log_file(&audit_file)
        .await
        .unwrap();
    assert_eq!(report.total_records, 1);
    assert_eq!(report.last_sequence, 1);

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_cli_rate_limiting_via_config() {
    let temp_dir =
        std::env::temp_dir().join(format!("vibe_rate_limit_test_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let audit_file = temp_dir.join("audit.jsonl");
    let config_file = temp_dir.join("config.toml");

    let audit_path_str = audit_file.to_string_lossy().replace('\\', "/");
    let toml_content = format!(
        r#"[security]
max_calls_per_minute = 1

[audit]
log_path = "{audit_path_str}"
"#
    );
    tokio::fs::write(&config_file, toml_content).await.unwrap();

    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");
    let mut cmd = Command::new(bin_path);
    cmd.arg("--config").arg(&config_file);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn vibe-daemon");
    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "rate-limit-tester", "version": "1.0" }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _init_resp = stdout_reader.next_line().await.unwrap().unwrap();

    let init_notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(format!("{init_notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 2. First call within limit (limit = 1) -> must succeed
    let call1 = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "get_system_status",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{call1}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let resp1_line = stdout_reader.next_line().await.unwrap().unwrap();
    let resp1: serde_json::Value = serde_json::from_str(&resp1_line).unwrap();
    assert_eq!(resp1["id"], 2);
    assert!(resp1["result"]["isError"].is_null());

    // 3. Second call exceeds limit (limit = 1) -> must be rejected with isError: true
    let call2 = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get_system_status",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{call2}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let resp2_line = stdout_reader.next_line().await.unwrap().unwrap();
    let resp2: serde_json::Value = serde_json::from_str(&resp2_line).unwrap();
    assert_eq!(resp2["id"], 3);
    assert_eq!(resp2["result"]["isError"], true);
    let err_msg = resp2["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(
        err_msg,
        "Rate limit exceeded: too many tool calls. Please wait a moment before retrying."
    );

    // Close stdin and verify child exits cleanly
    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success());

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify audit log
    assert!(audit_file.exists());
    let audit_content = tokio::fs::read_to_string(&audit_file).await.unwrap();
    let lines: Vec<&str> = audit_content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 2);

    let rec1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(rec1["status"], "success");

    let rec2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(rec2["status"], "error");
    assert_eq!(
        rec2["error"],
        "Rate limit exceeded: too many tool calls. Please wait a moment before retrying."
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_cli_file_operations_and_security_guard() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let temp_dir = std::env::temp_dir().join(format!("vibe_cli_fileops_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let mut cmd = Command::new(bin_path);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn vibe-daemon");
    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "file-ops-tester", "version": "1.0" }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _init_resp = stdout_reader.next_line().await.unwrap().unwrap();

    let init_notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(format!("{init_notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 2. Safe write_file to temp path
    let test_file = temp_dir.join("test_file.txt");
    let test_file_str = test_file.to_string_lossy().replace('\\', "/");

    let write_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": test_file_str,
                "content": "Line A\nLine B\nLine C"
            }
        }
    });
    stdin
        .write_all(format!("{write_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let w_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let w_val: serde_json::Value = serde_json::from_str(&w_resp_line).unwrap();
    assert_eq!(w_val["id"], 2);
    assert!(w_val["result"]["isError"].is_null());
    assert!(
        w_val["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Successfully wrote")
    );

    // 3. Safe read_file from temp path
    let read_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": test_file_str
            }
        }
    });
    stdin
        .write_all(format!("{read_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let r_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let r_val: serde_json::Value = serde_json::from_str(&r_resp_line).unwrap();
    assert_eq!(r_val["id"], 3);
    assert!(r_val["result"]["isError"].is_null());
    assert_eq!(
        r_val["result"]["content"][0]["text"].as_str().unwrap(),
        "Line A\nLine B\nLine C"
    );

    // 4. write_file attempt on protected /etc/shadow -> must fail with isError: true
    let shadow_write_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "/etc/shadow",
                "content": "hacked"
            }
        }
    });
    stdin
        .write_all(format!("{shadow_write_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let sw_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let sw_val: serde_json::Value = serde_json::from_str(&sw_resp_line).unwrap();
    assert_eq!(sw_val["id"], 4);
    assert_eq!(sw_val["result"]["isError"], true);
    let sw_err = sw_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(sw_err.contains("Security Violation"));
    assert!(sw_err.contains("forbidden"));

    // 5. read_file attempt on /etc/shadow -> must fail with isError: true
    let shadow_read_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "/etc/shadow"
            }
        }
    });
    stdin
        .write_all(format!("{shadow_read_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let sr_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let sr_val: serde_json::Value = serde_json::from_str(&sr_resp_line).unwrap();
    assert_eq!(sr_val["id"], 5);
    assert_eq!(sr_val["result"]["isError"], true);
    let sr_err = sr_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(sr_err.contains("Security Violation"));

    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_cli_write_server_config_and_rollback() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let temp_dir =
        std::env::temp_dir().join(format!("vibe_integ_cfg_writer_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .expect("Failed to create temp dir");

    let mut child = Command::new(bin_path)
        .arg("--log-level")
        .arg("error")
        .env("VIBE_ALLOWED_CONFIG_DIRS", temp_dir.to_str().unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon");

    let mut stdin = child.stdin.take().expect("Failed to get stdin");
    let stdout = child.stdout.take().expect("Failed to get stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Handshake
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "integration-test-client",
                "version": "1.0.0"
            }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _init_resp = stdout_reader.next_line().await.unwrap().unwrap();

    let init_notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(format!("{init_notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 2. Create initial configuration file
    let conf_path = temp_dir.join("nginx.conf");
    let conf_path_str = conf_path.to_string_lossy().replace('\\', "/");
    tokio::fs::write(&conf_path, "server { listen 80; }")
        .await
        .unwrap();

    // 3. write_server_config with successful validation
    let write_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "write_server_config",
            "arguments": {
                "path": conf_path_str,
                "content": "server { listen 8080; }",
                "validate_command": "echo config_syntax_valid"
            }
        }
    });
    stdin
        .write_all(format!("{write_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let w_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let w_val: serde_json::Value = serde_json::from_str(&w_resp_line).unwrap();
    assert_eq!(w_val["id"], 2);
    assert!(w_val["result"]["isError"].is_null() || w_val["result"]["isError"] == false);

    let text_content = w_val["result"]["content"][0]["text"].as_str().unwrap();
    let res_obj: serde_json::Value = serde_json::from_str(text_content).unwrap();
    assert_eq!(res_obj["status"], "success");
    let backup_path = res_obj["backup_path"]
        .as_str()
        .expect("Must have backup_path");

    // Verify target file has updated content
    let current_content = tokio::fs::read_to_string(&conf_path).await.unwrap();
    assert_eq!(current_content, "server { listen 8080; }");

    // Verify backup file exists and has previous content
    let backup_content = tokio::fs::read_to_string(backup_path).await.unwrap();
    assert_eq!(backup_content, "server { listen 80; }");

    // 4. write_server_config with failing validation -> must trigger rollback
    let fail_cmd = if cfg!(windows) {
        "cmd /C exit 1"
    } else {
        "sh -c 'exit 1'"
    };

    let fail_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "write_server_config",
            "arguments": {
                "path": conf_path_str,
                "content": "syntax error bad config",
                "validate_command": fail_cmd
            }
        }
    });
    stdin
        .write_all(format!("{fail_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let f_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let f_val: serde_json::Value = serde_json::from_str(&f_resp_line).unwrap();
    assert_eq!(f_val["id"], 3);
    assert_eq!(f_val["result"]["isError"], true);

    let err_msg = f_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(err_msg.contains("validation failed"));
    assert!(err_msg.contains("Successfully restored original configuration"));

    // Verify target file was restored to previous valid content
    let rolled_back_content = tokio::fs::read_to_string(&conf_path).await.unwrap();
    assert_eq!(rolled_back_content, "server { listen 8080; }");

    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_cli_monitoring_subsystem_stdio() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let mut child = Command::new(bin_path)
        .arg("--log-level")
        .arg("debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon binary");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Initialize handshake
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "monitoring-test-client",
                "version": "1.0.0"
            }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let init_line = stdout_reader.next_line().await.unwrap().unwrap();
    let init_resp: serde_json::Value = serde_json::from_str(&init_line).unwrap();
    assert_eq!(init_resp["id"], 1);

    // 2. notifications/initialized
    let notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    stdin
        .write_all(format!("{notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 3. Call get_disk_usage
    let disk_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "get_disk_usage",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{disk_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let disk_line = stdout_reader.next_line().await.unwrap().unwrap();
    let disk_val: serde_json::Value = serde_json::from_str(&disk_line).unwrap();
    assert_eq!(disk_val["id"], 2);
    assert!(disk_val["result"]["isError"].is_null() || disk_val["result"]["isError"] == false);
    let disk_text = disk_val["result"]["content"][0]["text"].as_str().unwrap();
    let disk_array: serde_json::Value =
        serde_json::from_str(disk_text).expect("Disk usage must be valid JSON array");
    assert!(disk_array.is_array());

    // 4. Call get_cpu_info
    let cpu_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get_cpu_info",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{cpu_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let cpu_line = stdout_reader.next_line().await.unwrap().unwrap();
    let cpu_val: serde_json::Value = serde_json::from_str(&cpu_line).unwrap();
    assert_eq!(cpu_val["id"], 3);
    assert!(cpu_val["result"]["isError"].is_null() || cpu_val["result"]["isError"] == false);
    let cpu_text = cpu_val["result"]["content"][0]["text"].as_str().unwrap();
    let cpu_obj: serde_json::Value =
        serde_json::from_str(cpu_text).expect("Cpu info must be valid JSON object");
    assert!(cpu_obj["cpu_count"].as_u64().unwrap_or(0) >= 1);
    assert!(cpu_obj["load_average"].is_object());

    // 5. Call get_top_processes
    let proc_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "get_top_processes",
            "arguments": {
                "limit": 3,
                "sort_by": "cpu"
            }
        }
    });
    stdin
        .write_all(format!("{proc_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let proc_line = stdout_reader.next_line().await.unwrap().unwrap();
    let proc_val: serde_json::Value = serde_json::from_str(&proc_line).unwrap();
    assert_eq!(proc_val["id"], 4);
    assert!(proc_val["result"]["isError"].is_null() || proc_val["result"]["isError"] == false);
    let proc_text = proc_val["result"]["content"][0]["text"].as_str().unwrap();
    let proc_arr: serde_json::Value =
        serde_json::from_str(proc_text).expect("Procs must be valid JSON array");
    assert!(proc_arr.is_array());
    assert!(proc_arr.as_array().unwrap().len() <= 3);

    // 6. Call get_network_stats
    let net_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "get_network_stats",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{net_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let net_line = stdout_reader.next_line().await.unwrap().unwrap();
    let net_val: serde_json::Value = serde_json::from_str(&net_line).unwrap();
    assert_eq!(net_val["id"], 5);
    assert!(net_val["result"]["isError"].is_null() || net_val["result"]["isError"] == false);
    let net_text = net_val["result"]["content"][0]["text"].as_str().unwrap();
    let net_obj: serde_json::Value =
        serde_json::from_str(net_text).expect("Network stats must be valid JSON object");
    assert!(net_obj["interfaces"].is_array());

    // 7. Call tail_service_logs (safe service)
    let log_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "tail_service_logs",
            "arguments": {
                "service_name": "nginx",
                "lines": 15
            }
        }
    });
    stdin
        .write_all(format!("{log_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let log_line = stdout_reader.next_line().await.unwrap().unwrap();
    let log_val: serde_json::Value = serde_json::from_str(&log_line).unwrap();
    assert_eq!(log_val["id"], 6);
    assert!(log_val["result"]["isError"].is_null() || log_val["result"]["isError"] == false);
    let log_text = log_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(log_text.contains("nginx"));

    // 8. Call tail_service_logs with command injection attempt (must be blocked by Guard)
    let inj_req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "tail_service_logs",
            "arguments": {
                "service_name": "nginx; cat /etc/shadow",
                "lines": 10
            }
        }
    });
    stdin
        .write_all(format!("{inj_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let inj_line = stdout_reader.next_line().await.unwrap().unwrap();
    let inj_val: serde_json::Value = serde_json::from_str(&inj_line).unwrap();
    assert_eq!(inj_val["id"], 7);
    assert_eq!(inj_val["result"]["isError"], true);
    let inj_text = inj_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(inj_text.contains("Security Violation"));

    // 9. Call tail_service_logs with valid since and until RFC 3339 timestamps
    let log_time_req = json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "tail_service_logs",
            "arguments": {
                "service_name": "nginx",
                "lines": 20,
                "since": "2026-10-14T00:00:00Z",
                "until": "2026-10-14T12:00:00Z"
            }
        }
    });
    stdin
        .write_all(format!("{log_time_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let log_time_line = stdout_reader.next_line().await.unwrap().unwrap();
    let log_time_val: serde_json::Value = serde_json::from_str(&log_time_line).unwrap();
    assert_eq!(log_time_val["id"], 8);
    assert!(
        log_time_val["result"]["isError"].is_null() || log_time_val["result"]["isError"] == false
    );
    let log_time_text = log_time_val["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(log_time_text.contains("nginx"));

    // 10. Call tail_service_logs with invalid RFC 3339 format (must return isError)
    let bad_time_req = json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "tail_service_logs",
            "arguments": {
                "service_name": "nginx",
                "since": "invalid-timestamp-format"
            }
        }
    });
    stdin
        .write_all(format!("{bad_time_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let bad_time_line = stdout_reader.next_line().await.unwrap().unwrap();
    let bad_time_val: serde_json::Value = serde_json::from_str(&bad_time_line).unwrap();
    assert_eq!(bad_time_val["id"], 9);
    assert_eq!(bad_time_val["result"]["isError"], true);
    assert!(
        bad_time_val["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Invalid 'since' timestamp format")
    );

    // 11. Call tail_service_logs with inverted time window (since > until)
    let inv_time_req = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "tail_service_logs",
            "arguments": {
                "service_name": "nginx",
                "since": "2026-10-14T18:00:00Z",
                "until": "2026-10-14T06:00:00Z"
            }
        }
    });
    stdin
        .write_all(format!("{inv_time_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let inv_time_line = stdout_reader.next_line().await.unwrap().unwrap();
    let inv_time_val: serde_json::Value = serde_json::from_str(&inv_time_line).unwrap();
    assert_eq!(inv_time_val["id"], 10);
    assert_eq!(inv_time_val["result"]["isError"], true);
    assert!(
        inv_time_val["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Invalid time range")
    );

    // 12. Call tail_service_logs with pipe shell injection attempt (must be blocked by Guard)
    let pipe_req = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "tail_service_logs",
            "arguments": {
                "service_name": "nginx | whoami"
            }
        }
    });
    stdin
        .write_all(format!("{pipe_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let pipe_line = stdout_reader.next_line().await.unwrap().unwrap();
    let pipe_val: serde_json::Value = serde_json::from_str(&pipe_line).unwrap();
    assert_eq!(pipe_val["id"], 11);
    assert_eq!(pipe_val["result"]["isError"], true);
    assert!(
        pipe_val["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Security Violation")
    );

    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success());
}

#[tokio::test]
async fn test_cli_background_tasks_stdio() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let mut child = Command::new(bin_path)
        .arg("--log-level")
        .arg("debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon binary");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "bg-integration-client",
                "version": "1.0.0"
            }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let init_line = stdout_reader.next_line().await.unwrap().unwrap();
    let init_resp: serde_json::Value = serde_json::from_str(&init_line).unwrap();
    assert_eq!(init_resp["id"], 1);

    // 2. notifications/initialized
    let notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    stdin
        .write_all(format!("{notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 3. Start a safe background task
    let start_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "start_background_task",
            "arguments": {
                "command": "echo bg_integration_token_xyz"
            }
        }
    });
    stdin
        .write_all(format!("{start_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let start_line = stdout_reader.next_line().await.unwrap().unwrap();
    let start_val: serde_json::Value = serde_json::from_str(&start_line).unwrap();
    assert_eq!(start_val["id"], 2);
    assert!(start_val["result"]["isError"].is_null() || start_val["result"]["isError"] == false);
    let start_text = start_val["result"]["content"][0]["text"].as_str().unwrap();
    let start_json: serde_json::Value = serde_json::from_str(start_text).unwrap();
    let task_id = start_json["task_id"].as_str().unwrap();

    // 4. Poll check_task_status until task finishes
    let mut completed = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let check_req = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "check_task_status",
                "arguments": {
                    "task_id": task_id
                }
            }
        });
        stdin
            .write_all(format!("{check_req}\n").as_bytes())
            .await
            .unwrap();
        stdin.flush().await.unwrap();

        let check_val = read_next_response_matching_id(&mut stdout_reader, 3).await;
        let check_text = check_val["result"]["content"][0]["text"].as_str().unwrap();
        let report: serde_json::Value = serde_json::from_str(check_text).unwrap();
        if report["status"] == "Success" {
            completed = true;
            break;
        }
    }
    assert!(completed, "Background task should complete with Success");

    // 5. Get task output
    let out_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "get_task_output",
            "arguments": {
                "task_id": task_id
            }
        }
    });
    stdin
        .write_all(format!("{out_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let out_val = read_next_response_matching_id(&mut stdout_reader, 4).await;
    let out_text = out_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(out_text.contains("bg_integration_token_xyz"));

    // 6. Test cancellation with sleep
    let sleep_cmd = if cfg!(windows) {
        "powershell -Command \"Start-Sleep -Seconds 10\""
    } else {
        "sleep 10"
    };
    let start_sleep_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "start_background_task",
            "arguments": {
                "command": sleep_cmd
            }
        }
    });
    stdin
        .write_all(format!("{start_sleep_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let sleep_val = read_next_response_matching_id(&mut stdout_reader, 5).await;
    let sleep_text = sleep_val["result"]["content"][0]["text"].as_str().unwrap();
    let sleep_json: serde_json::Value = serde_json::from_str(sleep_text).unwrap();
    let sleep_task_id = sleep_json["task_id"].as_str().unwrap();

    let cancel_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "cancel_task",
            "arguments": {
                "task_id": sleep_task_id
            }
        }
    });
    stdin
        .write_all(format!("{cancel_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let cancel_val = read_next_response_matching_id(&mut stdout_reader, 6).await;
    let cancel_text = cancel_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(cancel_text.contains("successfully cancelled"));

    // 7. Verify Guard blocks dangerous background task
    let dang_req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "start_background_task",
            "arguments": {
                "command": "rm -rf /"
            }
        }
    });
    stdin
        .write_all(format!("{dang_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let dang_val = read_next_response_matching_id(&mut stdout_reader, 7).await;
    assert_eq!(dang_val["id"], 7);
    assert_eq!(dang_val["result"]["isError"], true);
    let dang_text = dang_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(dang_text.contains("Security Violation"));

    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success());
}

#[tokio::test]
async fn test_cli_docker_manager_stdio() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");
    let mut child = Command::new(bin_path)
        .arg("--log-level")
        .arg("debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon binary");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "docker-integration-client",
                "version": "1.0.0"
            }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let init_line = stdout_reader.next_line().await.unwrap().unwrap();
    let init_resp: serde_json::Value = serde_json::from_str(&init_line).unwrap();
    assert_eq!(init_resp["id"], 1);

    // 2. notifications/initialized
    let notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    stdin
        .write_all(format!("{notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 3. tools/list verification
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    stdin
        .write_all(format!("{list_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let list_line = stdout_reader.next_line().await.unwrap().unwrap();
    let list_val: serde_json::Value = serde_json::from_str(&list_line).unwrap();
    assert_eq!(list_val["id"], 2);
    let tools = list_val["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 33);
    let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(tool_names.contains(&"docker_ps"));
    assert!(tool_names.contains(&"docker_logs"));
    assert!(tool_names.contains(&"docker_restart"));
    assert!(tool_names.contains(&"docker_compose_up"));
    assert!(tool_names.contains(&"docker_stats"));

    // 4. tools/call: docker_ps
    let ps_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "docker_ps",
            "arguments": {
                "all": true
            }
        }
    });
    stdin
        .write_all(format!("{ps_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let ps_line = stdout_reader.next_line().await.unwrap().unwrap();
    let ps_val: serde_json::Value = serde_json::from_str(&ps_line).unwrap();
    assert_eq!(ps_val["id"], 3);
    let ps_text = ps_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!ps_text.is_empty());

    // 5. tools/call: docker_logs injection blocked by Guard
    let logs_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "docker_logs",
            "arguments": {
                "container_name_or_id": "c1; rm -rf /"
            }
        }
    });
    stdin
        .write_all(format!("{logs_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let logs_line = stdout_reader.next_line().await.unwrap().unwrap();
    let logs_val: serde_json::Value = serde_json::from_str(&logs_line).unwrap();
    assert_eq!(logs_val["id"], 4);
    assert_eq!(logs_val["result"]["isError"], true);
    let logs_err = logs_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(logs_err.contains("Security Violation"));

    // 6. tools/call: docker_restart injection blocked by Guard
    let restart_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "docker_restart",
            "arguments": {
                "container_name_or_id": "c1 && reboot"
            }
        }
    });
    stdin
        .write_all(format!("{restart_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let restart_line = stdout_reader.next_line().await.unwrap().unwrap();
    let restart_val: serde_json::Value = serde_json::from_str(&restart_line).unwrap();
    assert_eq!(restart_val["id"], 5);
    assert_eq!(restart_val["result"]["isError"], true);
    let restart_err = restart_val["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(restart_err.contains("Security Violation"));

    // 7. tools/call: docker_compose_up forbidden path blocked by Guard
    let compose_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "docker_compose_up",
            "arguments": {
                "file_path": "/etc/shadow"
            }
        }
    });
    stdin
        .write_all(format!("{compose_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let compose_line = stdout_reader.next_line().await.unwrap().unwrap();
    let compose_val: serde_json::Value = serde_json::from_str(&compose_line).unwrap();
    assert_eq!(compose_val["id"], 6);
    assert_eq!(compose_val["result"]["isError"], true);
    let compose_err = compose_val["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(compose_err.contains("Security Violation"));

    // 8. tools/call: docker_stats
    let stats_req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "docker_stats",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{stats_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let stats_line = stdout_reader.next_line().await.unwrap().unwrap();
    let stats_val: serde_json::Value = serde_json::from_str(&stats_line).unwrap();
    assert_eq!(stats_val["id"], 7);
    let stats_text = stats_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!stats_text.is_empty());

    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success());
}

#[tokio::test]
async fn test_cli_webserver_manager_stdio() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");
    let mut child = Command::new(bin_path)
        .arg("--log-level")
        .arg("debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon binary");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "webserver-integration-client",
                "version": "1.0.0"
            }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let init_line = stdout_reader.next_line().await.unwrap().unwrap();
    let init_resp: serde_json::Value = serde_json::from_str(&init_line).unwrap();
    assert_eq!(init_resp["id"], 1);

    // 2. notifications/initialized
    let notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    stdin
        .write_all(format!("{notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 3. tools/list verification
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    stdin
        .write_all(format!("{list_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let list_line = stdout_reader.next_line().await.unwrap().unwrap();
    let list_val: serde_json::Value = serde_json::from_str(&list_line).unwrap();
    assert_eq!(list_val["id"], 2);
    let tools = list_val["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 33);
    let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(tool_names.contains(&"nginx_test_config"));
    assert!(tool_names.contains(&"nginx_reload"));
    assert!(tool_names.contains(&"nginx_list_sites"));
    assert!(tool_names.contains(&"nginx_enable_site"));
    assert!(tool_names.contains(&"nginx_disable_site"));

    // 4. tools/call: nginx_test_config
    let test_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "nginx_test_config",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{test_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let test_line = stdout_reader.next_line().await.unwrap().unwrap();
    let test_val: serde_json::Value = serde_json::from_str(&test_line).unwrap();
    assert_eq!(test_val["id"], 3);
    let test_text = test_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!test_text.is_empty());

    // 5. tools/call: nginx_test_config forbidden file blocked by Guard
    let forb_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "nginx_test_config",
            "arguments": {
                "config_path": "/etc/shadow"
            }
        }
    });
    stdin
        .write_all(format!("{forb_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let forb_line = stdout_reader.next_line().await.unwrap().unwrap();
    let forb_val: serde_json::Value = serde_json::from_str(&forb_line).unwrap();
    assert_eq!(forb_val["id"], 4);
    assert_eq!(forb_val["result"]["isError"], true);
    let forb_err = forb_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(forb_err.contains("Security Violation"));

    // 6. tools/call: nginx_reload
    let reload_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "nginx_reload",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{reload_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let reload_line = stdout_reader.next_line().await.unwrap().unwrap();
    let reload_val: serde_json::Value = serde_json::from_str(&reload_line).unwrap();
    assert_eq!(reload_val["id"], 5);
    let reload_text = reload_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!reload_text.is_empty());

    // 7. tools/call: nginx_list_sites
    let list_sites_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "nginx_list_sites",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{list_sites_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let list_sites_line = stdout_reader.next_line().await.unwrap().unwrap();
    let list_sites_val: serde_json::Value = serde_json::from_str(&list_sites_line).unwrap();
    assert_eq!(list_sites_val["id"], 6);
    let list_sites_text = list_sites_val["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(!list_sites_text.is_empty());

    // 8. tools/call: nginx_enable_site injection blocked by Guard
    let enable_req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "nginx_enable_site",
            "arguments": {
                "site_name": "app; reboot"
            }
        }
    });
    stdin
        .write_all(format!("{enable_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let enable_line = stdout_reader.next_line().await.unwrap().unwrap();
    let enable_val: serde_json::Value = serde_json::from_str(&enable_line).unwrap();
    assert_eq!(enable_val["id"], 7);
    assert_eq!(enable_val["result"]["isError"], true);
    let enable_err = enable_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        enable_err.contains("Invalid characters") || enable_err.contains("strictly prohibited")
    );

    // 9. tools/call: nginx_disable_site traversal blocked by Guard
    let disable_req = json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "nginx_disable_site",
            "arguments": {
                "site_name": "../etc/shadow"
            }
        }
    });
    stdin
        .write_all(format!("{disable_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let disable_line = stdout_reader.next_line().await.unwrap().unwrap();
    let disable_val: serde_json::Value = serde_json::from_str(&disable_line).unwrap();
    assert_eq!(disable_val["id"], 8);
    assert_eq!(disable_val["result"]["isError"], true);
    let disable_err = disable_val["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(disable_err.contains("Path traversal") || disable_err.contains("strictly prohibited"));

    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success());
}

#[tokio::test]
async fn test_cli_ssl_manager_stdio() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let temp_dir = std::env::temp_dir().join(format!("vibe_ssl_integ_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .expect("Failed to create test dir");

    let mut child = Command::new(bin_path)
        .arg("--log-level")
        .arg("debug")
        .env("VIBE_ALLOWED_CONFIG_DIRS", temp_dir.to_str().unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon binary");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "integration-ssl-client",
                "version": "1.0.0"
            }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let init_line = stdout_reader.next_line().await.unwrap().unwrap();
    let init_val: serde_json::Value = serde_json::from_str(&init_line).unwrap();
    assert_eq!(init_val["id"], 1);

    // 2. notifications/initialized
    let notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    stdin
        .write_all(format!("{notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 3. tools/list
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    stdin
        .write_all(format!("{list_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let list_line = stdout_reader.next_line().await.unwrap().unwrap();
    let list_val: serde_json::Value = serde_json::from_str(&list_line).unwrap();
    assert_eq!(list_val["id"], 2);
    let tools = list_val["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 33);
    let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(tool_names.contains(&"ssl_check_expiry"));
    assert!(tool_names.contains(&"ssl_list_certs"));
    assert!(tool_names.contains(&"ssl_certbot_renew"));

    // 4. tools/call: ssl_check_expiry (scan directories)
    let expiry_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "ssl_check_expiry",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{expiry_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let expiry_line = stdout_reader.next_line().await.unwrap().unwrap();
    let expiry_val: serde_json::Value = serde_json::from_str(&expiry_line).unwrap();
    assert_eq!(expiry_val["id"], 3);
    assert!(expiry_val["result"]["isError"].is_null() || expiry_val["result"]["isError"] == false);
    let expiry_text = expiry_val["result"]["content"][0]["text"].as_str().unwrap();
    let _: serde_json::Value = serde_json::from_str(expiry_text).unwrap();

    // 5. tools/call: ssl_list_certs
    let certs_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "ssl_list_certs",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{certs_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let certs_line = stdout_reader.next_line().await.unwrap().unwrap();
    let certs_val: serde_json::Value = serde_json::from_str(&certs_line).unwrap();
    assert_eq!(certs_val["id"], 4);
    assert!(certs_val["result"]["isError"].is_null() || certs_val["result"]["isError"] == false);

    // 6. tools/call: ssl_certbot_renew (dry_run: true)
    let renew_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "ssl_certbot_renew",
            "arguments": {
                "dry_run": true
            }
        }
    });
    stdin
        .write_all(format!("{renew_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let renew_line = stdout_reader.next_line().await.unwrap().unwrap();
    let renew_val: serde_json::Value = serde_json::from_str(&renew_line).unwrap();
    assert_eq!(renew_val["id"], 5);
    let renew_text = renew_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!renew_text.is_empty());

    // 7. tools/call: ssl_check_expiry with private key blocked by Guard
    let priv_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "ssl_check_expiry",
            "arguments": {
                "path": "/etc/ssl/private/server.key"
            }
        }
    });
    stdin
        .write_all(format!("{priv_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let priv_line = stdout_reader.next_line().await.unwrap().unwrap();
    let priv_val: serde_json::Value = serde_json::from_str(&priv_line).unwrap();
    assert_eq!(priv_val["id"], 6);
    assert_eq!(priv_val["result"]["isError"], true);
    let priv_err = priv_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(priv_err.contains("Security Violation"));

    // 8. tools/call: ssl_check_expiry with domain injection blocked by Guard
    let inj_req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "ssl_check_expiry",
            "arguments": {
                "domain": "site.com; shutdown -h now"
            }
        }
    });
    stdin
        .write_all(format!("{inj_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let inj_line = stdout_reader.next_line().await.unwrap().unwrap();
    let inj_val: serde_json::Value = serde_json::from_str(&inj_line).unwrap();
    assert_eq!(inj_val["id"], 7);
    assert_eq!(inj_val["result"]["isError"], true);
    let inj_err = inj_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(inj_err.contains("Invalid characters") || inj_err.contains("shell metacharacters"));

    drop(stdin);
    let status = child.wait().await.unwrap();
    assert!(status.success());

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

// -----------------------------------------------------------------------------
// HTTP & SSE Remote Transport Integration Tests
// -----------------------------------------------------------------------------

fn get_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

async fn wait_for_http_ready(addr: &str) {
    for _ in 0..50 {
        if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
            let req = format!("GET /health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(req.as_bytes()).await;
            return;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }
    panic!("Server at {addr} did not become ready in time");
}

async fn http_request(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    auth_header: Option<&str>,
) -> (u16, String, serde_json::Value) {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("Failed to connect to server");

    let body_str = body.unwrap_or("");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body_str.len()
    );

    if let Some(auth) = auth_header {
        req.push_str(&format!("Authorization: {auth}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body_str);

    stream.write_all(req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).await.unwrap();
    let response_str = String::from_utf8_lossy(&response_bytes);

    let first_line = response_str.lines().next().unwrap_or("");
    let status_code: u16 = first_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    let body_part = response_str.split("\r\n\r\n").nth(1).unwrap_or("");
    let json_val: serde_json::Value =
        serde_json::from_str(body_part).unwrap_or(serde_json::Value::Null);

    (status_code, body_part.to_string(), json_val)
}

#[tokio::test]
async fn test_cli_http_transport_e2e() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");
    let port = get_free_port();
    let addr = format!("127.0.0.1:{port}");

    let mut child = Command::new(bin_path)
        .arg("--transport")
        .arg("http")
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--log-level")
        .arg("debug")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon HTTP server");

    wait_for_http_ready(&addr).await;

    // 1. Check /health
    let (status, _body_raw, health_json) = http_request(&addr, "GET", "/health", None, None).await;
    assert_eq!(status, 200);
    assert_eq!(health_json["status"], "ok");
    assert_eq!(health_json["service"], "vibe-daemon");

    // 2. Send initialize via POST /
    let init_payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "http-test-client", "version": "1.0.0" }
        }
    });
    let (status, _, init_resp) =
        http_request(&addr, "POST", "/", Some(&init_payload.to_string()), None).await;
    assert_eq!(status, 200);
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "vibe-daemon");

    // 3. Send tools/list via POST /message
    let tools_payload = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    let (status, _, tools_resp) = http_request(
        &addr,
        "POST",
        "/message",
        Some(&tools_payload.to_string()),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(tools_resp["id"], 2);
    let tools = tools_resp["result"]["tools"]
        .as_array()
        .expect("Tools array");
    assert_eq!(tools.len(), 33);

    // 4. Send tools/call via POST /message
    let call_payload = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get_system_status",
            "arguments": {}
        }
    });
    let (status, _, call_resp) = http_request(
        &addr,
        "POST",
        "/message",
        Some(&call_payload.to_string()),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(call_resp["id"], 3);
    assert!(call_resp["result"]["content"][0]["text"].as_str().is_some());

    let _ = child.kill().await;
}

#[tokio::test]
async fn test_cli_http_bearer_token_authorization() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");
    let port = get_free_port();
    let addr = format!("127.0.0.1:{port}");

    let temp_dir = std::env::temp_dir().join(format!("vibe_auth_test_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let conf_path = temp_dir.join("config.toml");
    let conf_content = r#"
[daemon]
log_level = "debug"

[security]
auth_token = "secure-secret-token-42"
"#;
    tokio::fs::write(&conf_path, conf_content).await.unwrap();

    let mut child = Command::new(bin_path)
        .arg("-c")
        .arg(conf_path.to_str().unwrap())
        .arg("--transport")
        .arg("http")
        .arg("--port")
        .arg(port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon HTTP server with auth");

    wait_for_http_ready(&addr).await;

    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    });

    // 1. Without auth header -> 401 Unauthorized
    let (status, _, resp) =
        http_request(&addr, "POST", "/", Some(&payload.to_string()), None).await;
    assert_eq!(status, 401);
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Unauthorized")
    );

    // 2. With wrong auth header -> 401 Unauthorized
    let (status, _, resp) = http_request(
        &addr,
        "POST",
        "/",
        Some(&payload.to_string()),
        Some("Bearer wrong-token"),
    )
    .await;
    assert_eq!(status, 401);
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Unauthorized")
    );

    // 3. With correct auth header -> 200 OK
    let (status, _, resp) = http_request(
        &addr,
        "POST",
        "/",
        Some(&payload.to_string()),
        Some("Bearer secure-secret-token-42"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(resp["id"], 1);

    let _ = child.kill().await;
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_cli_sse_transport_e2e() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");
    let port = get_free_port();
    let addr = format!("127.0.0.1:{port}");

    let mut child = Command::new(bin_path)
        .arg("--transport")
        .arg("sse")
        .arg("--port")
        .arg(port.to_string())
        .arg("--log-level")
        .arg("debug")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon SSE server");

    wait_for_http_ready(&addr).await;

    // Connect to /sse
    let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let sse_req = format!("GET /sse HTTP/1.1\r\nHost: {addr}\r\nAccept: text/event-stream\r\n\r\n");
    stream.write_all(sse_req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let response_str = String::from_utf8_lossy(&buf[..n]);

    assert!(response_str.contains("HTTP/1.1 200 OK"));
    assert!(response_str.contains("text/event-stream"));
    assert!(response_str.contains("event: endpoint"));
    assert!(response_str.contains("/message?sessionId=sess_"));

    let _ = child.kill().await;
}

#[tokio::test]
async fn test_cli_fail_closed_missing_config() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");
    let missing_path = "non_existent_config_file_should_fail_123.toml";

    let output = Command::new(bin_path)
        .arg("--config")
        .arg(missing_path)
        .output()
        .await
        .expect("Failed to execute vibe-daemon with missing config");

    assert!(
        !output.status.success(),
        "Daemon must exit with non-zero exit code when --config points to non-existent file"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Configuration Error") || stderr.contains("not found"),
        "Expected error message about missing configuration file, got: {stderr}"
    );
}

#[tokio::test]
async fn test_cli_fail_closed_corrupt_config() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");
    let temp_file =
        std::env::temp_dir().join(format!("corrupt_config_{}.toml", std::process::id()));
    tokio::fs::write(&temp_file, "[[invalid toml structure without closing")
        .await
        .expect("Failed to write corrupt config");

    let output = Command::new(bin_path)
        .arg("--config")
        .arg(&temp_file)
        .output()
        .await
        .expect("Failed to execute vibe-daemon with corrupt config");

    let _ = tokio::fs::remove_file(&temp_file).await;

    assert!(
        !output.status.success(),
        "Daemon must exit with non-zero exit code when --config points to corrupt file"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Configuration Error") || stderr.contains("TOML"),
        "Expected error message about invalid TOML, got: {stderr}"
    );
}

#[tokio::test]
async fn test_cli_fail_closed_validation_error() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");
    let temp_file = std::env::temp_dir().join(format!("invalid_val_{}.toml", std::process::id()));
    tokio::fs::write(&temp_file, "[security]\nprotected_ports = [0]\n")
        .await
        .expect("Failed to write invalid config");

    let output = Command::new(bin_path)
        .arg("--config")
        .arg(&temp_file)
        .output()
        .await
        .expect("Failed to execute vibe-daemon with invalid config");

    let _ = tokio::fs::remove_file(&temp_file).await;

    assert!(
        !output.status.success(),
        "Daemon must exit with non-zero exit code when --config contains invalid security settings"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Configuration Error") || stderr.contains("invalid port 0"),
        "Expected error message about port 0, got: {stderr}"
    );
}

#[tokio::test]
async fn test_cli_file_ops_bounded_tail_and_pagination() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");
    let temp_dir = std::env::temp_dir().join(format!("vibe_integ_fops_p_{}", std::process::id()));
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .expect("Failed to create temp dir");

    let mut child = Command::new(bin_path)
        .arg("--log-level")
        .arg("error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon");

    let mut stdin = child.stdin.take().expect("Failed to get stdin");
    let stdout = child.stdout.take().expect("Failed to get stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Handshake
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "1.0.0" }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _init_resp = stdout_reader.next_line().await.unwrap().unwrap();

    let init_notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(format!("{init_notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 2. Create 15 files for pagination test
    for i in 0..15 {
        let f = temp_dir.join(format!("file_{:02}.log", i));
        tokio::fs::write(&f, format!("log line {i}")).await.unwrap();
    }

    let dir_str = temp_dir.to_string_lossy().replace('\\', "/");

    // 3. Test list_directory page 1
    let list_req1 = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "list_directory",
            "arguments": {
                "path": dir_str,
                "limit": 10
            }
        }
    });
    stdin
        .write_all(format!("{list_req1}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let resp_line1 = stdout_reader.next_line().await.unwrap().unwrap();
    let val1: serde_json::Value = serde_json::from_str(&resp_line1).unwrap();
    let content1 = val1["result"]["content"][0]["text"].as_str().unwrap();
    let res1: serde_json::Value = serde_json::from_str(content1).unwrap();

    assert_eq!(res1["entries"].as_array().unwrap().len(), 10);
    assert_eq!(res1["truncated"], true);
    let next_cursor = res1["next_cursor"].as_str().expect("Must have next_cursor");

    // 4. Test list_directory page 2 with cursor
    let list_req2 = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "list_directory",
            "arguments": {
                "path": dir_str,
                "limit": 10,
                "cursor": next_cursor
            }
        }
    });
    stdin
        .write_all(format!("{list_req2}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let resp_line2 = stdout_reader.next_line().await.unwrap().unwrap();
    let val2: serde_json::Value = serde_json::from_str(&resp_line2).unwrap();
    let content2 = val2["result"]["content"][0]["text"].as_str().unwrap();
    let res2: serde_json::Value = serde_json::from_str(content2).unwrap();

    assert_eq!(res2["entries"].as_array().unwrap().len(), 5);
    assert_eq!(res2["truncated"], false);
    assert!(res2["next_cursor"].is_null());

    // 5. Test tail_logs bounded seek
    let target_log = temp_dir.join("file_00.log");
    let mut big_lines = Vec::new();
    for i in 1..=100 {
        big_lines.push(format!("entry {i:03} - log line details"));
    }
    tokio::fs::write(&target_log, big_lines.join("\n"))
        .await
        .unwrap();

    let tail_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "tail_logs",
            "arguments": {
                "path": target_log.to_string_lossy().replace('\\', "/"),
                "lines": 3,
                "max_bytes": 1024
            }
        }
    });
    stdin
        .write_all(format!("{tail_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let resp_line3 = stdout_reader.next_line().await.unwrap().unwrap();
    let val3: serde_json::Value = serde_json::from_str(&resp_line3).unwrap();
    let tail_text = val3["result"]["content"][0]["text"].as_str().unwrap();
    assert!(tail_text.contains("entry 100"));
    assert!(tail_text.contains("entry 099"));
    assert!(tail_text.contains("entry 098"));

    // 6. Test write_file atomic backup
    let test_file = temp_dir.join("version.txt");
    let test_file_str = test_file.to_string_lossy().replace('\\', "/");
    tokio::fs::write(&test_file, "original content")
        .await
        .unwrap();

    let write_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": test_file_str,
                "content": "new updated content"
            }
        }
    });
    stdin
        .write_all(format!("{write_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let resp_line4 = stdout_reader.next_line().await.unwrap().unwrap();
    let val4: serde_json::Value = serde_json::from_str(&resp_line4).unwrap();
    let write_text = val4["result"]["content"][0]["text"].as_str().unwrap();
    assert!(write_text.contains("Successfully wrote"));
    assert!(write_text.contains("backup created"));

    let _ = child.kill().await;
    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_background_tasks_mcp_lifecycle_and_cancellation() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let mut child = Command::new(bin_path)
        .arg("--log-level")
        .arg("debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon binary");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "integration-test-client",
                "version": "1.0.0"
            }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let _ = stdout_reader.next_line().await.unwrap().unwrap();

    // 2. Initialized notification
    let initialized_notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    stdin
        .write_all(format!("{initialized_notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 3. Start background task
    let sleep_cmd = if cfg!(windows) {
        "powershell -Command \"Start-Sleep -Seconds 10\""
    } else {
        "sleep 10"
    };

    let start_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "start_background_task",
            "arguments": {
                "command": sleep_cmd
            }
        }
    });
    stdin
        .write_all(format!("{start_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let start_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let start_val: serde_json::Value = serde_json::from_str(&start_resp_line).unwrap();
    let start_text = start_val["result"]["content"][0]["text"].as_str().unwrap();
    let start_data: serde_json::Value = serde_json::from_str(start_text).unwrap();
    let task_id = start_data["task_id"].as_str().unwrap().to_string();
    assert_eq!(start_data["status"], "Running");

    // 4. Check status
    let check_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "check_task_status",
            "arguments": {
                "task_id": &task_id
            }
        }
    });
    stdin
        .write_all(format!("{check_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let check_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let check_val: serde_json::Value = serde_json::from_str(&check_resp_line).unwrap();
    let check_text = check_val["result"]["content"][0]["text"].as_str().unwrap();
    let check_data: serde_json::Value = serde_json::from_str(check_text).unwrap();
    assert_eq!(check_data["status"], "Running");

    // 5. Get output while running
    let output_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "get_task_output",
            "arguments": {
                "task_id": &task_id
            }
        }
    });
    stdin
        .write_all(format!("{output_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let output_val = read_next_response_matching_id(&mut stdout_reader, 4).await;
    let output_text = output_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(output_text.contains(&task_id));

    // 6. Cancel task
    let cancel_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "cancel_task",
            "arguments": {
                "task_id": &task_id
            }
        }
    });
    stdin
        .write_all(format!("{cancel_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let cancel_val = read_next_response_matching_id(&mut stdout_reader, 5).await;
    let cancel_text = cancel_val["result"]["content"][0]["text"].as_str().unwrap();
    assert!(cancel_text.contains("successfully cancelled"));

    // 7. Verify task status is Cancelled
    let check_req2 = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "check_task_status",
            "arguments": {
                "task_id": &task_id
            }
        }
    });
    stdin
        .write_all(format!("{check_req2}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let check_val2 = read_next_response_matching_id(&mut stdout_reader, 6).await;
    let check_text2 = check_val2["result"]["content"][0]["text"].as_str().unwrap();
    let check_data2: serde_json::Value = serde_json::from_str(check_text2).unwrap();
    assert_eq!(check_data2["status"], "Cancelled");

    let _ = child.kill().await;
}

#[tokio::test]
async fn test_cli_resources_subsystem_stdio() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let mut child = Command::new(bin_path)
        .arg("--log-level")
        .arg("error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon binary");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Send `initialize` request and verify resources capability
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "resources-test-client", "version": "1.0.0" }
        }
    });

    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let init_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let init_val: serde_json::Value = serde_json::from_str(&init_resp_line).unwrap();
    assert_eq!(init_val["id"], 1);

    let res_cap = &init_val["result"]["capabilities"]["resources"];
    assert_eq!(res_cap["subscribe"], true);
    assert_eq!(res_cap["listChanged"], false);

    // Initialized notification
    let init_notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(format!("{init_notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 2. Request `resources/list`
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/list"
    });
    stdin
        .write_all(format!("{list_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let list_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let list_val: serde_json::Value = serde_json::from_str(&list_resp_line).unwrap();
    assert_eq!(list_val["id"], 2);
    let resources = list_val["result"]["resources"]
        .as_array()
        .expect("resources array");
    assert!(resources.iter().any(|r| r["uri"] == "system://status"));
    assert!(
        resources
            .iter()
            .any(|r| r["uri"] == "config://nginx/nginx.conf")
    );
    assert!(resources.iter().any(|r| r["uri"] == "log://service/nginx"));

    // 3. Request `resources/read` for `system://status`
    let read_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "resources/read",
        "params": {
            "uri": "system://status"
        }
    });
    stdin
        .write_all(format!("{read_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let read_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let read_val: serde_json::Value = serde_json::from_str(&read_resp_line).unwrap();
    assert_eq!(read_val["id"], 3);
    let contents = read_val["result"]["contents"]
        .as_array()
        .expect("contents array");
    assert_eq!(contents.len(), 1);
    assert_eq!(contents[0]["uri"], "system://status");
    assert_eq!(contents[0]["mimeType"], "application/json");
    let status_json: serde_json::Value =
        serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
    assert!(status_json.get("hostname").is_some());

    // 4. Request `resources/read` with path traversal (must be rejected)
    let trav_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "resources/read",
        "params": {
            "uri": "config://nginx/../../etc/shadow"
        }
    });
    stdin
        .write_all(format!("{trav_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let trav_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let trav_val: serde_json::Value = serde_json::from_str(&trav_resp_line).unwrap();
    assert_eq!(trav_val["id"], 4);
    assert!(trav_val["error"].is_object());

    // 5. Subscribe to `system://status`
    let sub_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "resources/subscribe",
        "params": {
            "uri": "system://status"
        }
    });
    stdin
        .write_all(format!("{sub_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let sub_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let sub_val: serde_json::Value = serde_json::from_str(&sub_resp_line).unwrap();
    assert_eq!(sub_val["id"], 5);
    assert!(sub_val["result"].is_object());

    // 6. Unsubscribe from `system://status`
    let unsub_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "resources/unsubscribe",
        "params": {
            "uri": "system://status"
        }
    });
    stdin
        .write_all(format!("{unsub_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let unsub_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let unsub_val: serde_json::Value = serde_json::from_str(&unsub_resp_line).unwrap();
    assert_eq!(unsub_val["id"], 6);
    assert!(unsub_val["result"].is_object());

    let _ = child.kill().await;
}

#[tokio::test]
async fn test_cli_server_initiated_notifications_stdio() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let mut child = Command::new(bin_path)
        .arg("--log-level")
        .arg("error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon binary");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Handshake
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "notif-test-client", "version": "1.0.0" }
        }
    });

    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let init_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let init_val: serde_json::Value = serde_json::from_str(&init_resp_line).unwrap();
    assert_eq!(init_val["id"], 1);

    let init_notify = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(format!("{init_notify}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 2. Start a fast background task
    let cmd_str = if cfg!(windows) {
        "cmd.exe /c echo task_notif_done"
    } else {
        "sh -c \"echo task_notif_done\""
    };

    let start_task_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "start_background_task",
            "arguments": {
                "command": cmd_str
            }
        }
    });

    stdin
        .write_all(format!("{start_task_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let task_resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let task_resp_val: serde_json::Value = serde_json::from_str(&task_resp_line).unwrap();
    assert_eq!(task_resp_val["id"], 2);
    let content_text = task_resp_val["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    let task_info: serde_json::Value = serde_json::from_str(content_text).unwrap();
    let task_id = task_info["task_id"].as_str().unwrap().to_string();

    // 3. Await asynchronous server-initiated notification on stdout
    let notif_line =
        tokio::time::timeout(std::time::Duration::from_secs(5), stdout_reader.next_line())
            .await
            .expect("Timed out waiting for task completion notification")
            .unwrap()
            .expect("Received notification line");

    let notif_val: serde_json::Value = serde_json::from_str(&notif_line).unwrap();

    // Verification of requirement: server-initiated notification has NO id field
    assert!(
        notif_val.get("id").is_none(),
        "Server-initiated notification must not have an 'id' field"
    );
    assert_eq!(notif_val["jsonrpc"], "2.0");
    assert_eq!(notif_val["method"], "notifications/tasks/completed");
    assert_eq!(notif_val["params"]["taskId"], task_id);
    assert_eq!(notif_val["params"]["status"], "Success");

    let _ = child.kill().await;
}

#[tokio::test]
async fn test_cli_fail_closed_corrupt_audit_log() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");
    let temp_dir =
        std::env::temp_dir().join(format!("vibe_audit_fail_closed_{}", std::process::id()));
    let _ = tokio::fs::create_dir_all(&temp_dir).await;
    let corrupt_log = temp_dir.join("corrupted_audit.jsonl");

    // Write a corrupted record whose record_hash does not match its contents
    let corrupt_json = r#"{"seq":1,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","record_hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","timestamp":"2026-10-14T12:00:00Z","operation":"test_op","tool_name":"execute_safe_command","command":null,"user":"system","status":"success","details":{}}"#;
    tokio::fs::write(&corrupt_log, format!("{corrupt_json}\n"))
        .await
        .unwrap();

    let output = Command::new(bin_path)
        .arg("--audit-log")
        .arg(&corrupt_log)
        .output()
        .await
        .expect("Failed to execute vibe-daemon");

    assert!(
        !output.status.success(),
        "Daemon must fail startup when audit log is corrupt (fail-closed)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Audit log integrity failure")
            || stderr.contains("Integrity error")
            || stderr.contains("corrupt"),
        "Expected integrity error message in stderr, got: {stderr}"
    );

    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
}

#[tokio::test]
async fn test_cli_system_ports_and_services_resources() {
    let bin_path = env!("CARGO_BIN_EXE_vibe-daemon");

    let mut child = Command::new(bin_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn vibe-daemon binary");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout).lines();

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "1.0.0" }
        }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _ = stdout_reader.next_line().await.unwrap().unwrap();

    // 2. Read system://ports
    let read_ports_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/read",
        "params": { "uri": "system://ports" }
    });
    stdin
        .write_all(format!("{read_ports_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let resp_line = stdout_reader.next_line().await.unwrap().unwrap();
    let resp_val: serde_json::Value = serde_json::from_str(&resp_line).unwrap();
    assert_eq!(resp_val["id"], 2);
    let ports_text = resp_val["result"]["contents"][0]["text"].as_str().unwrap();
    assert!(ports_text.contains("listening_ports"));
    assert!(ports_text.contains("established_connections"));

    // 3. Read system://services
    let read_services_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "resources/read",
        "params": { "uri": "system://services" }
    });
    stdin
        .write_all(format!("{read_services_req}\n").as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let resp_services_line = stdout_reader.next_line().await.unwrap().unwrap();
    let resp_services_val: serde_json::Value = serde_json::from_str(&resp_services_line).unwrap();
    assert_eq!(resp_services_val["id"], 3);
    let services_text = resp_services_val["result"]["contents"][0]["text"]
        .as_str()
        .unwrap();
    assert!(services_text.contains("key_services"));
    assert!(services_text.contains("services"));

    let _ = child.kill().await;
}
