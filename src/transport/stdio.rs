//! Local Standard I/O (stdio) transport implementation.
//! Communicates with the MCP host using newline-delimited JSON-RPC over stdin/stdout.

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use crate::mcp::McpDispatcher;

/// Runs the MCP server over standard input and output streams.
pub async fn run_stdio(dispatcher: McpDispatcher) -> anyhow::Result<()> {
    info!("Starting vibe-daemon stdio transport loop");
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    run_stream(dispatcher, stdin, stdout).await
}

/// Runs the MCP server over any async reader and writer.
pub async fn run_stream<R, W>(dispatcher: McpDispatcher, reader: R, writer: W) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let res = dispatcher.run(reader, writer).await;
    dispatcher.audit_logger.flush().await;
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn test_stdio_stream_transport_lifecycle() {
        let dispatcher = McpDispatcher::new();

        let (client_read, server_write) = tokio::io::duplex(4096);
        let (server_read, mut client_write) = tokio::io::duplex(4096);

        let server_handle =
            tokio::spawn(async move { run_stream(dispatcher, server_read, server_write).await });

        // Send initialize
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "stdio-client", "version": "1.0" }
            }
        });
        client_write
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();

        let mut lines = BufReader::new(client_read).lines();
        let resp_line = lines.next_line().await.unwrap().expect("Response line");
        let resp: serde_json::Value = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["serverInfo"]["name"], "vibe-daemon");

        // Close stream
        drop(client_write);
        let res = server_handle.await.unwrap();
        assert!(res.is_ok());
    }
}
