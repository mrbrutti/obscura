use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// A port nothing listens on, for `serve --port`.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn serve_with_ca_cert(ca_cert: &str) -> (std::process::Output, u16) {
    let port = free_port();
    let output = Command::new(env!("CARGO_BIN_EXE_obscura"))
        .args(["--ca-cert", ca_cert, "serve", "--port"])
        .arg(port.to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (output, port)
}

fn assert_nothing_listens(port: u16) {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err(),
        "serve must not have bound port {port}"
    );
}

// --ca-cert (M2-AC3): a bad certificate path ends the process, with the path
// in the message, before serve binds its port.
#[test]
fn bad_ca_cert_exits_before_serving() {
    let (output, port) = serve_with_ca_cert("/nonexistent/x.pem");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--ca-cert"), "{stderr}");
    assert!(stderr.contains("/nonexistent/x.pem"), "{stderr}");
    assert_nothing_listens(port);
}

// --ca-cert (M2-AC3): a file holding a key and no certificate is refused too.
#[test]
fn private_key_ca_cert_exits_before_serving() {
    let dir = std::env::temp_dir().join(format!("obscura-ca-cert-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("key.pem");
    std::fs::write(
        &key_path,
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();

    let (output, port) = serve_with_ca_cert(key_path.to_str().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains(key_path.to_str().unwrap()), "{stderr}");
    assert_nothing_listens(port);
}

// The probe aitmproxy runs to tell a patched binary from an upstream one.
#[test]
fn help_lists_ca_cert() {
    let output = Command::new(env!("CARGO_BIN_EXE_obscura"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--ca-cert"), "{stdout}");
}
