use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use qrcode::QrCode;
use qrcode::render::unicode;
use ring::digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};

const MAX_UPLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_ACTIVE_CONNECTIONS: usize = 32;
static LIVE_CLIENTS: AtomicUsize = AtomicUsize::new(0);
static LIVE_SYSTEM: Mutex<(u64, Vec<u8>)> = Mutex::new((0, Vec::new()));

struct LiveClient;

impl Drop for LiveClient {
    fn drop(&mut self) {
        LIVE_CLIENTS.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone)]
struct Config {
    root: PathBuf,
    token: String,
}

struct Request {
    method: String,
    path: String,
    content_length: u64,
    token: String,
    range_start: Option<u64>,
    upload_offset: Option<u64>,
    destination: Option<String>,
    delay_seconds: Option<u64>,
    websocket_key: Option<String>,
    websocket_upgrade: bool,
    connection_upgrade: bool,
    websocket_version: Option<String>,
    origin: Option<String>,
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("--config") {
        let path = args
            .get(2)
            .ok_or_else(|| io::Error::other("--config dosya yolu gerekli"))?;
        for line in fs::read_to_string(path)?
            .trim_start_matches('\u{feff}')
            .lines()
        {
            if let Some((key, value)) = line.split_once('=')
                && key.starts_with("MRP_")
            {
                // Startup is single-threaded; no other thread reads the environment yet.
                unsafe {
                    env::set_var(key, value);
                }
            }
        }
    }
    let root = env::var_os("MRP_FILES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_files_dir);
    fs::create_dir_all(&root)?;

    let token = env::var("MRP_TOKEN").map_err(|_| io::Error::other("MRP_TOKEN ayarlanmalı"))?;
    if token.len() < 16 || token == "mrp-local" {
        return Err(io::Error::other(
            "MRP_TOKEN en az 16 karakterlik rastgele bir anahtar olmalı",
        ));
    }
    let bind = env::var("MRP_BIND").unwrap_or_else(|_| "0.0.0.0:8765".to_string());
    let listener = TcpListener::bind(&bind)?;
    let (tls, fingerprint) = tls_config(&root)?;
    let config = Arc::new(Config { root, token });
    let sampler_config = Arc::clone(&config);
    thread::spawn(move || {
        loop {
            if LIVE_CLIENTS.load(Ordering::Acquire) > 0 {
                let mut response = Vec::new();
                if system_info(&mut response, &sampler_config).is_ok()
                    && response.starts_with(b"HTTP/1.1 200")
                    && let Some(offset) =
                        response.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let mut sample = LIVE_SYSTEM
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    sample.0 = sample.0.wrapping_add(1);
                    sample.1 = response[offset + 4..].to_vec();
                }
            }
            thread::sleep(std::time::Duration::from_secs(2));
        }
    });
    let active_connections = Arc::new(AtomicUsize::new(0));

    println!("Hypr Connect Agent listening on https://{bind}");
    println!("Shared folder: {}", config.root.display());
    print_pairing_qr(&listener, &config.token, &fingerprint);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if active_connections.fetch_add(1, Ordering::AcqRel) >= MAX_ACTIVE_CONNECTIONS {
                    active_connections.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }
                let config = Arc::clone(&config);
                let tls = Arc::clone(&tls);
                let active = Arc::clone(&active_connections);
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &config, tls) {
                        eprintln!("request error: {error}");
                    }
                    active.fetch_sub(1, Ordering::AcqRel);
                });
            }
            Err(error) => eprintln!("connection error: {error}"),
        }
    }
    Ok(())
}

fn print_pairing_qr(listener: &TcpListener, token: &str, fingerprint: &str) {
    let port = listener
        .local_addr()
        .map(|address| address.port())
        .unwrap_or(8765);
    let host = env::var("MRP_ADVERTISE_ADDRESS")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(local_ip);
    let address = format!("https://{host}:{port}");
    let mac = local_mac().unwrap_or_default();
    let payload = format!(
        "{{\"type\":\"mrp-pair\",\"address\":\"{}\",\"token\":\"{}\",\"mac\":\"{}\",\"fingerprint\":\"{}\"}}",
        json_escape(&address),
        json_escape(token),
        json_escape(&mac),
        fingerprint
    );
    println!("\nHypr Connect uygulamasında 'QR İLE BAĞLAN' seçeneğini açın:");
    match QrCode::new(payload.as_bytes()) {
        Ok(code) => println!(
            "{}",
            code.render::<unicode::Dense1x2>().quiet_zone(true).build()
        ),
        Err(error) => eprintln!("QR oluşturulamadı: {error}"),
    }
    println!("Pairing address: {address}");
    if !mac.is_empty() {
        println!("Wake-on-LAN MAC: {mac}");
    }
    println!();
}

fn tls_config(root: &Path) -> io::Result<(Arc<ServerConfig>, String)> {
    let private = root.join(".hypr-connect-private");
    fs::create_dir_all(&private)?;
    let cert_path = private.join("certificate.der");
    let key_path = private.join("private-key.der");
    if !cert_path.exists() || !key_path.exists() {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|error| io::Error::other(format!("TLS kimliği oluşturulamadı: {error}")))?;
        fs::write(&key_path, identity.signing_key.serialize_der())?;
        fs::write(&cert_path, identity.cert.der())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        }
    }
    let cert_bytes = fs::read(cert_path)?;
    let key_bytes = fs::read(key_path)?;
    let fingerprint = Sha256::digest(&cert_bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let certs = vec![CertificateDer::from(cert_bytes)];
    let key = PrivateKeyDer::try_from(key_bytes)
        .map_err(|error| io::Error::other(format!("TLS özel anahtarı okunamadı: {error}")))?;
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| io::Error::other(format!("TLS yapılandırılamadı: {error}")))?;
    Ok((Arc::new(server), fingerprint))
}

fn local_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("8.8.8.8:80")?;
            socket.local_addr()
        })
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn local_mac() -> Option<String> {
    if let Ok(configured) = env::var("MRP_MAC")
        && !configured.trim().is_empty()
    {
        return Some(configured.trim().to_uppercase());
    }
    if cfg!(windows) {
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", "$ip = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex; (Get-NetAdapter -InterfaceIndex $ip).MacAddress"])
            .output().ok()?;
        let mac = String::from_utf8_lossy(&output.stdout)
            .trim()
            .replace('-', ":");
        return (output.status.success() && mac.len() == 17).then_some(mac);
    }
    if env::consts::OS != "linux" {
        return None;
    }
    let entries = fs::read_dir("/sys/class/net").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo"
            || name.starts_with("br-")
            || name.starts_with("docker")
            || name.starts_with("veth")
        {
            continue;
        }
        let root = entry.path();
        let state = fs::read_to_string(root.join("operstate")).unwrap_or_default();
        let mac = fs::read_to_string(root.join("address")).unwrap_or_default();
        if state.trim() == "up" && mac.trim().matches(':').count() == 5 {
            return Some(mac.trim().to_uppercase());
        }
    }
    None
}

fn default_files_dir() -> PathBuf {
    let home = env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join("Documents").join("Hypr Connect Files")
}

fn handle_connection(stream: TcpStream, config: &Config, tls: Arc<ServerConfig>) -> io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    let mut first = [0u8; 1];
    let count = stream.peek(&mut first)?;
    if count == 0 || first[0] != 0x16 {
        return Err(io::Error::other("Yalnızca TLS bağlantılarına izin verilir"));
    }
    let connection = ServerConnection::new(tls)
        .map_err(|error| io::Error::other(format!("TLS bağlantısı kurulamadı: {error}")))?;
    handle(StreamOwned::new(connection, stream), config)
}

fn handle(stream: StreamOwned<ServerConnection, TcpStream>, config: &Config) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let request = match read_request(&mut reader) {
        Ok(request) => request,
        Err(message) => return respond_text(reader.get_mut(), 400, "Bad Request", &message),
    };

    if !constant_time_token_eq(&request.token, &config.token) {
        return respond_text(
            reader.get_mut(),
            401,
            "Unauthorized",
            "Geçersiz erişim anahtarı",
        );
    }

    let clean_path = request.path.split('?').next().unwrap_or(&request.path);
    append_audit(config, &request.method, clean_path);
    if request.method == "GET" && clean_path == "/api/live" {
        return websocket_session(reader, &request);
    }
    match (request.method.as_str(), clean_path) {
        ("GET", "/api/status") => status(reader.get_mut(), config),
        ("GET", "/api/system") => system_info(reader.get_mut(), config),
        ("GET", "/api/processes") => processes(reader.get_mut()),
        ("GET", "/api/apps") => apps(reader.get_mut()),
        ("GET", "/api/audit") => audit_log(reader.get_mut(), config),
        ("GET", "/api/clipboard") => clipboard_get(reader.get_mut()),
        ("PUT", "/api/clipboard") => clipboard_set(&mut reader, request.content_length),
        ("POST", "/api/open-url") => open_url(&mut reader, request.content_length),
        ("GET", "/api/displays") => displays(reader.get_mut()),
        ("GET", "/api/screenshot") => screenshot(reader.get_mut(), &request.path),
        ("GET", "/api/files") => list_files(reader.get_mut(), config),
        ("HEAD", path) if path.starts_with("/api/files/") => {
            upload_status(reader.get_mut(), config, &path[11..])
        }
        ("POST", path) if path.starts_with("/api/folders/") => {
            create_folder(reader.get_mut(), config, &path[13..])
        }
        ("POST", path) if path.starts_with("/api/files/move/") => move_file(
            reader.get_mut(),
            config,
            &path[16..],
            request.destination.as_deref(),
        ),
        ("POST", path) if path.starts_with("/api/files/archive/") => archive_file(
            reader.get_mut(),
            config,
            &path[19..],
            request.destination.as_deref(),
        ),
        ("POST", path) if path.starts_with("/api/files/extract/") => {
            extract_file(reader.get_mut(), config, &path[19..])
        }
        ("GET", path) if path.starts_with("/api/files/") => {
            download(reader.get_mut(), config, &path[11..], request.range_start)
        }
        ("PUT", path) if path.starts_with("/api/files/") => upload(
            &mut reader,
            config,
            &path[11..],
            request.content_length,
            request.upload_offset,
        ),
        ("DELETE", path) if path.starts_with("/api/files/") => {
            delete_file(reader.get_mut(), config, &path[11..])
        }
        ("POST", path) if path.starts_with("/api/power/") => power(reader.get_mut(), &path[11..]),
        ("POST", path) if path.starts_with("/api/media/") => media(reader.get_mut(), &path[11..]),
        ("POST", path) if path.starts_with("/api/control/") => {
            control(reader.get_mut(), &path[13..])
        }
        ("POST", path) if path.starts_with("/api/apps/") => {
            launch_app(reader.get_mut(), &path[10..])
        }
        ("POST", path) if path.starts_with("/api/schedule/") => {
            schedule_power(reader.get_mut(), &path[14..], request.delay_seconds)
        }
        ("DELETE", "/api/schedule") => cancel_schedule(reader.get_mut()),
        ("OPTIONS", _) => respond_empty(reader.get_mut(), 204, "No Content"),
        _ => respond_text(reader.get_mut(), 404, "Not Found", "Bulunamadı"),
    }
}

fn constant_time_token_eq(candidate: &str, expected: &str) -> bool {
    let a = candidate.as_bytes();
    let b = expected.as_bytes();
    let mut diff = a.len() ^ b.len();
    for (index, byte) in b.iter().enumerate() {
        diff |= (*byte ^ a.get(index).copied().unwrap_or(0)) as usize;
    }
    diff == 0
}

fn websocket_session(
    mut reader: BufReader<StreamOwned<ServerConnection, TcpStream>>,
    request: &Request,
) -> io::Result<()> {
    if !request.websocket_upgrade
        || !request.connection_upgrade
        || request.websocket_version.as_deref() != Some("13")
        || request.origin.is_some()
    {
        return respond_text(
            reader.get_mut(),
            400,
            "Bad Request",
            "Geçersiz WebSocket isteği",
        );
    }
    let Some(key) = request.websocket_key.as_deref() else {
        return respond_text(
            reader.get_mut(),
            400,
            "Bad Request",
            "WebSocket anahtarı eksik",
        );
    };
    let Ok(key_bytes) = base64::engine::general_purpose::STANDARD.decode(key) else {
        return respond_text(
            reader.get_mut(),
            400,
            "Bad Request",
            "WebSocket anahtarı geçersiz",
        );
    };
    if key_bytes.len() != 16 {
        return respond_text(
            reader.get_mut(),
            400,
            "Bad Request",
            "WebSocket anahtarı geçersiz",
        );
    }
    let hash = digest::digest(
        &digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
    );
    let accept = base64::engine::general_purpose::STANDARD.encode(hash.as_ref());
    write!(
        reader.get_mut(),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    )?;
    reader.get_mut().flush()?;
    reader
        .get_mut()
        .sock
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))?;
    LIVE_CLIENTS.fetch_add(1, Ordering::AcqRel);
    let _live_client = LiveClient;
    let mut last_system_version = 0;
    loop {
        let sample = {
            let sample = LIVE_SYSTEM
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if sample.0 != last_system_version && !sample.1.is_empty() {
                Some((sample.0, sample.1.clone()))
            } else {
                None
            }
        };
        if let Some((version, body)) = sample {
            let mut event = b"system:".to_vec();
            event.extend_from_slice(&body);
            write_ws_frame(reader.get_mut(), 1, &event)?;
            last_system_version = version;
        }
        let frame = match read_ws_frame(&mut reader) {
            Ok(Some(frame)) => frame,
            Ok(None) => continue,
            Err(_) => break,
        };
        match frame.0 {
            1 => {
                let Ok(message) = std::str::from_utf8(&frame.1) else {
                    break;
                };
                if let Some(action) = message.strip_prefix("media:") {
                    let mut response = Vec::new();
                    let success = media(&mut response, action).is_ok()
                        && response.starts_with(b"HTTP/1.1 202");
                    write_ws_frame(
                        reader.get_mut(),
                        1,
                        if success { b"media:ok" } else { b"media:error" },
                    )?;
                } else if let Some(action) = message.strip_prefix("control:") {
                    let mut response = Vec::new();
                    let success = control(&mut response, action).is_ok()
                        && response.starts_with(b"HTTP/1.1 202");
                    write_ws_frame(
                        reader.get_mut(),
                        1,
                        if success {
                            b"control:ok"
                        } else {
                            b"control:error"
                        },
                    )?;
                } else {
                    write_ws_frame(reader.get_mut(), 1, b"error:unsupported")?;
                }
            }
            8 => {
                let _ = write_ws_frame(reader.get_mut(), 8, &[]);
                break;
            }
            9 => write_ws_frame(reader.get_mut(), 10, &frame.1)?,
            _ => break,
        }
    }
    Ok(())
}

fn read_ws_frame<R: Read>(reader: &mut R) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0u8; 2];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    }
    if header[0] & 0x80 == 0 || header[1] & 0x80 == 0 || header[1] & 0x7f > 125 {
        return Err(io::Error::other("Geçersiz WebSocket çerçevesi"));
    }
    let len = usize::from(header[1] & 0x7f);
    let mut mask = [0u8; 4];
    reader.read_exact(&mut mask)?;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    Ok(Some((header[0] & 0x0f, payload)))
}

fn write_ws_frame<W: Write>(writer: &mut W, opcode: u8, payload: &[u8]) -> io::Result<()> {
    writer.write_all(&[0x80 | opcode])?;
    if payload.len() < 126 {
        writer.write_all(&[payload.len() as u8])?;
    } else if payload.len() <= u16::MAX as usize {
        writer.write_all(&[126])?;
        writer.write_all(&(payload.len() as u16).to_be_bytes())?;
    } else {
        return Err(io::Error::other("WebSocket mesajı çok büyük"));
    }
    writer.write_all(payload)?;
    writer.flush()
}

fn read_request<R: Read>(reader: &mut BufReader<R>) -> Result<Request, String> {
    let mut first = String::new();
    read_http_line(reader, &mut first)?;
    let mut parts = first.split_whitespace();
    let method = parts.next().ok_or("Eksik HTTP metodu")?.to_string();
    let path = parts.next().ok_or("Eksik HTTP yolu")?.to_string();
    let mut content_length = 0;
    let mut token = String::new();
    let mut range_start = None;
    let mut upload_offset = None;
    let mut destination = None;
    let mut delay_seconds = None;
    let mut websocket_key = None;
    let mut websocket_upgrade = false;
    let mut connection_upgrade = false;
    let mut websocket_version = None;
    let mut origin = None;

    let mut headers_complete = false;
    for _ in 0..64 {
        let mut line = String::new();
        read_http_line(reader, &mut line)?;
        if line == "\r\n" || line.is_empty() {
            headers_complete = true;
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "content-length" => {
                    content_length = value
                        .trim()
                        .parse()
                        .map_err(|_| "Geçersiz Content-Length")?
                }
                "x-mrp-token" => token = value.trim().to_string(),
                "range" => {
                    range_start = value
                        .trim()
                        .strip_prefix("bytes=")
                        .and_then(|value| value.strip_suffix('-'))
                        .and_then(|value| value.parse().ok())
                }
                "x-mrp-offset" => upload_offset = value.trim().parse().ok(),
                "x-mrp-destination" => destination = Some(value.trim().to_string()),
                "x-hypr-delay" => delay_seconds = value.trim().parse().ok(),
                "sec-websocket-key" => websocket_key = Some(value.trim().to_string()),
                "sec-websocket-version" => websocket_version = Some(value.trim().to_string()),
                "upgrade" => websocket_upgrade = value.trim().eq_ignore_ascii_case("websocket"),
                "connection" => {
                    connection_upgrade = value
                        .split(',')
                        .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
                }
                "origin" => origin = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }
    if !headers_complete {
        return Err("Çok fazla HTTP başlığı".to_string());
    }
    Ok(Request {
        method,
        path,
        content_length,
        token,
        range_start,
        upload_offset,
        destination,
        delay_seconds,
        websocket_key,
        websocket_upgrade,
        connection_upgrade,
        websocket_version,
        origin,
    })
}

fn read_http_line<R: Read>(reader: &mut BufReader<R>, line: &mut String) -> Result<(), String> {
    let mut bytes = Vec::new();
    reader
        .take(8193)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 8192 || !bytes.ends_with(b"\n") {
        return Err("HTTP satırı çok uzun veya eksik".to_string());
    }
    *line = String::from_utf8(bytes).map_err(|_| "Geçersiz HTTP başlığı".to_string())?;
    Ok(())
}

fn status<W: Write>(stream: &mut W, config: &Config) -> io::Result<()> {
    let hostname = env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "Bilgisayar".to_string());
    let body = format!(
        "{{\"name\":\"{}\",\"os\":\"{}\",\"folder\":\"{}\"}}",
        json_escape(&hostname),
        env::consts::OS,
        json_escape(&config.root.to_string_lossy())
    );
    respond_json(stream, 200, "OK", &body)
}

fn list_files<W: Write>(stream: &mut W, config: &Config) -> io::Result<()> {
    let mut items = Vec::new();
    collect_files(&config.root, &config.root, &mut items)?;
    items.sort();
    let body = format!("[{}]", items.join(","));
    respond_json(stream, 200, "OK", &body)
}

fn collect_files(root: &Path, dir: &Path, items: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        } else if file_type.is_dir() && entry.file_name() != ".hypr-connect-private" {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            items.push(format!(
                "{{\"name\":\"{}\",\"size\":0,\"modified\":0,\"directory\":true}}",
                json_escape(&relative)
            ));
            collect_files(root, &path, items)?;
        } else if file_type.is_file() {
            let meta = entry.metadata()?;
            let modified = meta
                .modified()
                .unwrap_or(UNIX_EPOCH)
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            items.push(format!(
                "{{\"name\":\"{}\",\"size\":{},\"modified\":{},\"directory\":false}}",
                json_escape(&relative),
                meta.len(),
                modified
            ));
        }
    }
    Ok(())
}

fn safe_path(root: &Path, encoded: &str) -> Result<PathBuf, &'static str> {
    let decoded = percent_decode(encoded)?;
    if decoded.is_empty() {
        return Err("Dosya yolu boş olamaz");
    }
    let candidate = Path::new(&decoded);
    if candidate.is_absolute()
        || candidate.components().any(|c| match c {
            Component::Normal(name) => name
                .to_str()
                .is_some_and(|part| part.eq_ignore_ascii_case(".hypr-connect-private")),
            _ => true,
        })
    {
        return Err("Geçersiz dosya yolu");
    }
    let mut resolved = root.to_path_buf();
    let private_root = fs::canonicalize(root.join(".hypr-connect-private")).ok();
    for component in candidate.components() {
        if let Component::Normal(part) = component {
            resolved.push(part);
            if fs::symlink_metadata(&resolved)
                .map(|metadata| is_redirecting_entry(&metadata))
                .unwrap_or(false)
            {
                return Err("Sembolik bağlantılara erişilemez");
            }
            if let (Some(private), Ok(real)) = (&private_root, fs::canonicalize(&resolved)) {
                let private_text = private.to_string_lossy().to_lowercase();
                let real_text = real.to_string_lossy().to_lowercase();
                if real_text == private_text
                    || real_text.starts_with(&(private_text + std::path::MAIN_SEPARATOR_STR))
                {
                    return Err("Özel dosyalara erişilemez");
                }
            }
        }
    }
    Ok(resolved)
}

fn is_redirecting_entry(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    false
}

fn contains_symlink(path: &Path) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    if is_redirecting_entry(&metadata) {
        return Ok(true);
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            if contains_symlink(&entry?.path())? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn download<W: Write>(
    stream: &mut W,
    config: &Config,
    encoded: &str,
    range_start: Option<u64>,
) -> io::Result<()> {
    let path = match safe_path(&config.root, encoded) {
        Ok(path) => path,
        Err(message) => return respond_text(stream, 400, "Bad Request", message),
    };
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return respond_text(stream, 404, "Not Found", "Dosya bulunamadı");
        }
        Err(error) => return Err(error),
    };
    let total = file.metadata()?.len();
    let start = range_start.unwrap_or(0).min(total);
    file.seek(SeekFrom::Start(start))?;
    let length = total - start;
    if start > 0 {
        write!(
            stream,
            "HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\nContent-Length: {length}\r\nContent-Range: bytes {start}-{}/{total}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
            total.saturating_sub(1)
        )?;
    } else {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {length}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n"
        )?;
    }
    io::copy(&mut file, stream)?;
    Ok(())
}

fn upload_status<W: Write>(stream: &mut W, config: &Config, encoded: &str) -> io::Result<()> {
    let path = match safe_path(&config.root, encoded) {
        Ok(path) => path,
        Err(message) => return respond_text(stream, 400, "Bad Request", message),
    };
    let offset = path
        .with_extension("mrp-upload")
        .metadata()
        .map(|meta| meta.len())
        .unwrap_or(0);
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nX-MRP-Upload-Offset: {offset}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

fn upload<R: Read + Write>(
    reader: &mut BufReader<R>,
    config: &Config,
    encoded: &str,
    length: u64,
    offset: Option<u64>,
) -> io::Result<()> {
    if length > MAX_UPLOAD_BYTES {
        return respond_text(
            reader.get_mut(),
            413,
            "Payload Too Large",
            "Dosya 4 GB sınırını aşıyor",
        );
    }
    let path = match safe_path(&config.root, encoded) {
        Ok(path) => path,
        Err(message) => return respond_text(reader.get_mut(), 400, "Bad Request", message),
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("mrp-upload");
    let requested_offset = offset.unwrap_or(0);
    let mut file = if requested_offset > 0 && temp.exists() {
        let mut file = fs::OpenOptions::new().append(true).open(&temp)?;
        if file.metadata()?.len() != requested_offset {
            return respond_text(
                reader.get_mut(),
                409,
                "Conflict",
                "Yükleme konumu eşleşmiyor",
            );
        }
        file.seek(SeekFrom::End(0))?;
        file
    } else {
        File::create(&temp)?
    };
    let copied = io::copy(&mut reader.take(length), &mut file)?;
    if copied != length {
        return respond_text(
            reader.get_mut(),
            400,
            "Bad Request",
            "Aktarım tamamlanamadı; devam ettirilebilir",
        );
    }
    file.sync_all()?;
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(&path)?;
    }
    fs::rename(temp, path)?;
    respond_text(reader.get_mut(), 201, "Created", "Yüklendi")
}

fn delete_file<W: Write>(stream: &mut W, config: &Config, encoded: &str) -> io::Result<()> {
    let path = match safe_path(&config.root, encoded) {
        Ok(path) => path,
        Err(message) => return respond_text(stream, 400, "Bad Request", message),
    };
    let result = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match result {
        Ok(()) => respond_empty(stream, 204, "No Content"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            respond_text(stream, 404, "Not Found", "Dosya bulunamadı")
        }
        Err(error) => Err(error),
    }
}

fn create_folder<W: Write>(stream: &mut W, config: &Config, encoded: &str) -> io::Result<()> {
    let path = match safe_path(&config.root, encoded) {
        Ok(path) => path,
        Err(message) => return respond_text(stream, 400, "Bad Request", message),
    };
    fs::create_dir_all(path)?;
    respond_text(stream, 201, "Created", "Klasör oluşturuldu")
}

fn move_file<W: Write>(
    stream: &mut W,
    config: &Config,
    source: &str,
    destination: Option<&str>,
) -> io::Result<()> {
    let Some(destination) = destination else {
        return respond_text(stream, 400, "Bad Request", "Hedef dosya yolu eksik");
    };
    let from = match safe_path(&config.root, source) {
        Ok(path) => path,
        Err(message) => return respond_text(stream, 400, "Bad Request", message),
    };
    let to = match safe_path(&config.root, destination) {
        Ok(path) => path,
        Err(message) => return respond_text(stream, 400, "Bad Request", message),
    };
    if !from.exists() {
        return respond_text(stream, 404, "Not Found", "Dosya bulunamadı");
    }
    if to.exists() {
        return respond_text(stream, 409, "Conflict", "Hedef zaten var");
    }
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::rename(from, to)?;
    respond_text(stream, 200, "OK", "Taşındı")
}

fn archive_file<W: Write>(
    stream: &mut W,
    config: &Config,
    encoded: &str,
    destination: Option<&str>,
) -> io::Result<()> {
    let source = match safe_path(&config.root, encoded) {
        Ok(path) if path.exists() => path,
        Ok(_) => return respond_text(stream, 404, "Not Found", "Kaynak bulunamadı"),
        Err(message) => return respond_text(stream, 400, "Bad Request", message),
    };
    if contains_symlink(&source)? {
        return respond_text(
            stream,
            400,
            "Bad Request",
            "Sembolik bağlantılar arşivlenemez",
        );
    }
    let default_name = format!(
        "{}.zip",
        source
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("arsiv")
    );
    let target = match safe_path(&config.root, destination.unwrap_or(&default_name)) {
        Ok(path) => path,
        Err(message) => return respond_text(stream, 400, "Bad Request", message),
    };
    if target.exists() {
        return respond_text(stream, 409, "Conflict", "Arşiv zaten var");
    }
    let result = if cfg!(windows) {
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", "Compress-Archive -LiteralPath $env:HYPR_SOURCE -DestinationPath $env:HYPR_TARGET -ErrorAction Stop"])
            .env("HYPR_SOURCE", &source)
            .env("HYPR_TARGET", &target)
            .output()
    } else {
        let parent = source.parent().unwrap_or(&config.root);
        let name = source.file_name().unwrap_or_default();
        Command::new("zip")
            .current_dir(parent)
            .arg("-r")
            .arg(&target)
            .arg(name)
            .output()
    };
    match result {
        Ok(output) if output.status.success() => {
            respond_text(stream, 201, "Created", "ZIP arşivi oluşturuldu")
        }
        Ok(output) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &String::from_utf8_lossy(&output.stderr),
        ),
        Err(error) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &format!("ZIP oluşturulamadı: {error}"),
        ),
    }
}

fn extract_file<W: Write>(stream: &mut W, config: &Config, encoded: &str) -> io::Result<()> {
    let source = match safe_path(&config.root, encoded) {
        Ok(path) if path.is_file() => path,
        Ok(_) => return respond_text(stream, 404, "Not Found", "Arşiv bulunamadı"),
        Err(message) => return respond_text(stream, 400, "Bad Request", message),
    };
    if source
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| v.eq_ignore_ascii_case("zip"))
        != Some(true)
    {
        return respond_text(
            stream,
            400,
            "Bad Request",
            "Yalnızca ZIP arşivleri çıkarılabilir",
        );
    }
    let folder_name = source
        .file_stem()
        .and_then(|v| v.to_str())
        .unwrap_or("arsiv");
    let target = source.parent().unwrap_or(&config.root).join(folder_name);
    fs::create_dir_all(&target)?;
    let result = if cfg!(windows) {
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", "Expand-Archive -LiteralPath $env:HYPR_SOURCE -DestinationPath $env:HYPR_TARGET -ErrorAction Stop"])
            .env("HYPR_SOURCE", &source)
            .env("HYPR_TARGET", &target)
            .output()
    } else {
        Command::new("unzip")
            .arg("-n")
            .arg(&source)
            .arg("-d")
            .arg(&target)
            .output()
    };
    match result {
        Ok(output) if output.status.success() => respond_text(stream, 200, "OK", "Arşiv çıkarıldı"),
        Ok(output) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &String::from_utf8_lossy(&output.stderr),
        ),
        Err(error) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &format!("Arşiv çıkarılamadı: {error}"),
        ),
    }
}

fn append_audit(config: &Config, method: &str, path: &str) {
    let private = config.root.join(".hypr-connect-private");
    let _ = fs::create_dir_all(&private);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(private.join("audit.log"))
    {
        let _ = writeln!(file, "{timestamp}\t{method}\t{path}");
    }
}

fn audit_log<W: Write>(stream: &mut W, config: &Config) -> io::Result<()> {
    let contents =
        fs::read_to_string(config.root.join(".hypr-connect-private/audit.log")).unwrap_or_default();
    let lines: Vec<&str> = contents.lines().rev().take(100).collect();
    let body = format!(
        "[{}]",
        lines
            .iter()
            .map(|line| format!("\"{}\"", json_escape(line)))
            .collect::<Vec<_>>()
            .join(",")
    );
    respond_json(stream, 200, "OK", &body)
}

fn processes<W: Write>(stream: &mut W) -> io::Result<()> {
    if env::consts::OS == "windows" {
        let script = "$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;$total=[double]$o.TotalVisibleMemorySize*1024;$p=@(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process|Where-Object {$_.IDProcess -gt 0}|Sort-Object PercentProcessorTime -Descending|Select-Object -First 40|ForEach-Object {[pscustomobject]@{pid=[long]$_.IDProcess;name=$_.Name;cpu=[double]$_.PercentProcessorTime;memory=([double]$_.WorkingSetPrivate/$total*100)}});ConvertTo-Json -InputObject $p -Compress";
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()?;
        return if output.status.success() {
            respond_json(stream, 200, "OK", &String::from_utf8_lossy(&output.stdout))
        } else {
            respond_text(stream, 500, "Internal Server Error", "İşlemler okunamadı")
        };
    }
    let output = if env::consts::OS == "linux" {
        Command::new("ps")
            .args(["-eo", "pid=,comm=,%cpu=,%mem=", "--sort=-%cpu"])
            .output()
    } else {
        unreachable!()
    }?;
    if !output.status.success() {
        return respond_text(stream, 500, "Internal Server Error", "İşlemler okunamadı");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let items = text
        .lines()
        .take(40)
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let pid = parts.next()?.parse::<u64>().ok()?;
            let name = parts.next()?;
            let cpu = parts.next()?.replace(',', ".").parse::<f64>().ok()?;
            let memory = parts.next()?.replace(',', ".").parse::<f64>().ok()?;
            Some(format!(
                "{{\"pid\":{pid},\"name\":\"{}\",\"cpu\":{cpu:.1},\"memory\":{memory:.1}}}",
                json_escape(name)
            ))
        })
        .collect::<Vec<_>>();
    respond_json(stream, 200, "OK", &format!("[{}]", items.join(",")))
}

fn app_catalog() -> [(&'static str, &'static str, &'static [&'static str]); 5] {
    if cfg!(windows) {
        return [
            ("files", "Dosyalar", &["explorer.exe"]),
            ("terminal", "Terminal", &["powershell.exe"]),
            ("notepad", "Not Defteri", &["notepad.exe"]),
            ("calculator", "Hesap Makinesi", &["calc.exe"]),
            ("paint", "Paint", &["mspaint.exe"]),
        ];
    }
    [
        ("browser", "Tarayıcı", &["omarchy", "launch", "browser"]),
        ("files", "Dosyalar", &["xdg-open", "."]),
        ("terminal", "Terminal", &["xdg-terminal-exec"]),
        ("steam", "Steam", &["steam"]),
        ("code", "Kod Editörü", &["code"]),
    ]
}

fn apps<W: Write>(stream: &mut W) -> io::Result<()> {
    let items = app_catalog()
        .iter()
        .map(|(id, label, command)| {
            let available = command
                .first()
                .map(|name| executable_available(name))
                .unwrap_or(false);
            format!(
                "{{\"id\":\"{id}\",\"name\":\"{}\",\"available\":{available}}}",
                json_escape(label)
            )
        })
        .collect::<Vec<_>>();
    respond_json(stream, 200, "OK", &format!("[{}]", items.join(",")))
}

fn executable_available(name: &str) -> bool {
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).any(|path| path.join(name).is_file()))
        .unwrap_or(false)
}

fn launch_app<W: Write>(stream: &mut W, id: &str) -> io::Result<()> {
    let Some((_, _, command)) = app_catalog()
        .into_iter()
        .find(|(candidate, _, _)| *candidate == id)
    else {
        return respond_text(stream, 404, "Not Found", "Uygulama izin listesinde değil");
    };
    let Some((program, args)) = command.split_first() else {
        return respond_text(stream, 500, "Internal Server Error", "Uygulama komutu boş");
    };
    match Command::new(program).args(args).spawn() {
        Ok(_) => respond_text(stream, 202, "Accepted", "Uygulama başlatılıyor"),
        Err(error) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &format!("Uygulama başlatılamadı: {error}"),
        ),
    }
}

fn open_url<R: Read + Write>(reader: &mut BufReader<R>, length: u64) -> io::Result<()> {
    if length > 8192 {
        return respond_text(
            reader.get_mut(),
            413,
            "Payload Too Large",
            "Bağlantı çok uzun",
        );
    }
    let mut bytes = Vec::with_capacity(length as usize);
    reader.take(length).read_to_end(&mut bytes)?;
    let url = String::from_utf8_lossy(&bytes).trim().to_string();
    if !(url.starts_with("https://") || url.starts_with("http://")) || url.contains(['\n', '\r']) {
        return respond_text(
            reader.get_mut(),
            400,
            "Bad Request",
            "Yalnızca HTTP/HTTPS bağlantıları açılabilir",
        );
    }
    let result = if cfg!(windows) {
        Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", url.as_str()])
            .spawn()
    } else {
        Command::new("xdg-open").arg(&url).spawn()
    };
    match result {
        Ok(_) => respond_text(reader.get_mut(), 202, "Accepted", "Bağlantı açılıyor"),
        Err(error) => respond_text(
            reader.get_mut(),
            500,
            "Internal Server Error",
            &format!("Bağlantı açılamadı: {error}"),
        ),
    }
}

fn control<W: Write>(stream: &mut W, action: &str) -> io::Result<()> {
    let result = match (env::consts::OS, action) {
        ("linux", "brightness-up") => Command::new("brightnessctl").args(["set", "+5%"]).spawn(),
        ("linux", "brightness-down") => Command::new("brightnessctl").args(["set", "5%-"]).spawn(),
        ("linux", "display-off") => Command::new("hyprctl")
            .args(["dispatch", "dpms", "off"])
            .spawn(),
        ("linux", "display-on") => Command::new("hyprctl")
            .args(["dispatch", "dpms", "on"])
            .spawn(),
        ("linux", "mic-mute") => Command::new("wpctl")
            .args(["set-mute", "@DEFAULT_AUDIO_SOURCE@", "toggle"])
            .spawn(),
        ("linux", "wifi-on") => Command::new("nmcli").args(["radio", "wifi", "on"]).spawn(),
        ("linux", "wifi-off") => Command::new("nmcli").args(["radio", "wifi", "off"]).spawn(),
        ("linux", "bluetooth-on") => Command::new("bluetoothctl").args(["power", "on"]).spawn(),
        ("linux", "bluetooth-off") => Command::new("bluetoothctl").args(["power", "off"]).spawn(),
        ("linux", "screensaver") => Command::new("omarchy-launch-screensaver")
            .arg("force")
            .spawn(),
        ("windows", "wifi-on") => Command::new("netsh")
            .args(["interface", "set", "interface", "Wi-Fi", "enable"])
            .spawn(),
        ("windows", "wifi-off") => Command::new("netsh")
            .args(["interface", "set", "interface", "Wi-Fi", "disable"])
            .spawn(),
        _ => return respond_text(stream, 400, "Bad Request", "Desteklenmeyen sistem kontrolü"),
    };
    match result {
        Ok(_) => respond_text(stream, 202, "Accepted", "Sistem komutu kabul edildi"),
        Err(error) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &format!("Sistem komutu çalıştırılamadı: {error}"),
        ),
    }
}

fn cancel_scheduled_linux() {
    let _ = Command::new("systemctl")
        .args(["--user", "stop", "hypr-connect-scheduled.timer"])
        .status();
    let _ = Command::new("systemctl")
        .args(["--user", "stop", "hypr-connect-scheduled.service"])
        .status();
}

fn schedule_power<W: Write>(
    stream: &mut W,
    action: &str,
    delay_seconds: Option<u64>,
) -> io::Result<()> {
    let Some(delay) = delay_seconds.filter(|value| (10..=86_400).contains(value)) else {
        return respond_text(stream, 400, "Bad Request", "Gecikme 10-86400 saniye olmalı");
    };
    if env::consts::OS == "windows" {
        let delay_text = delay.to_string();
        let args = match action {
            "shutdown" => ["/s", "/t", delay_text.as_str()],
            "restart" => ["/r", "/t", delay_text.as_str()],
            _ => {
                return respond_text(
                    stream,
                    400,
                    "Bad Request",
                    "Bu zamanlı komut Windows'ta desteklenmiyor",
                );
            }
        };
        return match Command::new("shutdown").args(args).spawn() {
            Ok(_) => respond_text(stream, 202, "Accepted", "Güç komutu zamanlandı"),
            Err(error) => respond_text(
                stream,
                500,
                "Internal Server Error",
                &format!("Komut zamanlanamadı: {error}"),
            ),
        };
    }
    let (program, args): (&str, &[&str]) = match action {
        "shutdown" => ("systemctl", &["poweroff"]),
        "restart" => ("systemctl", &["reboot"]),
        "hibernate" => ("systemctl", &["hibernate"]),
        "lock" if Path::new("/usr/share/omarchy/bin/omarchy-system-lock").exists() => {
            ("/usr/share/omarchy/bin/omarchy-system-lock", &[])
        }
        "lock" => ("loginctl", &["lock-sessions"]),
        _ => return respond_text(stream, 400, "Bad Request", "Desteklenmeyen güç komutu"),
    };
    cancel_scheduled_linux();
    let timer = format!("{delay}s");
    match Command::new("systemd-run")
        .args(["--user", "--unit=hypr-connect-scheduled", "--on-active"])
        .arg(timer)
        .arg(program)
        .args(args)
        .output()
    {
        Ok(output) if output.status.success() => {
            respond_text(stream, 202, "Accepted", "Güç komutu zamanlandı")
        }
        Ok(output) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &String::from_utf8_lossy(&output.stderr),
        ),
        Err(error) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &format!("Komut zamanlanamadı: {error}"),
        ),
    }
}

fn cancel_schedule<W: Write>(stream: &mut W) -> io::Result<()> {
    if env::consts::OS == "windows" {
        let _ = Command::new("shutdown").arg("/a").status();
    } else {
        cancel_scheduled_linux();
    }
    respond_text(stream, 200, "OK", "Zamanlanmış komut iptal edildi")
}

fn clipboard_get<W: Write>(stream: &mut W) -> io::Result<()> {
    let output = if env::consts::OS == "linux" {
        Command::new("wl-paste")
            .args(["--no-newline", "--type", "text"])
            .output()
    } else {
        Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "Get-Clipboard -Raw"])
            .output()
    };
    match output {
        Ok(output) if output.status.success() => {
            respond_text(stream, 200, "OK", &String::from_utf8_lossy(&output.stdout))
        }
        Ok(output) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &String::from_utf8_lossy(&output.stderr),
        ),
        Err(error) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &format!("Pano okunamadı: {error}"),
        ),
    }
}

fn clipboard_set<R: Read + Write>(reader: &mut BufReader<R>, length: u64) -> io::Result<()> {
    if length > 1024 * 1024 {
        return respond_text(
            reader.get_mut(),
            413,
            "Payload Too Large",
            "Pano metni 1 MB sınırını aşıyor",
        );
    }
    let mut body = Vec::with_capacity(length as usize);
    reader.take(length).read_to_end(&mut body)?;
    let mut child = if env::consts::OS == "linux" {
        Command::new("wl-copy").stdin(Stdio::piped()).spawn()
    } else {
        Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "$input | Set-Clipboard"])
            .stdin(Stdio::piped())
            .spawn()
    }?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("Pano girişi açılamadı"))?
        .write_all(&body)?;
    let status = child.wait()?;
    if status.success() {
        respond_text(reader.get_mut(), 200, "OK", "Pano güncellendi")
    } else {
        respond_text(
            reader.get_mut(),
            500,
            "Internal Server Error",
            "Pano güncellenemedi",
        )
    }
}

fn media<W: Write>(stream: &mut W, action: &str) -> io::Result<()> {
    let result: Result<(), String> = if env::consts::OS == "linux" {
        let output = match action {
            "playpause" => Command::new("omarchy-shell")
                .args(["media", "playPause"])
                .output(),
            "next" => Command::new("omarchy-shell")
                .args(["media", "next"])
                .output(),
            "previous" => Command::new("omarchy-shell")
                .args(["media", "previous"])
                .output(),
            "volume-up" => Command::new("wpctl")
                .args(["set-volume", "@DEFAULT_AUDIO_SINK@", "5%+"])
                .output(),
            "volume-down" => Command::new("wpctl")
                .args(["set-volume", "@DEFAULT_AUDIO_SINK@", "5%-"])
                .output(),
            "mute" => Command::new("wpctl")
                .args(["set-mute", "@DEFAULT_AUDIO_SINK@", "toggle"])
                .output(),
            _ => return respond_text(stream, 400, "Bad Request", "Desteklenmeyen medya komutu"),
        };
        output
            .map_err(|error| error.to_string())
            .and_then(|output| {
                if output.status.success() {
                    Ok(())
                } else {
                    Err(String::from_utf8_lossy(&output.stderr).into_owned())
                }
            })
    } else {
        let key = match action {
            "playpause" => 0xB3,
            "next" => 0xB0,
            "previous" => 0xB1,
            "volume-up" => 0xAF,
            "volume-down" => 0xAE,
            "mute" => 0xAD,
            _ => return respond_text(stream, 400, "Bad Request", "Desteklenmeyen medya komutu"),
        };
        send_windows_media_key(key).map_err(|error| error.to_string())
    };
    match result {
        Ok(()) => respond_text(stream, 202, "Accepted", "Medya komutu kabul edildi"),
        Err(error) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &format!("Medya komutu çalıştırılamadı: {error}"),
        ),
    }
}

#[cfg(windows)]
fn send_windows_media_key(key: u8) -> io::Result<()> {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn keybd_event(vk: u8, scan: u8, flags: u32, extra: usize);
    }
    // The agent runs in the signed-in user's interactive session.
    unsafe {
        keybd_event(key, 0, 0, 0);
        keybd_event(key, 0, 2, 0);
    }
    Ok(())
}

#[cfg(not(windows))]
fn send_windows_media_key(_key: u8) -> io::Result<()> {
    Err(io::Error::other("Windows medya tuşları desteklenmiyor"))
}

fn linux_monitor_names() -> Vec<String> {
    Command::new("hyprctl")
        .arg("monitors")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| line.trim().strip_prefix("Monitor "))
                .filter_map(|line| line.split_whitespace().next())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn displays<W: Write>(stream: &mut W) -> io::Result<()> {
    let count = if env::consts::OS == "windows" {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Add-Type -AssemblyName System.Windows.Forms; [Console]::Write([System.Windows.Forms.Screen]::AllScreens.Length)",
            ])
            .output()?;
        if !output.status.success() {
            return respond_text(stream, 500, "Internal Server Error", "Monitörler okunamadı");
        }
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<usize>()
            .unwrap_or(1)
    } else {
        linux_monitor_names().len().max(1)
    };
    respond_json(stream, 200, "OK", &format!("{{\"count\":{count}}}"))
}

fn screenshot<W: Write>(stream: &mut W, path: &str) -> io::Result<()> {
    let selection = path.split_once("?display=").map(|(_, value)| value);
    let display = match selection {
        None | Some("all") => None,
        Some(value) => match value.parse::<usize>() {
            Ok(index) if index < 16 => Some(index),
            _ => return respond_text(stream, 400, "Bad Request", "Geçersiz monitör seçimi"),
        },
    };
    let output = if env::consts::OS == "linux" {
        let mut command = Command::new("grim");
        command.args(["-t", "jpeg", "-q", "78"]);
        if let Some(index) = display {
            let monitors = linux_monitor_names();
            if let Some(name) = monitors.get(index) {
                command.args(["-o", name]);
            } else if index != 0 || !monitors.is_empty() {
                return respond_text(stream, 400, "Bad Request", "Monitör bulunamadı");
            }
        }
        command.arg("-").output()?
    } else {
        let display_arg = display.map_or_else(|| "all".to_owned(), |index| index.to_string());
        let script = format!(
            r#"$selection='{display_arg}'; $ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $screens=@([System.Windows.Forms.Screen]::AllScreens | Sort-Object @{{Expression={{-[int]$_.Primary}}}}); if($selection -eq 'all'){{ $b=[System.Windows.Forms.SystemInformation]::VirtualScreen }} else {{ $n=[int]$selection; if($n -lt 0 -or $n -ge $screens.Count){{ exit 2 }}; $b=$screens[$n].Bounds }}; $i=New-Object System.Drawing.Bitmap $b.Width,$b.Height; $g=[System.Drawing.Graphics]::FromImage($i); $g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size); $m=New-Object System.IO.MemoryStream; $i.Save($m,[System.Drawing.Imaging.ImageFormat]::Jpeg); $g.Dispose(); $i.Dispose(); $bytes=$m.ToArray(); $m.Dispose(); [Console]::OpenStandardOutput().Write($bytes,0,$bytes.Length)"#
        );
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()?
    };
    if !output.status.success() || output.stdout.is_empty() {
        return respond_text(
            stream,
            500,
            "Internal Server Error",
            "Ekran görüntüsü alınamadı",
        );
    }
    respond(stream, 200, "OK", "image/jpeg", &output.stdout)
}

fn system_info<W: Write>(stream: &mut W, config: &Config) -> io::Result<()> {
    if env::consts::OS == "windows" {
        let root = config.root.to_string_lossy();
        let drive = root
            .get(..2)
            .filter(|value| {
                value.ends_with(':') && value.starts_with(|c: char| c.is_ascii_alphabetic())
            })
            .unwrap_or("C:");
        let script = format!(
            "$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;$c=Get-CimInstance Win32_Processor|Select-Object -First 1;$d=Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='{drive}'\";$b=Get-CimInstance Win32_Battery|Select-Object -First 1;$n=Get-NetAdapterStatistics|Measure-Object -Property ReceivedBytes,SentBytes -Sum;[pscustomobject]@{{cpu=[int]$c.LoadPercentage;memoryUsed=($o.TotalVisibleMemorySize-$o.FreePhysicalMemory)*1024;memoryTotal=$o.TotalVisibleMemorySize*1024;diskUsed=$d.Size-$d.FreeSpace;diskTotal=$d.Size;temperature=0;battery=$(if($b){{[int]$b.EstimatedChargeRemaining}}else{{-1}});networkRx=[long]($n|Where-Object {{$_.Property -eq 'ReceivedBytes'}}).Sum;networkTx=[long]($n|Where-Object {{$_.Property -eq 'SentBytes'}}).Sum}}|ConvertTo-Json -Compress"
        );
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()?;
        return if output.status.success() {
            respond_json(stream, 200, "OK", &String::from_utf8_lossy(&output.stdout))
        } else {
            respond_text(
                stream,
                500,
                "Internal Server Error",
                "Sistem bilgisi okunamadı",
            )
        };
    }
    let mem = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let value = |key: &str| -> u64 {
        mem.lines()
            .find(|line| line.starts_with(key))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
            * 1024
    };
    let memory_total = value("MemTotal:");
    let memory_available = value("MemAvailable:");
    let cpu = linux_cpu_percent();
    let disk = Command::new("df")
        .args(["-B1", "--output=size,avail"])
        .arg(&config.root)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let disk_values: Vec<u64> = disk
        .lines()
        .nth(1)
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();
    let disk_total = disk_values.first().copied().unwrap_or(0);
    let disk_available = disk_values.get(1).copied().unwrap_or(0);
    let temperature = fs::read_dir("/sys/class/thermal")
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            fs::read_to_string(e.path().join("temp"))
                .ok()?
                .trim()
                .parse::<f64>()
                .ok()
        })
        .map(|v| v / 1000.0)
        .fold(0.0, f64::max);
    let battery = fs::read_dir("/sys/class/power_supply")
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .find_map(|e| {
            fs::read_to_string(e.path().join("capacity"))
                .ok()?
                .trim()
                .parse::<i64>()
                .ok()
        })
        .unwrap_or(-1);
    let net = fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let (network_rx, network_tx) = net
        .lines()
        .skip(2)
        .filter_map(|line| line.split_once(':').map(|(_, values)| values))
        .fold((0u64, 0u64), |(rx, tx), values| {
            let values: Vec<u64> = values
                .split_whitespace()
                .filter_map(|v| v.parse().ok())
                .collect();
            (
                rx + values.first().copied().unwrap_or(0),
                tx + values.get(8).copied().unwrap_or(0),
            )
        });
    let body = format!(
        "{{\"cpu\":{cpu},\"memoryUsed\":{},\"memoryTotal\":{memory_total},\"diskUsed\":{},\"diskTotal\":{disk_total},\"temperature\":{temperature:.1},\"battery\":{battery},\"networkRx\":{network_rx},\"networkTx\":{network_tx}}}",
        memory_total.saturating_sub(memory_available),
        disk_total.saturating_sub(disk_available)
    );
    respond_json(stream, 200, "OK", &body)
}

fn linux_cpu_percent() -> u64 {
    static PREVIOUS: OnceLock<Mutex<Option<(u64, u64)>>> = OnceLock::new();
    let Some(sample) = fs::read_to_string("/proc/stat").ok().and_then(|text| {
        let values = text
            .lines()
            .next()?
            .split_whitespace()
            .skip(1)
            .filter_map(|value| value.parse::<u64>().ok())
            .collect::<Vec<_>>();
        if values.len() < 5 {
            return None;
        }
        let idle = values[3] + values[4];
        Some((idle, values.iter().sum::<u64>()))
    }) else {
        return 0;
    };
    let mut previous = PREVIOUS.get_or_init(|| Mutex::new(None)).lock().unwrap();
    let result = previous
        .map(|(idle, total)| {
            let elapsed = sample.1.saturating_sub(total);
            let busy = elapsed.saturating_sub(sample.0.saturating_sub(idle));
            busy.saturating_mul(100)
                .checked_div(elapsed)
                .unwrap_or(0)
                .min(100)
        })
        .unwrap_or(0);
    *previous = Some(sample);
    result
}

fn power<W: Write>(stream: &mut W, action: &str) -> io::Result<()> {
    let result = match (env::consts::OS, action) {
        ("linux", "shutdown") => Command::new("systemctl").args(["poweroff"]).spawn(),
        ("linux", "restart") => Command::new("systemctl").args(["reboot"]).spawn(),
        ("linux", "hibernate") => Command::new("systemctl").args(["hibernate"]).spawn(),
        ("linux", "lock") if Path::new("/usr/share/omarchy/bin/omarchy-system-lock").exists() => {
            Command::new("/usr/share/omarchy/bin/omarchy-system-lock").spawn()
        }
        ("linux", "lock") => Command::new("loginctl").args(["lock-sessions"]).spawn(),
        ("windows", "shutdown") => Command::new("shutdown").args(["/s", "/t", "0"]).spawn(),
        ("windows", "restart") => Command::new("shutdown").args(["/r", "/t", "0"]).spawn(),
        ("windows", "hibernate") => Command::new("shutdown").args(["/h"]).spawn(),
        ("windows", "lock") => Command::new("rundll32.exe")
            .arg("user32.dll,LockWorkStation")
            .spawn(),
        _ => return respond_text(stream, 400, "Bad Request", "Desteklenmeyen güç komutu"),
    };
    match result {
        Ok(_) => respond_text(stream, 202, "Accepted", "Komut kabul edildi"),
        Err(error) => respond_text(
            stream,
            500,
            "Internal Server Error",
            &format!("Komut çalıştırılamadı: {error}"),
        ),
    }
}

fn respond_json<W: Write>(stream: &mut W, code: u16, status: &str, body: &str) -> io::Result<()> {
    respond(
        stream,
        code,
        status,
        "application/json; charset=utf-8",
        body.as_bytes(),
    )
}

fn respond_text<W: Write>(stream: &mut W, code: u16, status: &str, body: &str) -> io::Result<()> {
    respond(
        stream,
        code,
        status,
        "text/plain; charset=utf-8",
        body.as_bytes(),
    )
}

fn respond_empty<W: Write>(stream: &mut W, code: u16, status: &str) -> io::Result<()> {
    respond(stream, code, status, "text/plain", &[])
}

fn respond<W: Write>(
    stream: &mut W,
    code: u16,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {code} {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

fn percent_decode(value: &str) -> Result<String, &'static str> {
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("Geçersiz URL kodlaması");
            }
            let high = hex(bytes[index + 1])?;
            let low = hex(bytes[index + 2])?;
            result.push(high * 16 + low);
            index += 3;
        } else {
            result.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(result).map_err(|_| "Dosya adı UTF-8 olmalı")
}

fn hex(value: u8) -> Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("Geçersiz URL kodlaması"),
    }
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c < ' ' => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped
}
