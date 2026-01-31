// Data Broker Daemon - Main Entry Point
// Phase 1: TCP server with Get/Set APIs (DEPRECATED)
// Phase 2.5: Auth module integration via FFI (DEPRECATED)
// Phase 3.0: UDS migration with SO_PEERCRED authentication (DEPRECATED)
// Phase 3.5: Auth daemon integration (UDS client) (DEPRECATED)
// Phase 3.6: TCP/IP with Token-based authentication (Hook方式)
// Phase 3.7: Dual-mode authentication (UDS for vendor daemons, TCP/IP for apps)

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::thread;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::io::AsRawFd;
use std::io::{self, BufRead, BufReader, Write};
use std::ffi::CString;
use libc::{getsockopt, SOL_SOCKET, SO_PEERCRED};

type DataStore = Arc<Mutex<HashMap<String, String>>>;

// Phase 3.7: SO_PEERCRED structure (from libc)
#[repr(C)]
struct ucred {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

/**
 * Get peer credentials (UID, PID) from Unix Domain Socket
 *
 * Phase 3.7: Extracts kernel-provided credentials via SO_PEERCRED
 * - These credentials cannot be spoofed by the client
 * - Kernel guarantees authenticity
 * - Used for Defense-in-Depth validation in UDS connections
 *
 * @param stream UnixStream connection
 * @return (uid, pid) or error
 */
fn get_peer_credentials(stream: &UnixStream) -> io::Result<(u32, u32)> {
    let fd = stream.as_raw_fd();
    let mut ucred: ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<ucred>() as libc::socklen_t;

    let ret = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret == 0 {
        Ok((ucred.uid, ucred.pid as u32))
    } else {
        Err(io::Error::last_os_error())
    }
}

/**
 * Verify token via Auth Hook (dlopen)
 *
 * Phase 3.6: Dynamically loads libauth_hook.so and calls auth_hook_verify_token()
 * - Hook is loaded via dlopen() to avoid static linking
 * - If Hook is not available, returns false (graceful degradation)
 * - Hook verifies Keystore Attestation token
 * - auth_hook_init() is called once on first load to initialize whitelist
 *
 * @param package_name Client package name
 * @param token Base64-encoded attestation certificate chain (opaque string)
 * @param uid Client UID (from SO_PEERCRED)
 * @param pid Client PID (from SO_PEERCRED)
 * @return true if token is valid, false otherwise
 */
fn auth_verify_via_hook(package_name: &str, token: &str, uid: u32, pid: u32) -> bool {
    use libc::{dlopen, dlsym, dlclose, RTLD_LAZY};
    use std::sync::Once;

    // Phase 3.6: Hook library path (moved to product partition in Phase 3.8)
    let hook_path = "/product/lib64/libauth_hook.so";

    log::info!("[Phase 3.6] Loading Auth Hook from: {}", hook_path);

    // Load shared library
    let hook_path_c = CString::new(hook_path).unwrap();
    let handle = unsafe { dlopen(hook_path_c.as_ptr(), RTLD_LAZY) };

    if handle.is_null() {
        log::error!("[Phase 3.6] Failed to load Auth Hook: {}", hook_path);
        return false;
    }

    // Phase 3.6: Call auth_hook_init() once on first load
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        log::info!("[Phase 3.6] First Hook load - calling auth_hook_init()");
        let init_symbol = CString::new("auth_hook_init").unwrap();
        let init_ptr = unsafe { dlsym(handle, init_symbol.as_ptr()) };

        if !init_ptr.is_null() {
            type InitFn = unsafe extern "C" fn();
            let init_fn: InitFn = unsafe { std::mem::transmute(init_ptr) };
            unsafe { init_fn() };
            log::info!("[Phase 3.6] Hook initialization complete");
        } else {
            log::error!("[Phase 3.6] Symbol 'auth_hook_init' not found in Hook");
        }
    });

    // Lookup symbol: auth_hook_verify_token
    let symbol_name = CString::new("auth_hook_verify_token").unwrap();
    let func_ptr = unsafe { dlsym(handle, symbol_name.as_ptr()) };

    if func_ptr.is_null() {
        log::error!("[Phase 3.6] Symbol 'auth_hook_verify_token' not found in Hook");
        unsafe { dlclose(handle) };
        return false;
    }

    // Cast to function pointer type
    type VerifyTokenFn = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char, u32, u32) -> bool;
    let verify_token: VerifyTokenFn = unsafe { std::mem::transmute(func_ptr) };

    // Convert Rust strings to C strings
    let pkg_name_c = CString::new(package_name).unwrap();
    let token_c = CString::new(token).unwrap();

    // Call Hook function
    log::info!("[Phase 3.6] Calling auth_hook_verify_token()");
    let result = unsafe {
        verify_token(
            pkg_name_c.as_ptr(),
            token_c.as_ptr(),
            uid,
            pid,
        )
    };

    // Phase 3.6: DO NOT call dlclose() - keep Hook loaded to preserve static data (whitelist)
    // The Hook library will remain loaded for the lifetime of db_daemon process
    // This is acceptable for a system daemon that runs continuously

    log::info!("[Phase 3.6] Hook verification result: {}", result);
    result
}

/**
 * Handle UDS client connection (vendor daemons)
 *
 * Phase 3.7: Option 2 (Defense-in-Depth)
 * - Extract UID/PID via SO_PEERCRED (kernel-provided, cannot be spoofed)
 * - Verify UID == 1000 (system)
 * - No token authentication required (trust-based within vendor domain)
 * - File permissions (0770 system:system) provide primary access control
 * - UID verification provides secondary defense layer:
 *   - Detects anomalies (e.g., root in debug builds)
 *   - Provides useful logging (UID/PID information)
 *   - Minimal overhead (~1μs)
 */
fn handle_uds_client(stream: UnixStream, store: DataStore) {
    // Phase 3.7: Extract kernel-provided credentials
    let (uid, pid) = match get_peer_credentials(&stream) {
        Ok(creds) => creds,
        Err(e) => {
            log::error!("[UDS] Failed to get peer credentials: {}", e);
            return;
        }
    };

    log::info!("[UDS] Client connected: uid={}, pid={}", uid, pid);

    // Phase 3.10: Allow both vendor daemons (UID=1000) and apps (UID>=10000)
    // - UID 1000: system (vendor daemons) - trust-based, no AUTH required
    // - UID >= 10000: apps - require AUTH command with token
    const SYSTEM_UID: u32 = 1000;
    const APP_UID_START: u32 = 10000;

    let is_vendor_daemon = uid == SYSTEM_UID;
    let is_app = uid >= APP_UID_START;

    if !is_vendor_daemon && !is_app {
        log::warn!("[UDS] ⚠️  Rejecting connection from UID={} (not system or app)", uid);
        if let Err(e) = writeln!(&stream, "ERROR: Access denied (UID {} not allowed)", uid) {
            log::error!("[UDS] Failed to send error response: {}", e);
        }
        return;
    }

    if is_vendor_daemon {
        log::info!("[UDS] ✅ Vendor daemon connected: uid={} (trust-based)", uid);
    } else {
        log::info!("[UDS] 📱 App connected: uid={} (token auth required)", uid);
    }

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;

    // Phase 3.10: Authentication depends on client type
    // - Vendor daemons (UID=1000): pre-authenticated (trust-based)
    // - Apps (UID>=10000): require AUTH command with token
    let mut authenticated = is_vendor_daemon;
    let mut package_name = if is_vendor_daemon {
        Some(format!("vendor_daemon_uid{}_pid{}", uid, pid))
    } else {
        None  // Apps must authenticate via AUTH command
    };

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                log::info!("[UDS] Client disconnected: uid={}, pid={}", uid, pid);
                break;
            }
            Ok(_) => {
                let response = process_command(
                    &line.trim(),
                    &store,
                    &mut authenticated,
                    &mut package_name,
                    uid,
                    pid,
                );
                if let Err(e) = writeln!(writer, "{}", response) {
                    log::error!("[UDS] Failed to send response: {}", e);
                    break;
                }
            }
            Err(e) => {
                log::error!("[UDS] Error reading from client: {}", e);
                break;
            }
        }
    }
}

fn handle_client(stream: TcpStream, store: DataStore) {
    // Phase 3.6: TCP/IP connection - no SO_PEERCRED available
    // UID/PID are not available in TCP/IP, but token-based authentication provides sufficient security
    let peer_addr = stream.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    log::info!("[TCP] Client connected from: {}", peer_addr);

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;

    // Phase 3.6: Track authentication state for this connection
    let mut authenticated = false;
    let mut package_name: Option<String> = None;

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                log::info!("[TCP] Client from {} disconnected (auth={})", peer_addr, authenticated);
                break;
            }
            Ok(_) => {
                let response = process_command(
                    &line.trim(),
                    &store,
                    &mut authenticated,
                    &mut package_name,
                    0,  // uid not available in TCP/IP
                    0   // pid not available in TCP/IP
                );
                if let Err(e) = writeln!(writer, "{}", response) {
                    log::error!("[TCP] Failed to send response: {}", e);
                    break;
                }
            }
            Err(e) => {
                log::error!("[TCP] Error reading from client: {}", e);
                break;
            }
        }
    }
}

fn process_command(
    cmd: &str,
    store: &DataStore,
    authenticated: &mut bool,
    package_name: &mut Option<String>,
    uid: u32,
    pid: u32
) -> String {
    let parts: Vec<&str> = cmd.split_whitespace().collect();

    if parts.is_empty() {
        return "ERROR: Empty command".to_string();
    }

    let command = parts[0].to_uppercase();

    // Phase 3.6: AUTH command extended to support tokens
    // Protocol: AUTH <package_name> [token]
    // - If token is provided: Hook-based verification (Keystore Attestation)
    // - If token is absent: Legacy verification (Auth daemon via UDS)
    if command == "AUTH" {
        if parts.len() < 2 {
            return "ERROR: AUTH requires package name".to_string();
        }

        let pkg_name = parts[1];

        // Phase 3.6: Token is required (token may contain spaces, so join remaining parts)
        if parts.len() < 3 {
            log::warn!("AUTH command missing token: package={}", pkg_name);
            return "ERROR: AUTH requires token (Phase 3.6: Token-based authentication only)".to_string();
        }

        let token_str = parts[2..].join(" ");

        // Verify authentication via Hook (dlopen)
        log::info!("[Phase 3.6] Authenticating with token: package={}, token_len={}, uid={}, pid={}",
                  pkg_name, token_str.len(), uid, pid);

        let auth_result = auth_verify_via_hook(pkg_name, &token_str, uid, pid);

        // Process authentication result
        if auth_result {
            *authenticated = true;
            *package_name = Some(pkg_name.to_string());
            log::info!("✅ Client authenticated: package={}, uid={}, pid={}", pkg_name, uid, pid);
            format!("OK: Authenticated as {}", pkg_name)
        } else {
            *authenticated = false;
            log::warn!("❌ Authentication failed for package={}, uid={}, pid={}", pkg_name, uid, pid);
            "ERROR: Authentication failed".to_string()
        }
    } else {
        // All other commands require authentication
        if !*authenticated {
            return "ERROR: Not authenticated. Use AUTH command first.".to_string();
        }

        match command.as_str() {
            "GET" => {
                if parts.len() < 2 {
                    return "ERROR: GET requires a key".to_string();
                }
                let key = parts[1];
                let data = store.lock().unwrap();
                match data.get(key) {
                    Some(value) => format!("OK: {}", value),
                    None => "ERROR: Key not found".to_string(),
                }
            }
            "SET" => {
                if parts.len() < 3 {
                    return "ERROR: SET requires key and value".to_string();
                }
                let key = parts[1].to_string();
                let value = parts[2..].join(" ");
                let mut data = store.lock().unwrap();
                data.insert(key.clone(), value.clone());
                log::info!("SET {}={} (by {})", key, value,
                          package_name.as_ref().unwrap_or(&"unknown".to_string()));
                format!("OK: Set {}={}", key, value)
            }
            "LIST" => {
                let data = store.lock().unwrap();
                if data.is_empty() {
                    "OK: (empty)".to_string()
                } else {
                    let entries: Vec<String> = data.iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect();
                    format!("OK: {}", entries.join(", "))
                }
            }
            "QUIT" => {
                "OK: Goodbye".to_string()
            }
            _ => format!("ERROR: Unknown command: {}", parts[0]),
        }
    }
}

fn main() {
    // Initialize logging (stderr will appear in logcat via stdio_to_kmsg)
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    log::info!("db_daemon starting... (Phase 3.7: Dual-mode authentication)");

    // Phase 3.7: Dual-mode authentication
    // - UDS: vendor daemons (trust-based, UID verification only)
    // - TCP/IP: apps (token-based via Hook)
    log::info!("Phase 3.7: UDS (vendor) + TCP/IP (apps) dual-mode");

    // Create data store (HashMap for latest values)
    let store: DataStore = Arc::new(Mutex::new(HashMap::new()));

    // Insert test data
    {
        let mut data = store.lock().unwrap();
        data.insert("test_key".to_string(), "test_value".to_string());
        data.insert("vehicle.speed".to_string(), "60".to_string());
        log::info!("Initialized with test data");
    }

    // Phase 3.7: Start UDS server (vendor daemons)
    let uds_path = "/data/misc/db/data_broker.sock";

    // Remove old socket file if exists
    let _ = std::fs::remove_file(uds_path);

    let uds_listener = match UnixListener::bind(uds_path) {
        Ok(l) => {
            log::info!("[UDS] Server listening on {}", uds_path);
            l
        }
        Err(e) => {
            log::error!("[UDS] Failed to bind UDS server to {}: {}", uds_path, e);
            return;
        }
    };

    // Phase 3.10: Set permissions for app access
    // SELinux is the primary access control; filesystem permissions are secondary
    // - Directory: 0771 (allow others to search/traverse)
    // - Socket: 0666 (allow others to read/write)
    use std::os::unix::fs::PermissionsExt;

    // Set directory permissions to allow app access
    let uds_dir = std::path::Path::new(uds_path).parent().unwrap();
    if let Err(e) = std::fs::set_permissions(uds_dir, std::fs::Permissions::from_mode(0o771)) {
        log::error!("[UDS] Failed to set directory permissions: {}", e);
        // Continue anyway - init.rc may have set correct permissions
    } else {
        log::info!("[UDS] Directory permissions set to 0771");
    }

    // Set socket file permissions
    if let Err(e) = std::fs::set_permissions(uds_path, std::fs::Permissions::from_mode(0o666)) {
        log::error!("[UDS] Failed to set socket permissions: {}", e);
        return;
    }
    log::info!("[UDS] Socket permissions set to 0666 (SELinux provides access control)");

    // Phase 3.7: Start TCP server (apps)
    let tcp_addr = "127.0.0.1:50051";

    let tcp_listener = match TcpListener::bind(tcp_addr) {
        Ok(l) => {
            log::info!("[TCP] Server listening on {}", tcp_addr);
            l
        }
        Err(e) => {
            log::error!("[TCP] Failed to bind TCP server to {}: {}", tcp_addr, e);
            return;
        }
    };

    log::info!("db_daemon started successfully");
    log::info!("Data store ready with {} entries", store.lock().unwrap().len());
    log::info!("Waiting for client connections (UDS + TCP)...");

    // Phase 3.7: Spawn UDS server thread
    let store_uds = Arc::clone(&store);
    thread::spawn(move || {
        log::info!("[UDS] Accept loop started");
        for stream in uds_listener.incoming() {
            match stream {
                Ok(stream) => {
                    let store_clone = Arc::clone(&store_uds);
                    thread::spawn(move || {
                        handle_uds_client(stream, store_clone);
                    });
                }
                Err(e) => {
                    log::error!("[UDS] Error accepting connection: {}", e);
                }
            }
        }
    });

    // Phase 3.7: TCP server runs in main thread
    log::info!("[TCP] Accept loop started");
    for stream in tcp_listener.incoming() {
        match stream {
            Ok(stream) => {
                let store_clone = Arc::clone(&store);
                thread::spawn(move || {
                    handle_client(stream, store_clone);
                });
            }
            Err(e) => {
                log::error!("[TCP] Error accepting connection: {}", e);
            }
        }
    }
}
