//! C ABI shared by Android JNI and Apple. Carries unchanged PAYPHONE frames.
//! Receive has a short deadline so foreign-language cancellation can close it.

use bytes::Bytes;
use payphone_transport::{client::create_client_endpoint_on_socket, obfuscation::ObfuscationKey};
use quinn::{Connection, Endpoint};
use std::{
    collections::HashMap,
    net::UdpSocket,
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::runtime::Runtime;

struct Link {
    endpoint: Endpoint,
    socket: UdpSocket,
    connection: RwLock<Option<Connection>>,
    // Keep receive calls serialized; send/close remain independent.
    receive: Mutex<()>,
}

static LINKS: OnceLock<RwLock<HashMap<u64, Arc<Link>>>> = OnceLock::new();
static NEXT: AtomicU64 = AtomicU64::new(1);
fn links() -> &'static RwLock<HashMap<u64, Arc<Link>>> {
    LINKS.get_or_init(RwLock::default)
}
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("mobile runtime")
    })
}
fn link(handle: u64) -> Option<Arc<Link>> {
    links().read().ok()?.get(&handle).cloned()
}
fn connection(handle: u64) -> Option<Connection> {
    link(handle)?.connection.read().ok()?.clone()
}

/// Remote address as a big-endian numeric IPv4 value, or 0 before connect.
#[unsafe(no_mangle)]
pub extern "C" fn pp_remote_ipv4(handle: u64) -> u32 {
    match connection(handle).map(|c| c.remote_address().ip()) {
        Some(std::net::IpAddr::V4(ip)) => u32::from_be_bytes(ip.octets()),
        _ => 0,
    }
}

/// Open but do not connect: Android MUST protect `pp_socket_fd` before `pp_connect`.
/// # Safety
/// key must point to 32 bytes; pin must point to pin_len bytes (or be null for 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_open(key: *const u8, pin: *const u8, pin_len: usize) -> u64 {
    if key.is_null() || (pin.is_null() && pin_len != 0) || pin_len > 65536 {
        return 0;
    }
    let key: [u8; 32] = unsafe { std::slice::from_raw_parts(key, 32) }
        .try_into()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    if pin_len == 0 {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    } else {
        let certificate = unsafe { std::slice::from_raw_parts(pin, pin_len) }.to_vec();
        if roots
            .add(rustls::pki_types::CertificateDer::from(certificate))
            .is_err()
        {
            return 0;
        }
    }
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return 0;
    };
    let Ok(owned) = socket.try_clone() else {
        return 0;
    };
    let _guard = runtime().enter();
    let Ok(endpoint) = create_client_endpoint_on_socket(
        owned,
        ObfuscationKey::from_derived_key(key),
        false,
        roots,
    ) else {
        return 0;
    };
    let handle = NEXT.fetch_add(1, Ordering::Relaxed);
    links().write().unwrap().insert(
        handle,
        Arc::new(Link {
            endpoint,
            socket,
            connection: RwLock::new(None),
            receive: Mutex::new(()),
        }),
    );
    handle
}

#[unsafe(no_mangle)]
pub extern "C" fn pp_socket_fd(handle: u64) -> i32 {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        link(handle).map(|l| l.socket.as_raw_fd()).unwrap_or(-1)
    }
    #[cfg(not(unix))]
    {
        let _ = handle;
        -1
    }
}

/// # Safety
/// address and sni must point to UTF-8 buffers of the specified lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_connect(
    handle: u64,
    address: *const u8,
    address_len: usize,
    sni: *const u8,
    sni_len: usize,
) -> i32 {
    if address.is_null() || sni.is_null() || address_len > 1024 || sni_len > 255 {
        return -1;
    }
    let Ok(address) =
        std::str::from_utf8(unsafe { std::slice::from_raw_parts(address, address_len) })
    else {
        return -1;
    };
    let Ok(sni) = std::str::from_utf8(unsafe { std::slice::from_raw_parts(sni, sni_len) }) else {
        return -1;
    };
    let Some(link) = link(handle) else {
        return -1;
    };
    let result = runtime().block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let target = tokio::net::lookup_host(address)
                .await
                .ok()?
                .find(|addr| addr.is_ipv4())?;
            link.endpoint.connect(target, sni).ok()?.await.ok()
        })
        .await
    });
    match result {
        Ok(Some(connection)) => {
            *link.connection.write().unwrap() = Some(connection);
            1
        }
        _ => -1,
    }
}

/// 1 = queued, 0 = exceeds current datagram budget, -1 = closed/error.
/// # Safety
/// data must point to len bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_send(handle: u64, data: *const u8, len: usize) -> i32 {
    if data.is_null() || len > 65535 {
        return -1;
    }
    let Some(connection) = connection(handle) else {
        return -1;
    };
    let bytes = Bytes::copy_from_slice(unsafe { std::slice::from_raw_parts(data, len) });
    match payphone_transport::send_vpn_datagram(&connection, bytes) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

/// >0 = bytes copied, 0 = poll timeout (50ms), -1 = closed/error.
/// # Safety
/// out must point to capacity writable bytes, with capacity at least 65535.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pp_receive(handle: u64, out: *mut u8, capacity: usize) -> i32 {
    if out.is_null() || capacity < 65535 {
        return -1;
    }
    let Some(link) = link(handle) else {
        return -1;
    };
    let Ok(_receive) = link.receive.lock() else {
        return -1;
    };
    let Some(connection) = connection(handle) else {
        return -1;
    };
    let result = runtime().block_on(async {
        tokio::time::timeout(Duration::from_millis(50), connection.read_datagram()).await
    });
    match result {
        Ok(Ok(bytes)) if bytes.len() <= capacity => {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
            }
            bytes.len() as i32
        }
        Err(_) => 0,
        _ => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pp_close(handle: u64) {
    if let Some(link) = links().write().unwrap().remove(&handle) {
        link.endpoint.close(0u32.into(), b"mobile closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use payphone_transport::{
        identity::{CERT_PATH, ServerTlsConfig, ensure_dev_identity},
        server::create_server_endpoint,
    };

    #[test]
    fn ffi_roundtrip_and_close_interrupts_receive() {
        ensure_dev_identity().unwrap();
        let key = [7u8; 32];
        let cert = std::fs::read(CERT_PATH).unwrap();
        let _guard = runtime().enter();
        let server = create_server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            ObfuscationKey::from_derived_key(key),
            false,
            &ServerTlsConfig::default(),
        )
        .unwrap();
        let address = server.local_addr().unwrap().to_string();
        let server_task = runtime().spawn(async move {
            let c = server.accept().await.unwrap().await.unwrap();
            let packet = c.read_datagram().await.unwrap();
            c.send_datagram(packet).unwrap();
            c.closed().await;
        });
        let handle = unsafe { pp_open(key.as_ptr(), cert.as_ptr(), cert.len()) };
        assert_ne!(handle, 0);
        assert!(pp_socket_fd(handle) >= 0);
        assert_eq!(
            unsafe {
                pp_connect(
                    handle,
                    address.as_ptr(),
                    address.len(),
                    b"localhost".as_ptr(),
                    9,
                )
            },
            1
        );
        assert_eq!(pp_remote_ipv4(handle), u32::from_be_bytes([127, 0, 0, 1]));
        let payload = [0xAB; 1140];
        assert_eq!(
            unsafe { pp_send(handle, payload.as_ptr(), payload.len()) },
            1
        );
        let mut out = [0; 65535];
        let start = std::time::Instant::now();
        loop {
            let n = unsafe { pp_receive(handle, out.as_mut_ptr(), out.len()) };
            assert!(n >= 0);
            if n > 0 {
                assert_eq!(&out[..n as usize], &payload);
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(2));
        }
        let receiver = std::thread::spawn(move || {
            let mut out = [0; 65535];
            unsafe { pp_receive(handle, out.as_mut_ptr(), out.len()) }
        });
        pp_close(handle);
        assert!(receiver.join().unwrap() <= 0);
        assert_eq!(
            unsafe { pp_send(handle, payload.as_ptr(), payload.len()) },
            -1
        );
        runtime().block_on(server_task).unwrap();
    }

    #[test]
    fn ffi_rejects_wrong_hostname() {
        ensure_dev_identity().unwrap();
        let key = [9u8; 32];
        let cert = std::fs::read(CERT_PATH).unwrap();
        let _guard = runtime().enter();
        let server = create_server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            ObfuscationKey::from_derived_key(key),
            false,
            &ServerTlsConfig::default(),
        )
        .unwrap();
        let address = server.local_addr().unwrap().to_string();
        let acceptor = server.clone();
        let task = runtime().spawn(async move {
            let _ = acceptor.accept().await.unwrap().await;
        });
        let handle = unsafe { pp_open(key.as_ptr(), cert.as_ptr(), cert.len()) };
        assert_ne!(handle, 0);
        assert_eq!(
            unsafe {
                pp_connect(
                    handle,
                    address.as_ptr(),
                    address.len(),
                    b"wrong.invalid".as_ptr(),
                    13,
                )
            },
            -1
        );
        pp_close(handle);
        server.close(0u32.into(), b"done");
        runtime().block_on(task).unwrap();
    }
}
