//! JNI bridge between the Android app shell (`com.chameleonpq.android`, see
//! `../app/`) and the `chameleon` core crate. Everything platform-specific
//! about Android lives here or in the Kotlin shell — the core crate itself
//! needed exactly one addition to support this (`TunPair::from_raw_fd`,
//! `src/tun_iface.rs`), and knows nothing about JNI, Android, or this crate.
//!
//! Four exported functions, matching `NativeBridge.kt`'s `external fun`
//! declarations one for one — deliberately kept this small (see the plan:
//! hand-written JNI was chosen over UniFFI precisely because the real surface
//! is this tiny). All fallible logic lives in a plain-Rust-typed `*_inner`
//! function per export; the `Java_...` wrapper only does JNI type marshalling
//! and turns `Err`/a caught panic into a thrown `RuntimeException` — no
//! `JNIEnv` ever crosses into a `catch_unwind`, which sidesteps the
//! `UnwindSafe` ceremony that would otherwise be needed.
//!
//! Single-instance client: this is a personal VPN app, not a session
//! manager, so "already connected" is a hard error rather than something
//! that queues or replaces.

use chameleon::client::{build_auth, Client};
use chameleon::config::{AppConfig, TrafficConfig, TrafficProfile};
use chameleon::ChameleonError;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use serde::Serialize;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, OnceLock};

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static CLIENT: Mutex<Option<Arc<Client>>> = Mutex::new(None);
/// Traffic profile chosen in the UI. Wins over `[traffic] profile` in the
/// imported config: the app, not the TOML, is where a user picks it. Survives
/// across (re)connects.
static PROFILE_OVERRIDE: Mutex<Option<TrafficProfile>> = Mutex::new(None);
/// `[traffic]` section of the running session, so a live profile switch keeps
/// its other fields (cooldown). `None` while disconnected.
static TRAFFIC: Mutex<Option<TrafficConfig>> = Mutex::new(None);
static LOG_INIT: std::sync::Once = std::sync::Once::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build the Android JNI tokio runtime")
    })
}

/// Idempotent: safe to call from every export, cheap after the first call.
/// Without this, every `tracing::info!`/`warn!`/`error!` the core crate emits
/// (handshake state, TUN errors, route/DNS warnings) targets stdout/stderr,
/// which Android silently discards for app processes — on-device failures
/// would otherwise be unreadable from `adb logcat`.
fn init_logging() {
    LOG_INIT.call_once(|| {
        #[cfg(target_os = "android")]
        paranoid_android::init("chameleon");
        // Off-device dev builds only (see Cargo.toml) — never linked into
        // the real Android .so.
        #[cfg(not(target_os = "android"))]
        let _ = tracing_subscriber::fmt::try_init();
    });
}

fn config_error(msg: impl Into<String>) -> ChameleonError {
    ChameleonError::Handshake {
        state: "jni".into(),
        msg: msg.into(),
    }
}

/// The DNS resolvers the tunnel will actually use once `androidize` runs:
/// the configured list, or a hardcoded fallback if empty. Shared by
/// `native_tun_params_inner` (so Kotlin's `Builder.addDnsServer` calls match
/// reality) and `androidize` (so `nativeStart` matches what it reported) —
/// one place, so the two can't drift apart.
fn effective_dns(cfg: &chameleon::config::TunConfig) -> Vec<String> {
    if cfg.dns.is_empty() {
        vec!["1.1.1.1".into(), "1.0.0.1".into()]
    } else {
        cfg.dns.clone()
    }
}

/// Overrides applied to an imported (desktop-generated) config so it makes
/// sense under Android's own VpnService-managed routing instead of this
/// crate's desktop full-tunnel machinery (`route.rs`/`dns.rs`/
/// `killswitch.rs`) — `chameleon-pq init` defaults to `route_all = true`
/// (see `src/setup.rs`), so this WILL fire on essentially every real config.
/// Override, don't reject: keeps "one config file, both platforms" instead
/// of forcing a hand-maintained phone-only config.
fn androidize(cfg: &mut AppConfig) {
    if cfg.tun.route_all {
        tracing::warn!(
            "config: tun.route_all ignored on Android — \
             VpnService.Builder's own 0.0.0.0/0 route replaces it"
        );
        cfg.tun.route_all = false;
    }
    if cfg.tun.kill_switch {
        tracing::warn!(
            "config: tun.kill_switch ignored on Android — use the OS \
             \"Always-on VPN / Block connections without VPN\" setting instead"
        );
        cfg.tun.kill_switch = false;
    }
    cfg.tun.dns = effective_dns(&cfg.tun);
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

// ── nativeTunParams ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct TunParamsJson {
    address: String,
    netmask: String,
    mtu: u16,
    dns: Vec<String>,
}

/// Parses `configToml` and returns the fields Kotlin needs to build a
/// `VpnService.Builder` — address/netmask/mtu/dns — as JSON. This is also
/// Kotlin's ONLY config-validation step: a thrown exception here means the
/// config is bad, no second TOML parser needed on the Kotlin side.
fn native_tun_params_inner(config_toml: &str) -> chameleon::Result<String> {
    let cfg = AppConfig::from_toml_str(config_toml)?;
    let params = TunParamsJson {
        address: cfg.tun.address.clone(),
        netmask: cfg.tun.netmask.clone(),
        mtu: cfg.tun.mtu,
        dns: effective_dns(&cfg.tun),
    };
    Ok(serde_json::to_string(&params).unwrap_or_else(|_| "{}".into()))
}

#[no_mangle]
pub extern "system" fn Java_com_chameleonpq_android_NativeBridge_nativeTunParams<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_toml: JString<'local>,
) -> jstring {
    init_logging();
    let config_str: String = match env.get_string(&config_toml) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", format!("bad string arg: {e}"));
            return std::ptr::null_mut();
        }
    };
    match catch_unwind(AssertUnwindSafe(|| native_tun_params_inner(&config_str))) {
        Ok(Ok(json)) => env
            .new_string(json)
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Ok(Err(e)) => {
            let _ = env.throw_new("java/lang/RuntimeException", e.to_string());
            std::ptr::null_mut()
        }
        Err(payload) => {
            let msg = panic_message(&*payload);
            tracing::error!("panic in nativeTunParams: {msg}");
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("internal error: {msg}"),
            );
            std::ptr::null_mut()
        }
    }
}

// ── nativeStart ──────────────────────────────────────────────────────────

/// `fd` is Android's `ParcelFileDescriptor.getFd()` — Kotlin keeps the
/// `ParcelFileDescriptor` itself alive and owns closing it; see
/// `TunPair::from_raw_fd`'s doc for the ordering contract with `nativeStop`.
fn native_start_inner(fd: i32, config_toml: &str) -> chameleon::Result<()> {
    // Brief lock just to check-and-reject a concurrent start; the actual
    // handshake below runs without holding it. A start-button-disabled-while-
    // connecting UI (the only realistic caller) never races this in practice —
    // not worth a bigger lock scope for a single-instance personal VPN client.
    if CLIENT.lock().unwrap_or_else(|p| p.into_inner()).is_some() {
        return Err(config_error("already connected — call nativeStop first"));
    }

    let mut cfg = AppConfig::from_toml_str(config_toml)?;
    androidize(&mut cfg);
    if let Some(p) = *PROFILE_OVERRIDE.lock().unwrap_or_else(|p| p.into_inner()) {
        cfg.traffic.profile = p;
    }
    let server = cfg
        .network
        .server_addr
        .ok_or_else(|| config_error("network.server_addr not set in config"))?;

    // `from_raw_fd` registers the fd with the tokio reactor and spawns the
    // TUN I/O tasks, so it must run inside the runtime's context — we are on
    // a plain JVM thread here, not a tokio worker.
    let _guard = runtime().enter();
    let tun = chameleon::tun_iface::TunPair::from_raw_fd(fd, cfg.tun.mtu)?;
    let auth = build_auth(&cfg)?;
    let client = runtime().block_on(Client::connect(&cfg, server, auth, tun))?;

    *TRAFFIC.lock().unwrap_or_else(|p| p.into_inner()) = Some(cfg.traffic.clone());
    *CLIENT.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(client));
    Ok(())
}

#[no_mangle]
pub extern "system" fn Java_com_chameleonpq_android_NativeBridge_nativeStart<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    fd: jint,
    config_toml: JString<'local>,
) -> jboolean {
    init_logging();
    let config_str: String = match env.get_string(&config_toml) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", format!("bad string arg: {e}"));
            return JNI_FALSE;
        }
    };
    match catch_unwind(AssertUnwindSafe(|| native_start_inner(fd, &config_str))) {
        Ok(Ok(())) => JNI_TRUE,
        Ok(Err(e)) => {
            let _ = env.throw_new("java/lang/RuntimeException", e.to_string());
            JNI_FALSE
        }
        Err(payload) => {
            let msg = panic_message(&*payload);
            tracing::error!("panic in nativeStart: {msg}");
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("internal error: {msg}"),
            );
            JNI_FALSE
        }
    }
}

// ── nativeStop ───────────────────────────────────────────────────────────

/// Best-effort, matching `Client::disconnect_and_wait`'s own signature — a
/// stop should never fail loudly, it should just make the state consistent
/// again. Only returns once teardown has fully completed: Kotlin's
/// `pfd.close()` MUST wait for this to return before closing the fd (see
/// `TunPair::from_raw_fd`'s doc for why).
fn native_stop_inner() {
    *TRAFFIC.lock().unwrap_or_else(|p| p.into_inner()) = None;
    let client = CLIENT.lock().unwrap_or_else(|p| p.into_inner()).take();
    if let Some(client) = client {
        runtime().block_on(client.disconnect_and_wait());
    }
}

#[no_mangle]
pub extern "system" fn Java_com_chameleonpq_android_NativeBridge_nativeStop<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    init_logging();
    if let Err(payload) = catch_unwind(AssertUnwindSafe(native_stop_inner)) {
        let msg = panic_message(&*payload);
        tracing::error!("panic in nativeStop: {msg}");
        let _ = env.throw_new(
            "java/lang/RuntimeException",
            format!("internal error: {msg}"),
        );
    }
}

// ── nativeSetProfile ─────────────────────────────────────────────────────

/// Config-file spelling of a profile (what the UI sends). `custom` is not
/// offered in the app.
fn parse_profile(name: &str) -> Option<TrafficProfile> {
    match name {
        "off" => Some(TrafficProfile::Off),
        "balanced" => Some(TrafficProfile::Balanced),
        "throughput" => Some(TrafficProfile::Throughput),
        "stealth" => Some(TrafficProfile::Stealth),
        _ => None,
    }
}

/// Remembers the profile for the next connect and, if a tunnel is running,
/// applies it live (same path as the desktop GUI: `Client::set_traffic`).
fn native_set_profile_inner(name: &str) -> chameleon::Result<()> {
    let profile = parse_profile(name)
        .ok_or_else(|| config_error(format!("unknown traffic profile '{name}'")))?;
    *PROFILE_OVERRIDE.lock().unwrap_or_else(|p| p.into_inner()) = Some(profile);

    let client = CLIENT.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let mut traffic = TRAFFIC.lock().unwrap_or_else(|p| p.into_inner());
    if let (Some(client), Some(tc)) = (client, traffic.as_mut()) {
        tc.profile = profile;
        client.set_traffic(tc.effective());
        tracing::info!("traffic profile changed live: {name}");
    }
    Ok(())
}

#[no_mangle]
pub extern "system" fn Java_com_chameleonpq_android_NativeBridge_nativeSetProfile<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    profile: JString<'local>,
) {
    init_logging();
    let name: String = match env.get_string(&profile) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", format!("bad string arg: {e}"));
            return;
        }
    };
    match catch_unwind(AssertUnwindSafe(|| native_set_profile_inner(&name))) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = env.throw_new("java/lang/RuntimeException", e.to_string());
        }
        Err(payload) => {
            let msg = panic_message(&*payload);
            tracing::error!("panic in nativeSetProfile: {msg}");
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("internal error: {msg}"),
            );
        }
    }
}

// ── nativeStatus ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusJson {
    connected: bool,
    session_id: u32,
    tx_bytes: u64,
    rx_bytes: u64,
    uptime_secs: u64,
}

/// Always succeeds — "no client yet" is a valid, expected state (before the
/// first connect, or after a clean disconnect), not an error.
fn native_status_inner() -> String {
    let guard = CLIENT.lock().unwrap_or_else(|p| p.into_inner());
    let json = match guard.as_ref() {
        Some(client) => {
            let s = client.status();
            StatusJson {
                connected: s.connected,
                session_id: s.session_id,
                tx_bytes: s.tx_bytes,
                rx_bytes: s.rx_bytes,
                uptime_secs: s.uptime_secs,
            }
        }
        None => StatusJson {
            connected: false,
            session_id: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            uptime_secs: 0,
        },
    };
    serde_json::to_string(&json).unwrap_or_else(|_| "{}".into())
}

#[no_mangle]
pub extern "system" fn Java_com_chameleonpq_android_NativeBridge_nativeStatus<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    init_logging();
    match catch_unwind(native_status_inner) {
        Ok(json) => env
            .new_string(json)
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(payload) => {
            let msg = panic_message(&*payload);
            tracing::error!("panic in nativeStatus: {msg}");
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("internal error: {msg}"),
            );
            std::ptr::null_mut()
        }
    }
}
