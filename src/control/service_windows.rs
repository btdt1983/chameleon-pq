//! Windows service host: SCM registration, the service main, and a console mode.
//!
//! The service owns the controller (and through it the tunnel, routes, DNS and
//! kill switch) and serves the control pipe. See `docs/DESIGN-windows-service.md`.
//!
//! Stopping is orderly: the SCM is told "stop pending" with a wait hint and
//! periodic checkpoints, the pipe stops accepting, and only after the controller
//! has restored routes/DNS/firewall do we report "stopped". Reporting stopped
//! early would leave the host half-configured.

use super::controller::{self, ControllerHandle};
use super::pipe_windows;
use super::policy::Policy;
use super::server::Server;
use super::supervisor::Supervisor;
use super::winsec_windows as winsec;
use crate::config::{AppConfig, ServiceAction};
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::oneshot;
use windows_service::service::{
    ServiceAccess, ServiceAction as ScmAction, ServiceActionType, ServiceControl,
    ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "ChameleonPQ";
const DISPLAY_NAME: &str = "Chameleon-PQ VPN";
const DESCRIPTION: &str = "Hybrid post-quantum VPN client (tunnel, routes, DNS and kill switch).";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Config path handed to `service_main`, which the SCM calls without our context.
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Entry for `chameleon-pq service ...`. Runs before any tokio runtime exists.
pub fn run_cli(action: &ServiceAction, config: &Path, verbose: u8) -> Result<()> {
    match action {
        ServiceAction::Install {
            allow_insecure_path,
        } => install(config, *allow_insecure_path),
        ServiceAction::Harden => harden(config),
        ServiceAction::Uninstall => uninstall(),
        ServiceAction::Run => {
            CONFIG_PATH
                .set(config.to_path_buf())
                .map_err(|_| anyhow!("service started twice"))?;
            service_dispatcher::start(SERVICE_NAME, ffi_service_main)
                .context("could not connect to the Service Control Manager (use `service console` to run interactively)")
        }
        ServiceAction::Console => {
            init_console_logging(verbose);
            // Debug mode: a failing folder check is a warning here, not a stop,
            // so an administrator can try things in a scratch folder.
            let (cfg, policy) = startup(config, false)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_core(cfg, policy, async {
                let _ = tokio::signal::ctrl_c().await;
            }))
        }
    }
}

// ── Service main ─────────────────────────────────────────────────────────────

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service failed: {e:#}");
    }
}

fn status(
    state: ServiceState,
    accept: ServiceControlAccept,
    exit: ServiceExitCode,
    checkpoint: u32,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accept,
        exit_code: exit,
        checkpoint,
        wait_hint,
        process_id: None,
    }
}

fn run_service() -> Result<()> {
    let (stop_tx, stop_rx) = std_mpsc::channel::<()>();
    let handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = service_control_handler::register(SERVICE_NAME, handler)?;
    let none = ServiceControlAccept::empty();
    let ok = ServiceExitCode::Win32(0);

    handle.set_service_status(status(
        ServiceState::StartPending,
        none,
        ok,
        1,
        Duration::from_secs(15),
    ))?;

    let result = (|| -> Result<()> {
        let path = CONFIG_PATH.get().ok_or_else(|| anyhow!("no config path"))?;
        let (cfg, policy) = startup(path, true)?;
        let rt = tokio::runtime::Runtime::new()?;
        let status_handle = &handle;
        rt.block_on(async {
            // Bridge the SCM's blocking stop signal into async.
            let (stop_async_tx, stop_async_rx) = oneshot::channel::<()>();
            std::thread::spawn(move || {
                let _ = stop_rx.recv();
                let _ = stop_async_tx.send(());
            });
            run_core_with(
                cfg,
                policy,
                async {
                    let _ = stop_async_rx.await;
                },
                || {
                    let _ = status_handle.set_service_status(status(
                        ServiceState::Running,
                        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                        ServiceExitCode::Win32(0),
                        0,
                        Duration::default(),
                    ));
                },
                |n| {
                    let _ = status_handle.set_service_status(status(
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        ServiceExitCode::Win32(0),
                        n,
                        Duration::from_secs(30),
                    ));
                },
            )
            .await
        })
    })();

    let exit = match &result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(e) => {
            tracing::error!("service stopping on error: {e:#}");
            // 2 = refused to trust its data folder, 1 = anything else.
            if e.downcast_ref::<SecurityRefusal>().is_some() {
                ServiceExitCode::ServiceSpecific(2)
            } else {
                ServiceExitCode::ServiceSpecific(1)
            }
        }
    };
    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
        0,
        Duration::default(),
    ))?;
    result
}

// ── Startup checks ───────────────────────────────────────────────────────────

/// The data folder could not be trusted; distinct so the exit code says so.
#[derive(Debug)]
struct SecurityRefusal(String);

impl std::fmt::Display for SecurityRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SecurityRefusal {}

/// Everything the service needs before it may run, in the order that matters:
/// 1. verify the data folder (before reading or writing anything in it);
/// 2. only then start the file log inside it;
/// 3. load and cross-check the config and the policy.
///
/// With `enforce_acl` false (console debugging) a failed folder check is only
/// a warning.
fn startup(config: &Path, enforce_acl: bool) -> Result<(AppConfig, Policy)> {
    let dir = config
        .parent()
        .ok_or_else(|| anyhow!("the config path has no folder"))?;
    let policy_path = dir.join("policy.toml");

    if let Err(why) = winsec::check_data_dir(dir, &[config.to_path_buf(), policy_path.clone()]) {
        if enforce_acl {
            let msg = format!(
                "refusing to start: the data folder is not safe ({why}). Run, as \
                 Administrator: chameleon-pq.exe --config \"{}\" service harden",
                config.display()
            );
            // Not the file log: that would write into a folder we just decided
            // we cannot trust.
            winsec::report_error_event(&msg);
            return Err(SecurityRefusal(msg).into());
        }
        eprintln!(
            "WARNING: data folder check failed ({why}); continuing because this is console mode"
        );
    }

    if enforce_acl {
        init_file_logging(&dir.join("logs"))?;
    }
    let cfg = AppConfig::load(config)
        .with_context(|| format!("loading service config {}", config.display()))?;
    let policy = Policy::load(&policy_path)?;
    policy.validate(&cfg)?;
    tracing::info!("policy: {policy:?}");
    Ok((cfg, policy))
}

// ── Shared core (service and console) ────────────────────────────────────────

async fn run_core(
    cfg: AppConfig,
    policy: Policy,
    stop: impl std::future::Future<Output = ()>,
) -> Result<()> {
    run_core_with(cfg, policy, stop, || {}, |_| {}).await
}

/// Start the controller and the pipe; wait for `stop`; tear down in order.
/// `on_running` fires once the pipe is listening; `on_stopping(n)` fires with an
/// increasing checkpoint while teardown is in progress.
async fn run_core_with(
    cfg: AppConfig,
    policy: Policy,
    stop: impl std::future::Future<Output = ()>,
    on_running: impl FnOnce(),
    mut on_stopping: impl FnMut(u32),
) -> Result<()> {
    let (handle, controller_task): (ControllerHandle, _) =
        controller::spawn_with_policy(cfg, policy, Supervisor::new(), controller::real_connect());
    let server = Server::new(handle.clone());
    let (pipe_stop_tx, pipe_stop_rx) = oneshot::channel();
    let mut pipe_task = tokio::spawn(pipe_windows::serve(
        pipe_windows::PIPE_NAME,
        server,
        pipe_stop_rx,
    ));
    tracing::info!("control pipe {} listening", pipe_windows::PIPE_NAME);
    on_running();

    // Run until asked to stop, or until the pipe dies (then there is no way to
    // control the service, so stop rather than run headless).
    let pipe_result = tokio::select! {
        _ = stop => None,
        res = &mut pipe_task => Some(res),
    };

    tracing::info!("stopping");
    let mut checkpoint = 1;
    on_stopping(checkpoint);
    let _ = pipe_stop_tx.send(());
    let mut shutdown = Box::pin(handle.shutdown());
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tick.tick() => {
                checkpoint += 1;
                on_stopping(checkpoint);
            }
        }
    }
    let _ = controller_task.await;

    match pipe_result {
        Some(Ok(Err(e))) => Err(anyhow!("control pipe failed: {e}")),
        Some(Err(e)) => Err(anyhow!("control pipe task panicked: {e}")),
        _ => Ok(()),
    }
}

// ── Is the service installed? (frontend side) ───────────────────────────────

/// What a frontend learns from the Service Control Manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Installed {
    No,
    Yes {
        running: bool,
    },
    /// Could not ask (message for the log). Treated as "not managed".
    Unknown(String),
}

/// Whether the service exists and is running. Needs only read access, which
/// standard users have by default. A frontend decides its mode from this (not
/// from whether the pipe happens to answer), so a service restart never flips a
/// session from managed to standalone.
pub fn installed() -> Installed {
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    {
        Ok(m) => m,
        Err(e) => return Installed::Unknown(e.to_string()),
    };
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(svc) => match svc.query_status() {
            Ok(st) => Installed::Yes {
                running: st.current_state == ServiceState::Running,
            },
            Err(_) => Installed::Yes { running: false },
        },
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => {
            Installed::No // ERROR_SERVICE_DOES_NOT_EXIST
        }
        Err(e) => Installed::Unknown(e.to_string()),
    }
}

// ── Install / uninstall ──────────────────────────────────────────────────────

fn strip_verbatim(p: PathBuf) -> PathBuf {
    match p.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(rest) => PathBuf::from(rest),
        None => p,
    }
}

/// The binary runs as SYSTEM, so it must not live where a normal user can
/// replace it. Under Program Files only administrators can write.
fn under_program_files(p: &Path) -> bool {
    let lower = p.to_string_lossy().to_lowercase();
    ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .map(|d| format!("{}\\", d.trim_end_matches('\\').to_lowercase()))
        .any(|d| lower.starts_with(&d))
}

fn install(config: &Path, allow_insecure_path: bool) -> Result<()> {
    let exe = strip_verbatim(std::env::current_exe()?.canonicalize()?);
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("executable has no directory"))?;
    if !under_program_files(&exe) {
        if allow_insecure_path {
            eprintln!(
                "WARNING: {} is not under Program Files; a user who can write there can \
                 replace a binary that runs as SYSTEM.",
                exe.display()
            );
        } else {
            bail!(
                "refusing to install: {} is not under Program Files, so a normal user may be \
                 able to replace a binary that runs as SYSTEM. Install the program into \
                 Program Files (or pass --allow-insecure-path for development).",
                exe.display()
            );
        }
    }
    if !dir.join("wintun.dll").is_file() {
        bail!(
            "wintun.dll not found next to {}; the service could not create the adapter",
            exe.display()
        );
    }
    let config = strip_verbatim(
        config
            .canonicalize()
            .with_context(|| format!("config {} not found", config.display()))?,
    );
    let data_dir = config
        .parent()
        .ok_or_else(|| anyhow!("the config path has no folder"))?
        .to_path_buf();
    // Lock the data folder down BEFORE the service can ever read it: it holds
    // the private key and is read by a SYSTEM process.
    winsec::harden_data_dir(&data_dir).map_err(|e| anyhow!(e))?;
    println!(
        "Folder {} is now readable by SYSTEM and Administrators only.",
        data_dir.display()
    );
    // Fail now rather than at first start.
    let cfg = AppConfig::load(&config).context("the service config is not valid")?;
    let policy = Policy::load(&data_dir.join("policy.toml"))?;
    policy.validate(&cfg)?;

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        // windows-service quotes the path and each argument, so a path with
        // spaces ("Program Files") is not an unquoted-service-path hole.
        executable_path: exe.clone(),
        launch_arguments: vec![
            OsString::from("--config"),
            config.clone().into_os_string(),
            OsString::from("service"),
            OsString::from("run"),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_CONFIG,
        )
        .context("could not create the service (is it already installed? run as Administrator)")?;
    service.set_description(DESCRIPTION)?;
    apply_recovery(&service)?;
    println!(
        "Service {SERVICE_NAME} installed ({}), config {}.\nStart it with: sc start {SERVICE_NAME}\nVerify the quoting with: sc qc {SERVICE_NAME}",
        exe.display(),
        config.display()
    );
    Ok(())
}

/// Restart the service after a crash (5 s, then 30 s), then leave it stopped.
/// Only real crashes count: a deliberate exit with an error code (for example
/// the folder check refusing to start) must not turn into a restart loop.
/// The tunnel itself does not come back on its own (there is no auto-connect);
/// the service and its pipe do, so a user can reconnect without an administrator.
fn apply_recovery(service: &windows_service::service::Service) -> Result<()> {
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ScmAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ScmAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
            ScmAction {
                action_type: ServiceActionType::None,
                delay: Duration::from_secs(0),
            },
        ]),
    })?;
    service.set_failure_actions_on_non_crash_failures(false)?;
    Ok(())
}

/// `service harden`: re-apply the folder permissions and the recovery settings
/// to an already installed service. Idempotent.
fn harden(config: &Path) -> Result<()> {
    let config = strip_verbatim(
        config
            .canonicalize()
            .with_context(|| format!("config {} not found", config.display()))?,
    );
    let dir = config
        .parent()
        .ok_or_else(|| anyhow!("the config path has no folder"))?;
    winsec::harden_data_dir(dir).map_err(|e| anyhow!(e))?;
    println!(
        "Folder {} is now readable by SYSTEM and Administrators only.",
        dir.display()
    );
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG)
        .context("service not installed (or not running as Administrator)")?;
    apply_recovery(&service)?;
    println!("Crash recovery set: restart after 5 s, then after 30 s.");
    Ok(())
}

fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("service not installed (or not running as Administrator)")?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        // Teardown can take a while (routes, DNS, firewall); wait for it.
        for _ in 0..60 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    service.delete()?;
    println!("Service {SERVICE_NAME} removed.");
    Ok(())
}

// ── Logging ──────────────────────────────────────────────────────────────────

fn level(verbose: u8) -> &'static str {
    match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    }
}

fn init_console_logging(verbose: u8) {
    use tracing_subscriber::{fmt, EnvFilter};
    let _ = fmt()
        .with_env_filter(EnvFilter::new(level(verbose)))
        .try_init();
}

/// stderr goes nowhere under the SCM, so log to a file in the (already
/// verified) data folder. The `logs` folder must be a real directory, not a
/// junction someone planted to redirect a SYSTEM write.
fn init_file_logging(logs: &Path) -> Result<()> {
    use tracing_subscriber::{fmt, EnvFilter};
    if logs.exists() {
        if winsec::is_reparse_point(logs)? {
            bail!("{} is a junction or symlink", logs.display());
        }
    } else {
        std::fs::create_dir(logs)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(logs.join("service.log"))?;
    let _ = fmt()
        .with_env_filter(EnvFilter::new("info"))
        .with_ansi(false)
        .with_writer(std::sync::Mutex::new(file))
        .try_init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbatim_prefix_is_stripped() {
        assert_eq!(
            strip_verbatim(PathBuf::from(r"\\?\C:\Program Files\x\a.exe")),
            PathBuf::from(r"C:\Program Files\x\a.exe")
        );
        assert_eq!(
            strip_verbatim(PathBuf::from(r"C:\a.exe")),
            PathBuf::from(r"C:\a.exe")
        );
    }

    #[test]
    fn program_files_check_is_prefix_on_a_directory_boundary() {
        std::env::set_var("ProgramFiles", r"C:\Program Files");
        assert!(under_program_files(Path::new(
            r"C:\Program Files\Chameleon-PQ\chameleon-pq.exe"
        )));
        assert!(under_program_files(Path::new(
            r"c:\program files\chameleon-pq\chameleon-pq.exe"
        )));
        assert!(!under_program_files(Path::new(
            r"C:\Program Files Evil\chameleon-pq.exe"
        )));
        assert!(!under_program_files(Path::new(
            r"C:\Users\x\Downloads\chameleon-pq.exe"
        )));
    }
}
