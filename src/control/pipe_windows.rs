//! Windows named-pipe transport for the control protocol.
//!
//! All the `unsafe` of the control plane is in this file, on purpose, so an
//! auditor can read it in one sitting: building a `SECURITY_ATTRIBUTES` from an
//! SDDL string and freeing it.
//!
//! Pipe security (design doc, section 7):
//! * the first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so if
//!   something else already owns the name, creation fails instead of us joining
//!   (or being impersonated by) a squatter;
//! * remote clients are rejected;
//! * every instance gets the same DACL: SYSTEM and Administrators full control,
//!   Authenticated Users read/write **without** `FILE_CREATE_PIPE_INSTANCE`.
//!   (The generic `GW` right includes `FILE_APPEND_DATA`, which is the same bit
//!   as `FILE_CREATE_PIPE_INSTANCE`: with it any user could create a rogue
//!   instance of the pipe.)

use super::server::Server;
use std::ffi::c_void;
use std::io;
use std::ptr;
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{LocalFree, FALSE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

pub const PIPE_NAME: &str = r"\\.\pipe\chameleon-pq-control";

/// SY = LocalSystem, BA = Administrators, AU = Authenticated Users.
/// 0x12019b = FILE_GENERIC_READ | FILE_GENERIC_WRITE minus FILE_CREATE_PIPE_INSTANCE (0x4).
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)";

/// A self-relative security descriptor allocated by the OS, freed on drop.
struct SecurityDescriptor {
    sd: PSECURITY_DESCRIPTOR,
}

// SAFETY: the descriptor is created once, never mutated afterwards, and only
// read (copied by the kernel) when a pipe instance is created.
#[allow(unsafe_code)]
unsafe impl Send for SecurityDescriptor {}
#[allow(unsafe_code)]
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    #[allow(unsafe_code)]
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `sd` is a valid
        // out-pointer; the size out-parameter is optional (null).
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { sd })
    }
}

impl Drop for SecurityDescriptor {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `sd` was allocated by ConvertStringSecurityDescriptor... and is
        // documented to be released with LocalFree, exactly once, here.
        unsafe {
            LocalFree(self.sd as _);
        }
    }
}

#[allow(unsafe_code)]
fn create_instance(
    name: &str,
    sd: &SecurityDescriptor,
    first: bool,
    max_instances: usize,
) -> io::Result<NamedPipeServer> {
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.sd,
        bInheritHandle: FALSE,
    };
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first)
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte)
        .max_instances(max_instances);
    // SAFETY: `attrs` is a fully initialised SECURITY_ATTRIBUTES whose descriptor
    // pointer stays valid for the duration of the call (`sd` is borrowed); the
    // kernel copies the descriptor, so nothing is retained afterwards.
    unsafe { opts.create_with_security_attributes_raw(name, &mut attrs as *mut _ as *mut c_void) }
}

/// Accept connections on the pipe `name` until `stop` fires (or its sender is
/// dropped). Fails immediately if the name is already taken.
pub async fn serve(name: &str, server: Server, mut stop: oneshot::Receiver<()>) -> io::Result<()> {
    let sd = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
    // Headroom over the connection cap: instances waiting to accept plus the
    // ones in use. Extra clients are refused by `Server::admit`, not the OS.
    let max = super::server::MAX_CONNECTIONS + 2;
    let mut pipe = create_instance(name, &sd, true, max)?;
    loop {
        tokio::select! {
            res = pipe.connect() => res?,
            _ = &mut stop => return Ok(()),
        }
        // Create the next instance BEFORE handing this one off, so there is
        // never a moment without a listening instance for the next client.
        let connected = pipe;
        pipe = create_instance(name, &sd, false, max)?;
        server.admit(connected);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::control::controller::{self, ConnectFn};
    use crate::control::protocol::{
        decode, read_frame, write_message, ClientMessage, Event, Hello, Phase, Request, Response,
        ServerMessage,
    };
    use crate::control::supervisor::Supervisor;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::net::windows::named_pipe::ClientOptions;

    fn unique_name() -> String {
        static N: AtomicU32 = AtomicU32::new(0);
        format!(
            r"\\.\pipe\chameleon-pq-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn start(name: &str) -> (oneshot::Sender<()>, tokio::task::JoinHandle<io::Result<()>>) {
        let cfg = AppConfig::load(std::path::Path::new("config.example.toml")).unwrap();
        let connect: ConnectFn =
            Arc::new(|_c, _s, _k| Box::pin(async { (Err("test".to_string()), None) }));
        let (handle, _) = controller::spawn(cfg, Supervisor::with_orphan(false), connect);
        let (stop_tx, stop_rx) = oneshot::channel();
        let name = name.to_string();
        let task = tokio::spawn(async move { serve(&name, Server::new(handle), stop_rx).await });
        (stop_tx, task)
    }

    #[test]
    fn the_sddl_is_valid() {
        SecurityDescriptor::from_sddl(PIPE_SDDL).expect("SDDL parses");
        assert!(SecurityDescriptor::from_sddl("not sddl").is_err());
    }

    #[tokio::test]
    async fn hello_and_get_state_over_a_real_pipe() {
        let name = unique_name();
        let (stop, task) = start(&name);
        // Give the server a moment to create its first instance.
        let mut client = loop {
            match ClientOptions::new().open(&name) {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        };
        write_message(&mut client, &ClientMessage::Hello(Hello::current()))
            .await
            .unwrap();
        let hello: ServerMessage = decode(&read_frame(&mut client).await.unwrap()).unwrap();
        assert_eq!(hello, ServerMessage::Hello(Hello::current()));
        let initial: ServerMessage = decode(&read_frame(&mut client).await.unwrap()).unwrap();
        assert!(matches!(initial, ServerMessage::Event(Event::State(_))));

        write_message(&mut client, &ClientMessage::Request(Request::GetState {}))
            .await
            .unwrap();
        let resp: ServerMessage = decode(&read_frame(&mut client).await.unwrap()).unwrap();
        match resp {
            ServerMessage::Response(Response::State(s)) => assert_eq!(s.phase, Phase::Disconnected),
            other => panic!("{other:?}"),
        }

        let _ = stop.send(());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_second_server_cannot_take_the_same_pipe_name() {
        let name = unique_name();
        let (stop, task) = start(&name);
        // Wait until the first instance exists.
        loop {
            if ClientOptions::new().open(&name).is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let sd = SecurityDescriptor::from_sddl(PIPE_SDDL).unwrap();
        assert!(
            create_instance(&name, &sd, true, 4).is_err(),
            "FILE_FLAG_FIRST_PIPE_INSTANCE must refuse an existing name"
        );
        let _ = stop.send(());
        let _ = task.await;
    }
}
