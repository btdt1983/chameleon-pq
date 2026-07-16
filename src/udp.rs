//! Batched UDP I/O via `quinn-udp` (GSO on send, GRO on receive), with
//! graceful per-packet fallback on old kernels / non-Linux.
//!
//! BACKGROUND: a microbenchmark showed that `send_to` (one syscall per
//! packet) is a hard wall (~0.18 Mpps on the devbox), *below* the crypto. By
//! sending multiple datagrams in one syscall (Linux UDP-GSO hands the kernel
//! one large buffer that it splits into segments) and receiving (GRO
//! coalesces multiple datagrams) that wall disappears — exactly what gave
//! wireguard-go its Gbit/s jump.
//!
//! NO wireformat change: GSO only glues already-sealed datagrams together,
//! GRO splits received bytes back into the same datagrams. The crypto sits
//! above this layer. `quinn-udp` detects GSO/GRO and automatically falls back
//! to per-packet where it is not supported.
//!
//! This module is the ONLY place that touches the dependency; the rest talks
//! to our small API (`batch_send` / `batch_recv` / `iter_datagrams` /
//! `group_equal_sized`).

use bytes::Bytes;
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Number of messages we request per receive batch. Larger = each recv-syscall
/// pulls more datagrams out of the kernel recv buffer, which helps keep the
/// buffer drained under bursty download (fewer overflow drops).
pub const RECV_BATCH: usize = 32;
/// Size of each receive buffer. Large enough for a sizeable GRO-coalesced run
/// of MTU datagrams; too small only pushes GRO toward less coalescing (never
/// data loss — quinn-udp never puts half a datagram in a buffer).
pub const RECV_BUF: usize = 64 * 1024;

/// Build the per-socket GSO/GRO state (sets the sockopts). Rarely fails; on an
/// unsupported kernel `max_gso_segments()` simply reports 1.
pub fn socket_state(socket: &UdpSocket) -> io::Result<UdpSocketState> {
    UdpSocketState::new(UdpSockRef::from(socket))
}

/// Requested kernel socket buffer (SO_RCVBUF/SO_SNDBUF). The OS default is too
/// small for bursty high throughput: on Windows ~64 KB, full in ~2 ms at 220
/// Mbit. One short stall in the (slow) client receive path → recv buffer
/// overflows → kernel drops datagrams → TCP retransmits → the download
/// collapses (measured: 8123 retransmits, 47 Mbit). A large buffer absorbs the
/// bursts so TCP settles on the real throughput instead of collapsing.
const SOCKET_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// Enlarge SO_RCVBUF/SO_SNDBUF on the UDP socket. Best-effort; logs what we got.
///
/// Plain SO_RCVBUF is silently clamped by the kernel to `net.core.rmem_max`
/// (208 KiB on stock Debian) — so on an untuned server the buffer overflows on
/// bursts, the kernel drops datagrams, and TCP throttles (upload especially:
/// ~0.1% loss caps a flow at a few Mbit via the Mathis bound). On Linux we
/// therefore prefer `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE`, which bypass that cap for
/// a privileged process — and the server always runs as root for the TUN, so it
/// gets the full buffer with zero sysctl tuning. Falls back to the plain sockopt
/// when unprivileged or non-Linux, and warns loudly if the OS still clamped us.
pub fn enlarge_socket_buffers(socket: &UdpSocket) {
    let sref = socket2::SockRef::from(socket);

    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        // Try the un-clamped FORCE variant first; fall back to the plain sockopt
        // (which socket2 sets) if we lack CAP_NET_ADMIN.
        if !set_buffer_force(fd, libc::SO_RCVBUFFORCE, SOCKET_BUFFER_BYTES) {
            let _ = sref.set_recv_buffer_size(SOCKET_BUFFER_BYTES);
        }
        if !set_buffer_force(fd, libc::SO_SNDBUFFORCE, SOCKET_BUFFER_BYTES) {
            let _ = sref.set_send_buffer_size(SOCKET_BUFFER_BYTES);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if let Err(e) = sref.set_recv_buffer_size(SOCKET_BUFFER_BYTES) {
            tracing::debug!("set_recv_buffer_size failed: {e}");
        }
        if let Err(e) = sref.set_send_buffer_size(SOCKET_BUFFER_BYTES) {
            tracing::debug!("set_send_buffer_size failed: {e}");
        }
    }

    match (sref.recv_buffer_size(), sref.send_buffer_size()) {
        (Ok(r), Ok(s)) => {
            tracing::info!(
                "UDP socket buffers: recv {} KiB, send {} KiB",
                r / 1024,
                s / 1024
            );
            // The kernel reports ~2× the set value; if we are still far under the
            // request the OS clamped us — say so, with the fix.
            if r < SOCKET_BUFFER_BYTES / 2 {
                tracing::warn!(
                    "UDP recv buffer is only {} KiB (wanted {} KiB) — the OS clamped it. \
                     Raise net.core.rmem_max (and run as root so SO_RCVBUFFORCE applies); \
                     otherwise bursty traffic drops and throughput — upload especially — \
                     suffers.",
                    r / 1024,
                    SOCKET_BUFFER_BYTES / 1024
                );
            }
        }
        _ => tracing::debug!("could not read back socket buffer sizes"),
    }
}

/// Linux-only: set `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE` (bypasses `net.core.*mem_max`
/// for a process with CAP_NET_ADMIN). Returns whether it succeeded.
#[cfg(target_os = "linux")]
fn set_buffer_force(fd: std::os::fd::RawFd, optname: libc::c_int, bytes: usize) -> bool {
    let val = bytes as libc::c_int;
    // SAFETY: a standard setsockopt with an `int` optval of the matching length.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            optname,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) == 0
    }
}

/// Create the receive buffers + metadata for `batch_recv` (keeps `quinn_udp`
/// out of the caller).
pub fn recv_buffers() -> (Vec<Vec<u8>>, Vec<RecvMeta>) {
    (
        vec![vec![0u8; RECV_BUF]; RECV_BATCH],
        vec![RecvMeta::default(); RECV_BATCH],
    )
}

/// Send a run of EQUAL-SIZED datagrams to one peer in as few syscalls as
/// possible. Under GSO up to `max_gso_segments()` segments go in one `sendmsg`;
/// otherwise quinn-udp falls back to per-packet. `seg_size` is the size of each
/// datagram (under GSO every segment except possibly the last must have that
/// size — guaranteed because the caller passes equal-sized runs).
pub async fn batch_send(
    socket: &UdpSocket,
    state: &UdpSocketState,
    peer: SocketAddr,
    datagrams: &[Bytes],
    seg_size: usize,
    gso: bool,
) -> io::Result<()> {
    if datagrams.is_empty() {
        return Ok(());
    }
    // GSO bundles several already-sealed datagrams into one segmented `sendmsg`.
    // It's OFF by default (see EngineConfig::gso): on some paths (a Hyper-V vSwitch
    // / NIC offload that doesn't pass Linux UDP-GSO) the segmented super-buffer is
    // dropped wholesale — a download measured collapsing 300→47 Mbit with 8000
    // retransmits. With `gso = false` we send one datagram per syscall, which is
    // correct everywhere; quinn-udp also falls back to per-datagram when the
    // platform reports max_gso_segments() == 1.
    let max_seg = if gso {
        state.max_gso_segments().max(1)
    } else {
        1
    };
    let mut buf: Vec<u8> = Vec::with_capacity(seg_size * datagrams.len().min(max_seg));
    let mut i = 0;
    while i < datagrams.len() {
        let end = (i + max_seg).min(datagrams.len());
        buf.clear();
        for d in &datagrams[i..end] {
            buf.extend_from_slice(d);
        }
        // segment_size None for a single datagram (no GSO needed), else seg_size.
        let segment_size = if end - i > 1 { Some(seg_size) } else { None };
        let transmit = Transmit {
            destination: peer,
            ecn: None,
            contents: &buf,
            segment_size,
            src_ip: None,
        };
        socket
            .async_io(Interest::WRITABLE, || {
                state.send(UdpSockRef::from(socket), &transmit)
            })
            .await?;
        i = end;
    }
    Ok(())
}

/// Receive a batch of datagrams (GRO-coalesced where possible). Fills `storage`
/// (RECV_BATCH buffers) and `metas`, and returns the number of messages. Then
/// use `iter_datagrams(storage, metas, count)` to walk the individual
/// datagrams.
pub async fn batch_recv(
    socket: &UdpSocket,
    state: &UdpSocketState,
    storage: &mut [Vec<u8>],
    metas: &mut [RecvMeta],
) -> io::Result<usize> {
    // EXPERIMENT (quinn-udp 0.6): re-enable GRO on Windows. The 0.5 native crash
    // was in GSO *send* (WSASendMsg); Tailscale proves batched I/O works on
    // Windows, so this is worth testing on the newer quinn-udp. Falls back to a
    // single-datagram recv only if the platform lacks GRO.
    let mut iov: Vec<IoSliceMut> = storage
        .iter_mut()
        .map(|b| IoSliceMut::new(b.as_mut_slice()))
        .collect();
    // `iov` (and thus the &mut on storage) lives only until the end of this fn;
    // afterwards the caller safely reads storage via `iter_datagrams`.
    socket
        .async_io(Interest::READABLE, || {
            state.recv(UdpSockRef::from(socket), &mut iov, metas)
        })
        .await
}

/// Walk the individual datagrams from a received batch. Each message can (with
/// GRO) contain multiple datagrams, on `stride` boundaries; the last one may be
/// shorter.
pub fn iter_datagrams<'a>(
    storage: &'a [Vec<u8>],
    metas: &'a [RecvMeta],
    count: usize,
) -> impl Iterator<Item = (SocketAddr, &'a [u8])> {
    metas[..count.min(metas.len())]
        .iter()
        .zip(storage.iter())
        .flat_map(|(m, buf)| {
            let len = m.len.min(buf.len());
            // stride 0 (no GRO) => the whole message is one datagram.
            let stride = if m.stride == 0 { len } else { m.stride }.max(1);
            let addr = m.addr;
            buf[..len].chunks(stride).map(move |dg| (addr, dg))
        })
}

/// Split a batch of datagrams into maximal runs of EQUAL size. Under
/// `PadPolicy::Full` everything is the same size → one run → one GSO call.
/// Under Bucketed/Off the sizes vary → smaller runs (or runs of 1 = per-packet).
pub fn group_equal_sized(datagrams: &[Bytes]) -> Vec<(&[Bytes], usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < datagrams.len() {
        let size = datagrams[i].len();
        let mut j = i + 1;
        while j < datagrams.len() && datagrams[j].len() == size {
            j += 1;
        }
        out.push((&datagrams[i..j], size));
        i = j;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(n: usize, fill: u8) -> Bytes {
        Bytes::from(vec![fill; n])
    }

    #[test]
    fn group_all_equal_is_one_run() {
        let d = [b(1280, 1), b(1280, 2), b(1280, 3)];
        let runs = group_equal_sized(&d);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].0.len(), 3);
        assert_eq!(runs[0].1, 1280);
    }

    #[test]
    fn group_mixed_splits_into_runs() {
        let d = [b(100, 1), b(100, 2), b(64, 3), b(200, 4)];
        let runs = group_equal_sized(&d);
        // (100,100) | (64) | (200)
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[0].0.len(), 2);
        assert_eq!(runs[0].1, 100);
        assert_eq!(runs[1].1, 64);
        assert_eq!(runs[2].1, 200);
    }

    #[test]
    fn group_empty() {
        assert!(group_equal_sized(&[]).is_empty());
    }

    fn meta(addr: SocketAddr, len: usize, stride: usize) -> RecvMeta {
        // RecvMeta is #[non_exhaustive] in quinn-udp 0.6 → build via default.
        let mut m = RecvMeta::default();
        m.addr = addr;
        m.len = len;
        m.stride = stride;
        m
    }

    #[test]
    fn iter_splits_gro_coalesced_buffer() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        // One message with 3 datagrams of stride 4, last one shorter (2).
        let mut storage = vec![vec![0u8; RECV_BUF]; RECV_BATCH];
        storage[0][..10].copy_from_slice(&[1, 1, 1, 1, 2, 2, 2, 2, 3, 3]);
        let mut metas = [meta(addr, 0, 0); RECV_BATCH];
        metas[0] = meta(addr, 10, 4); // len 10, stride 4 -> [4,4,2]
        let got: Vec<&[u8]> = iter_datagrams(&storage, &metas, 1)
            .map(|(_, d)| d)
            .collect();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], &[1, 1, 1, 1]);
        assert_eq!(got[1], &[2, 2, 2, 2]);
        assert_eq!(got[2], &[3, 3]);
    }

    #[test]
    fn iter_no_gro_is_one_datagram_per_message() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut storage = vec![vec![0u8; RECV_BUF]; RECV_BATCH];
        storage[0][..5].copy_from_slice(&[9, 9, 9, 9, 9]);
        storage[1][..3].copy_from_slice(&[7, 7, 7]);
        let mut metas = [meta(addr, 0, 0); RECV_BATCH];
        metas[0] = meta(addr, 5, 0); // stride 0 => one datagram of 5
        metas[1] = meta(addr, 3, 0);
        let got: Vec<Vec<u8>> = iter_datagrams(&storage, &metas, 2)
            .map(|(_, d)| d.to_vec())
            .collect();
        assert_eq!(got, vec![vec![9, 9, 9, 9, 9], vec![7, 7, 7]]);
    }
}
