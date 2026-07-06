//! Gebatchte UDP-I/O via `quinn-udp` (GSO op verzenden, GRO op ontvangen), met
//! graceful per-pakket fallback op oude kernels / niet-Linux.
//!
//! ACHTERGROND: een microbenchmark liet zien dat `send_to` (één syscall per
//! pakket) een harde muur is (~0,18 Mpps op de devbox), *onder* de crypto. Door
//! meerdere datagrammen in één syscall te versturen (Linux UDP-GSO geeft de
//! kernel één grote buffer die hij in segmenten splitst) en te ontvangen (GRO
//! coalesceert meerdere datagrammen) verdwijnt die muur — precies wat
//! wireguard-go zijn Gbit/s-sprong gaf.
//!
//! GEEN wireformat-wijziging: GSO plakt alleen reeds-verzegelde datagrammen aan
//! elkaar, GRO splitst ontvangen bytes weer in dezelfde datagrammen. De crypto
//! zit boven deze laag. `quinn-udp` detecteert GSO/GRO en valt vanzelf terug op
//! per-pakket waar het niet ondersteund wordt.
//!
//! Deze module is de ENIGE plek die de dependency aanraakt; de rest praat met
//! onze kleine API (`batch_send` / `batch_recv` / `iter_datagrams` /
//! `group_equal_sized`).

use bytes::Bytes;
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Aantal berichten dat we per ontvangst-batch aanvragen.
pub const RECV_BATCH: usize = 8;
/// Grootte van elke ontvangst-buffer. Groot genoeg voor een flinke GRO-coalesced
/// reeks MTU-datagrammen; te klein duwt GRO alleen naar minder coalescing (nooit
/// dataverlies — quinn-udp legt geen half datagram in een buffer).
pub const RECV_BUF: usize = 64 * 1024;

/// Bouw de per-socket GSO/GRO-state (zet de sockopts). Faalt zelden; bij een
/// niet-ondersteunde kernel rapporteert `max_gso_segments()` gewoon 1.
pub fn socket_state(socket: &UdpSocket) -> io::Result<UdpSocketState> {
    UdpSocketState::new(UdpSockRef::from(socket))
}

/// Maak de ontvangst-buffers + metadata voor `batch_recv` (houdt `quinn_udp`
/// buiten de aanroeper).
pub fn recv_buffers() -> (Vec<Vec<u8>>, Vec<RecvMeta>) {
    (
        vec![vec![0u8; RECV_BUF]; RECV_BATCH],
        vec![RecvMeta::default(); RECV_BATCH],
    )
}

/// Verstuur een reeks GELIJK-GROTE datagrammen naar één peer in zo min mogelijk
/// syscalls. Onder GSO gaan tot `max_gso_segments()` segmenten in één `sendmsg`;
/// anders valt quinn-udp terug op per-pakket. `seg_size` is de grootte van elk
/// datagram (bij GSO moet elk segment behalve eventueel het laatste die grootte
/// hebben — gegarandeerd omdat de aanroeper gelijk-grote runs doorgeeft).
pub async fn batch_send(
    socket: &UdpSocket,
    state: &UdpSocketState,
    peer: SocketAddr,
    datagrams: &[Bytes],
    seg_size: usize,
) -> io::Result<()> {
    if datagrams.is_empty() {
        return Ok(());
    }
    // Windows: NIET via quinn-udp's GSO. Het WSASendMsg/`UDP_SEND_MSG_SIZE`-pad
    // crasht native (access violation) op sommige Windows-adapters — reproduceer-
    // baar zelfs over loopback — en zo'n hardware-exception ontsnapt aan de Rust-
    // panic-hook (proces + venster weg, géén paniek-log). Verstuur daarom elk
    // datagram met één `send_to`. Geen GSO-batchingwinst, maar stabiel; die winst
    // was sowieso Linux-specifiek (kernel-UDP-GSO). Zie ook `batch_recv`.
    if cfg!(windows) {
        for d in datagrams {
            socket.send_to(d.as_ref(), peer).await?;
        }
        return Ok(());
    }
    let max_seg = state.max_gso_segments().max(1);
    let mut buf: Vec<u8> = Vec::with_capacity(seg_size * datagrams.len().min(max_seg));
    let mut i = 0;
    while i < datagrams.len() {
        let end = (i + max_seg).min(datagrams.len());
        buf.clear();
        for d in &datagrams[i..end] {
            buf.extend_from_slice(d);
        }
        // segment_size None bij één datagram (geen GSO nodig), anders seg_size.
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

/// Ontvang een batch datagrammen (GRO-coalesced waar mogelijk). Vult `storage`
/// (RECV_BATCH buffers) en `metas`, en geeft het aantal berichten terug. Gebruik
/// daarna `iter_datagrams(storage, metas, count)` om de losse datagrammen te
/// doorlopen.
pub async fn batch_recv(
    socket: &UdpSocket,
    state: &UdpSocketState,
    storage: &mut [Vec<u8>],
    metas: &mut [RecvMeta],
) -> io::Result<usize> {
    // Windows: geen quinn-udp GRO (zelfde native-crash-reden als de send-kant in
    // `batch_send`). Ontvang één datagram met `recv_from` in de eerste buffer;
    // `stride = 0` laat `iter_datagrams` het als één heel datagram teruggeven.
    if cfg!(windows) {
        let (n, addr) = socket.recv_from(&mut storage[0]).await?;
        metas[0] = RecvMeta {
            addr,
            len: n,
            stride: 0,
            ecn: None,
            dst_ip: None,
        };
        return Ok(1);
    }
    let mut iov: Vec<IoSliceMut> = storage
        .iter_mut()
        .map(|b| IoSliceMut::new(b.as_mut_slice()))
        .collect();
    // `iov` (en dus de &mut op storage) leeft alleen tot het eind van deze fn;
    // daarna leest de aanroeper storage veilig via `iter_datagrams`.
    socket
        .async_io(Interest::READABLE, || {
            state.recv(UdpSockRef::from(socket), &mut iov, metas)
        })
        .await
}

/// Doorloop de individuele datagrammen uit een ontvangen batch. Elk bericht kan
/// (met GRO) meerdere datagrammen bevatten, op `stride`-grenzen; het laatste mag
/// korter zijn.
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
            // stride 0 (geen GRO) => het hele bericht is één datagram.
            let stride = if m.stride == 0 { len } else { m.stride }.max(1);
            let addr = m.addr;
            buf[..len].chunks(stride).map(move |dg| (addr, dg))
        })
}

/// Splits een batch datagrammen in maximale runs van GELIJKE grootte. Onder
/// `PadPolicy::Full` is alles even groot → één run → één GSO-call. Onder
/// Bucketed/Off variëren de groottes → kleinere runs (of runs van 1 = per-pakket).
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
        RecvMeta {
            addr,
            len,
            stride,
            ecn: None,
            dst_ip: None,
        }
    }

    #[test]
    fn iter_splits_gro_coalesced_buffer() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        // Eén bericht met 3 datagrammen van stride 4, laatste korter (2).
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
        metas[0] = meta(addr, 5, 0); // stride 0 => één datagram van 5
        metas[1] = meta(addr, 3, 0);
        let got: Vec<Vec<u8>> = iter_datagrams(&storage, &metas, 2)
            .map(|(_, d)| d.to_vec())
            .collect();
        assert_eq!(got, vec![vec![9, 9, 9, 9, 9], vec![7, 7, 7]]);
    }
}
