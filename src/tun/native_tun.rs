//! NativeTun: virtio_net_hdr strip/prepend + optional GSO split on read.

use super::gso::{self, VirtioNetHdr, VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_HDR_LEN};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::warn;

pub struct NativeTun {
    reader: Arc<Mutex<NativeTunReader>>,
    writer: Arc<Mutex<NativeTunWriter>>,
}

impl NativeTun {
    pub fn new(
        dev: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        vnet_hdr: bool,
    ) -> Self {
        let (r, w) = tokio::io::split(dev);
        Self {
            reader: Arc::new(Mutex::new(NativeTunReader {
                inner: Box::pin(r),
                vnet_hdr,
                pending: VecDeque::new(),
                read_buf: vec![0u8; gso::GSO_MAX_SIZE + VIRTIO_NET_HDR_LEN],
            })),
            writer: Arc::new(Mutex::new(NativeTunWriter {
                inner: Box::pin(w),
                vnet_hdr,
            })),
        }
    }

    pub fn split(self) -> (Arc<Mutex<NativeTunReader>>, Arc<Mutex<NativeTunWriter>>) {
        (self.reader, self.writer)
    }
}

pub struct NativeTunReader {
    inner: Pin<Box<dyn AsyncRead + Unpin + Send>>,
    vnet_hdr: bool,
    pending: VecDeque<Vec<u8>>,
    read_buf: Vec<u8>,
}

impl NativeTunReader {
    /// Read one pure IP packet (no virtio_net_hdr).
    pub async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        if let Some(pkt) = self.pending.pop_front() {
            return Ok(pkt);
        }
        loop {
            let n = self.inner.read(&mut self.read_buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tun device closed",
                ));
            }
            if !self.vnet_hdr {
                return Ok(self.read_buf[..n].to_vec());
            }
            if n < VIRTIO_NET_HDR_LEN {
                warn!("tun: short read with vnet_hdr ({n} bytes), drop");
                continue;
            }
            let hdr = match VirtioNetHdr::decode(&self.read_buf[..VIRTIO_NET_HDR_LEN]) {
                Ok(h) => h,
                Err(e) => {
                    warn!(err = %e, "tun: bad virtio_net_hdr, drop");
                    continue;
                }
            };
            let payload = &self.read_buf[VIRTIO_NET_HDR_LEN..n];
            if hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE || payload.is_empty() {
                return Ok(payload.to_vec());
            }
            let mut options = match hdr.to_gso_options() {
                Ok(o) => o,
                Err(e) => {
                    warn!(err = %e, "tun: unsupported gso, pass through");
                    return Ok(payload.to_vec());
                }
            };
            if let Err(e) = gso::correct_gso_hdr_len(&mut options, payload) {
                warn!(err = %e, "tun: correct_gso_hdr_len failed, drop");
                continue;
            }
            let max_segs = (payload.len() / options.gso_size.max(1) as usize) + 2;
            let mut out_bufs: Vec<Vec<u8>> = vec![Vec::new(); max_segs];
            let mut sizes = vec![0usize; max_segs];
            match gso::gso_split(payload, &options, &mut out_bufs, &mut sizes) {
                Ok(count) => {
                    for i in 0..count {
                        let len = sizes[i];
                        let mut seg = std::mem::take(&mut out_bufs[i]);
                        if seg.len() > len {
                            seg.truncate(len);
                        }
                        self.pending.push_back(seg);
                    }
                    if let Some(pkt) = self.pending.pop_front() {
                        return Ok(pkt);
                    }
                }
                Err(e) => {
                    warn!(err = %e, "tun: gso_split failed, drop");
                }
            }
        }
    }
}

pub struct NativeTunWriter {
    inner: Pin<Box<dyn AsyncWrite + Unpin + Send>>,
    vnet_hdr: bool,
}

impl NativeTunWriter {
    /// Write one pure IP packet.
    pub async fn write_packet(&mut self, pkt: &[u8]) -> io::Result<()> {
        if !self.vnet_hdr {
            self.inner.write_all(pkt).await?;
            return Ok(());
        }
        let mut buf = Vec::with_capacity(VIRTIO_NET_HDR_LEN + pkt.len());
        buf.resize(VIRTIO_NET_HDR_LEN, 0); // GSO_NONE zero header
        buf.extend_from_slice(pkt);
        self.inner.write_all(&buf).await?;
        Ok(())
    }
}
