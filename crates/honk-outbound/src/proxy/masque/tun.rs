//! TUN device plumbing for the MASQUE IP tunnel.
//!
//! The endpoint gives us IP packets; the kernel already knows how to turn
//! those into TCP and UDP far better than any userspace stack. So instead of
//! reimplementing TCP we hand the tunnel to the kernel as a network interface:
//!
//! ```text
//! app socket --(SO_BINDTODEVICE + source address)--> TUN --> tunnel task --> endpoint
//! ```
//!
//! Linux lets a socket be pinned to an interface with `SO_BINDTODEVICE`, and
//! binding the source address to the one the endpoint assigned makes the
//! kernel route that socket's packets out through the TUN device. Everything
//! above IP — handshake, congestion control, retransmits — stays in the kernel.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use tokio::io::unix::AsyncFd;

const TUN_PATH: &str = "/dev/net/tun";

/// A TUN device carrying IP packets (no packet information header).
pub struct TunDevice {
    inner: AsyncFd<File>,
    name: String,
}

impl TunDevice {
    /// Create a TUN device. `name` may contain `%d`, which the kernel replaces
    /// with the next free index; the resolved name is returned by
    /// [`TunDevice::name`].
    pub fn create(name: &str) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(TUN_PATH)?;

        let mut request: libc::ifreq = unsafe { mem::zeroed() };
        for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *slot = byte as libc::c_char;
        }
        if name.len() >= request.ifr_name.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("TUN name {name:?} exceeds IFNAMSIZ"),
            ));
        }
        request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &request) } != 0 {
            return Err(io::Error::last_os_error());
        }

        // Read the name back: the kernel may have expanded a `%d` template.
        let resolved = request
            .ifr_name
            .iter()
            .take_while(|&&byte| byte != 0)
            .map(|&byte| byte as u8 as char)
            .collect::<String>();

        Ok(Self {
            inner: AsyncFd::new(file)?,
            name: resolved,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Assign an address, set the MTU and bring the interface up.
    pub fn configure(&self, address: IpAddr, prefix_len: u8, mtu: u32) -> io::Result<()> {
        let address = format!("{address}/{prefix_len}");
        let mtu = mtu.to_string();
        for args in [
            vec!["addr", "add", &address, "dev", &self.name],
            vec!["link", "set", "dev", &self.name, "mtu", &mtu],
            vec!["link", "set", "dev", &self.name, "up"],
        ] {
            ip(&args)?;
        }
        Ok(())
    }

    /// Read one IP packet. Resolves when the device becomes readable.
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read(buffer)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IP packet.
    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().write(packet)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        // A TUN device disappears with the owning fd, but dropping the link
        // explicitly keeps `ip link` output clean while nodes churn.
        let _ = ip(&["link", "del", &self.name]);
    }
}

/// Run `ip` and turn a failure into an io::Error carrying its stderr.
fn ip(args: &[&str]) -> io::Result<()> {
    let output = Command::new("ip").args(args).output().map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot run `ip {}` : {error}", args.join(" ")),
        )
    })?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "ip {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}
