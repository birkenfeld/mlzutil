extern crate time as time_crate;
extern crate itertools;
extern crate hostname;
extern crate dns_lookup;
extern crate interfaces;

use std::thread;

/// Spawn a thread with a given name.
pub fn spawn<F: Send + 'static + FnOnce()>(name: &str, f: F) {
    let _ = thread::Builder::new().name(name.into()).spawn(f);
}

pub mod bytes {
    use itertools::Itertools;

    fn printable(ch: &u8) -> char {
        if *ch >= 32 && *ch <= 127 { *ch as char } else { '.' }
    }

    /// Print a hexdump of a byte slice in the usual format.
    pub fn hexdump(mut data: &[u8]) {
        let mut addr = 0;
        while !data.is_empty() {
            let (line, rest) = data.split_at(data.len().min(16));
            println!("{:#06x}: {:02x}{} | {}", addr,
                     line.iter().format(" "),
                     (0..16 - line.len()).map(|_| "   ").format(""),
                     line.iter().map(printable).format(""));
            addr += 16;
            data = rest;
        }
        println!();
    }
}

pub mod fs {
    use std::{io, fs};
    use std::path::{Path, PathBuf};

    /// Shortcut for canonicalizing a path, if possible.
    pub fn abspath(path: impl AsRef<Path>) -> PathBuf {
        path.as_ref().canonicalize().unwrap_or_else(|_| path.as_ref().into())
    }

    /// mkdir -p utility.
    pub fn ensure_dir(path: impl AsRef<Path>) -> io::Result<()> {
        if path.as_ref().is_dir() {
            return Ok(());
        }
        fs::DirBuilder::new().recursive(true).create(path)
    }

    /// Write a PID file.
    pub fn write_pidfile(pid_path: impl AsRef<Path>, basename: &str) -> io::Result<()> {
        ensure_dir(&pid_path)?;
        let file = pid_path.as_ref().join(&format!("{}.pid", basename));
        // TODO: use std::process::id when available
        let my_pid = fs::read_link("/proc/self")?;
        let my_pid = my_pid.to_str().unwrap();
        fs::write(file, my_pid.as_bytes())
    }

    /// Remove a PID file.
    pub fn remove_pidfile(pid_path: impl AsRef<Path>, basename: &str) {
        let file = Path::new(pid_path.as_ref()).join(&format!("{}.pid", basename));
        let _ = fs::remove_file(file);
    }
}

pub mod net {
    use hostname;
    use dns_lookup;
    use interfaces;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};

    /// Determine IPv4 addresses of all interfaces in the system.
    pub fn find_ipv4_addrs() -> HashMap<String, (Ipv4Addr, Ipv4Addr)> {
        interfaces::Interface::get_all().unwrap().into_iter().filter_map(|iface| {
            ipv4_addr(&iface.addresses).map(|addr| (iface.name.clone(), addr))
        }).collect()
    }

    /// Get best-effort fully-qualified hostname.
    pub fn getfqdn() -> String {
        let hostname = hostname::get_hostname().unwrap_or_else(|| "localhost".into());
        let mut candidates = Vec::new();
        for addr in dns_lookup::lookup_host(&hostname).unwrap_or_default() {
            if let Ok(name) = dns_lookup::lookup_addr(&addr) {
                if name.contains('.') {
                    return name;
                }
                candidates.push(name);
            }
        }
        candidates.pop().unwrap_or_else(|| "localhost".into())
    }

    /// Extract the Ipv4Addr from the given IpAddr.
    pub fn unwrap_ipv4(addr: IpAddr) -> Ipv4Addr {
        match addr {
            IpAddr::V6(_) => panic!("IPv4 address required"),
            IpAddr::V4(ip) => ip
        }
    }

    /// Find the IPv4 address and netmask in the given list of addresses.
    pub fn ipv4_addr(addresses: &[interfaces::Address]) -> Option<(Ipv4Addr, Ipv4Addr)> {
        addresses.iter().find(|ad| ad.kind == interfaces::Kind::Ipv4)
            .map(|ad| (unwrap_ipv4(ad.addr.unwrap().ip()),
                       unwrap_ipv4(ad.mask.unwrap().ip())))
    }

    /// Determine IPv4 address of a host name.
    pub fn lookup_ipv4(host: &str) -> Option<Ipv4Addr> {
        for addr in (host, 0).to_socket_addrs().ok()? {
            if let SocketAddr::V4(v4addr) = addr {
                return Some(*v4addr.ip());
            }
        }
        None
    }

    /// Get a valid interface name.
    pub fn parse_interface(ifname: &str) -> Result<interfaces::Interface, String> {
        match interfaces::Interface::get_by_name(ifname) {
            Ok(Some(iface)) => Ok(iface),
            Ok(None) => Err("no such interface".into()),
            Err(e) => Err(format!("{}", e)),
        }
    }

    /// Determine if two addresses are in the same network, determined by a netmask.
    pub fn in_same_net<T: Into<u32>>(addr1: T, addr2: T, netmask: T) -> bool {
        let (addr1, addr2, netmask) = (addr1.into(), addr2.into(), netmask.into());
        addr1 & netmask == addr2 & netmask
    }
}

pub mod time {
    use time_crate as time;

    /// Local time as floating seconds since the epoch.
    pub fn localtime() -> f64 {
        let ts = time::get_time();
        (ts.sec as f64) + ((ts.nsec as f64) / 1_000_000_000.)
    }

    /// Float time to timespec.
    pub fn to_timespec(t: f64) -> time::Timespec {
        let itime = (1e9 * t) as u64;
        time::Timespec { nsec: (itime % 1_000_000_000) as i32,
                         sec:  (itime / 1_000_000_000) as i64 }
    }

    /// Time to floating.
    pub fn to_timefloat(t: time::Tm) -> f64 {
        let ts = t.to_timespec();
        (ts.sec as f64) + ((ts.nsec as f64) / 1_000_000_000.)
    }
}
