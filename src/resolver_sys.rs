
use std::net::IpAddr;
use std::io;
use std::mem;
use std::ffi::{CString, CStr};
use std::ptr::null_mut;

use ::resolver::{Result, Error, ErrorKind};

// Import all libc staff
use nix::errno::errno;
use nix::libc;
use nix::libc::{
    c_int, c_char, c_void,

    EAI_AGAIN, EAI_BADFLAGS, EAI_FAIL, EAI_FAMILY, 
    EAI_MEMORY, EAI_NONAME, EAI_OVERFLOW, EAI_SYSTEM,
    NI_MAXHOST, NI_NAMEREQD,

    sockaddr_in, sockaddr_in6,
    AF_INET, AF_INET6
};

fn gai_strerror(error: i32) -> &'static str {
    unsafe {
        CStr::from_ptr(libc::gai_strerror(error)).to_str().unwrap()
    }
}

extern "C" {
    fn inet_pton(af: c_int, addr_str: *const c_char, addr: *mut c_void);
    fn htons(hostshort: u16) -> u16;
}

pub fn getnameinfo(ip: &IpAddr) -> Result<String> {
    // From addr to string for inet_pton
    // @TODO find a way to avoid this shit
    let ip_str = CString::new(format!("{}", ip)).unwrap();

    // Buffer to store host
    let mut host = [0; NI_MAXHOST as usize];
    
    let status = unsafe { 
        match *ip {
            IpAddr::V4(_) => getnameinfo_ipv4(&ip_str, &mut host[..]),
            IpAddr::V6(_) => getnameinfo_ipv6(&ip_str, &mut host[..])
        }
    };

    match status {
        EAI_BADFLAGS | EAI_FAMILY | EAI_OVERFLOW => panic!("{}", gai_strerror(status)),
        EAI_AGAIN  => Err(Error::from_kind(ErrorKind::Again)),
        EAI_FAIL   => Err(Error::from_kind(ErrorKind::Fail)),
        EAI_MEMORY => Err(Error::from_kind(ErrorKind::OutOfMemory)),
        EAI_NONAME => Err(Error::from(io::Error::from(io::ErrorKind::NotFound))),
        EAI_SYSTEM => Err(Error::from(io::Error::from_raw_os_error(errno()))),
        0 => {
            let c_str = unsafe {
                CStr::from_ptr(&host[0] as *const i8).to_owned()
            };
            Ok(c_str.into_string().unwrap())
        }
        _ => panic!("Unknown error")
    }

    
}

unsafe fn getnameinfo_ipv4(ip_str: &CStr, host: &mut [i8]) -> i32 {
    // Init addr struct
    let mut addr: sockaddr_in = mem::zeroed();
    addr.sin_family = AF_INET as u16;
    addr.sin_port = htons(0);
    inet_pton(AF_INET, ip_str.as_ptr(), mem::transmute(&mut addr.sin_addr as *mut _));

    // Reverse DNS query
    libc::getnameinfo(
        mem::transmute(&mut addr as *mut _),
        mem::size_of::<sockaddr_in>() as u32,
        &mut host[0] as *mut c_char,
        NI_MAXHOST,
        null_mut(),
        0,
        NI_NAMEREQD
    )
}

unsafe fn getnameinfo_ipv6(ip_str: &CStr, host: &mut [i8]) -> i32 {
    // Init addr struct
    let mut addr: sockaddr_in6 = mem::zeroed();
    addr.sin6_family = AF_INET6 as u16;
    addr.sin6_port = htons(0);
    inet_pton(AF_INET6, ip_str.as_ptr(), mem::transmute(&mut addr.sin6_addr as *mut _));

    // Reverse DNS query
    libc::getnameinfo(
        mem::transmute(&mut addr as *mut _),
        mem::size_of::<sockaddr_in6>() as u32,
        &mut host[0] as *mut c_char,
        NI_MAXHOST,
        null_mut(),
        0,
        NI_NAMEREQD
    )
}

mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn reverse_ipv4() {
        let ipv4addr = IpAddr::from_str("213.180.193.3").unwrap();
        let hostname = super::getnameinfo(&ipv4addr).unwrap();
        assert_eq!("www.yandex.ru", &hostname);
    }
    
    #[test]
    fn reverse_ipv6() {
        let ipv6addr = IpAddr::from_str("2a02:6b8::3").unwrap();
        let hostname = super::getnameinfo(&ipv6addr).unwrap();
        assert_eq!("www.yandex.ru", &hostname);
    }
}