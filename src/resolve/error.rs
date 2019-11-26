use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ResolverError {
    ConnectionTimeout,
    NameServerNotResolved,
    NotFound,
    DnsClientError(::trust_dns::error::ClientError),
}

unsafe impl Send for ResolverError {}

impl fmt::Display for ResolverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl Error for ResolverError {
    fn description(&self) -> &str {
        match *self {
            ResolverError::ConnectionTimeout => "Connection timeout",
            ResolverError::NameServerNotResolved => "Failed to resolve nameserver",
            ResolverError::NotFound => "Not found",
            ResolverError::DnsClientError(ref err) => err.description(),
        }
    }
}
