use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub enum ResolverError {
    ConnectionTimeout,
    NameServerNotResolved,
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
            ResolverError::ConnectionTimeout       => "Connection timeout",
            ResolverError::NameServerNotResolved   => "Failed to resolve nameserver", 
            ResolverError::DnsClientError(ref err) => err.description(),
        }
    }
}
