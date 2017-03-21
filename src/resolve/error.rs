use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub enum ResolverError {
    FuturesSendError,
    ConnectionTimeout,
    NameServerNotResolved,
    DnsClientError(::trust_dns::error::ClientError),
    Io(::std::io::Error)
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
            ResolverError::FuturesSendError        => "Receiving end was closed",
            ResolverError::ConnectionTimeout       => "Connection timeout",
            ResolverError::NameServerNotResolved   => "Failed to resolve nameserver", 
            ResolverError::DnsClientError(ref err) => err.description(),
            ResolverError::Io(ref err)             => err.description(),
        }
    }
}