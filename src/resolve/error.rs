use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub enum ResolverError {
    FuturesSendError,
    DnsClientError(::trust_dns::error::ClientError),
    Io(::std::io::Error)
}

unsafe impl Send for ResolverError {}

impl fmt::Display for ResolverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ResolverError::FuturesSendError        => write!(f, "{}", self.description()),
            ResolverError::DnsClientError(ref err) => write!(f, "{}", err.description()),
            ResolverError::Io(ref err)             => write!(f, "{}", err.description()),
        }
    }
}


impl Error for ResolverError {
    fn description(&self) -> &str {
        match *self {
            ResolverError::FuturesSendError        => "Receiving end was closed",
            ResolverError::DnsClientError(ref err) => err.description(),
            ResolverError::Io(ref err)             => err.description(),
        }
    }
}