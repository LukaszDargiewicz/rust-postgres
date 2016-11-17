//! Schannel support.
extern crate schannel;

use std::error::Error;

use self::schannel::tls_stream;
use self::schannel::schannel_cred;
use tls::{Stream, TlsStream, TlsHandshake};

impl TlsStream for tls_stream::TlsStream<Stream> {
    fn get_ref(&self) -> &Stream {
        self.get_ref()
    }

    fn get_mut(&mut self) -> &mut Stream {
        self.get_mut()
    }
}

/// A `TlsHandshake` implementation that uses SChannel.
///
/// Requires the `with-schannel` feature.
pub struct Schannel(schannel_cred::Builder);

impl fmt::Debug for Schannel {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SChannel").finish()
    }
}

impl Schannel {
    /// Creates a `Schannel` with `SchannelCred`'s default configuration.
    pub fn new() -> Schannel {
        Schannel(schannel_cred::SchannelCred::builder())
    }
    /// Returns a mutable reference to the inner `schannel_cred::Builder`.
    pub fn cred_builder(&mut self)->&mut schannel_cred::Builder {
    	&mut self.0
    }
}

impl From<schannel_cred::Builder> for Schannel {
    fn from(builder: schannel_cred::Builder) -> Schannel {
        Schannel(builder)
    }
}

impl TlsHandshake for Schannel {
    fn tls_handshake(&self,
                     domain: &str,
                     stream: Stream)
                     -> Result<Box<TlsStream>, Box<Error + Send + Sync>> {
        let mut builder = tls_stream::Builder::new();
        builder.domain(domain);
        let cred = try!(self.0.acquire(schannel_cred::Direction::Outbound));
        let stream = try!(builder.connect(cred, stream));
        Ok(Box::new(stream))
    }
}
