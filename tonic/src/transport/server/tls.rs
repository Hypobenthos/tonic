use tokio_rustls::rustls::server::danger::ClientCertVerifier;

use crate::transport::{
    service::TlsAcceptor,
    tls::{Certificate, Identity},
};
use std::{fmt, sync::Arc};

/// Configures TLS settings for servers.
#[derive(Clone, Default)]
pub struct ServerTlsConfig {
    identity: Option<Identity>,
    client_ca_root: Option<Certificate>,
    client_auth_optional: bool,
    #[cfg(feature = "tls-danger")]
    verifier: Option<Arc<dyn ClientCertVerifier>>,
}

impl fmt::Debug for ServerTlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerTlsConfig").finish()
    }
}

impl ServerTlsConfig {
    /// Creates a new `ServerTlsConfig`.
    pub fn new() -> Self {
        ServerTlsConfig {
            identity: None,
            client_ca_root: None,
            client_auth_optional: false,
            #[cfg(feature = "tls-danger")]
            verifier: None,
        }
    }

    /// Sets the [`Identity`] of the server.
    pub fn identity(self, identity: Identity) -> Self {
        ServerTlsConfig {
            identity: Some(identity),
            ..self
        }
    }

    /// Sets a certificate against which to validate client TLS certificates.
    pub fn client_ca_root(self, cert: Certificate) -> Self {
        ServerTlsConfig {
            client_ca_root: Some(cert),
            ..self
        }
    }

    /// Sets whether client certificate verification is optional.
    ///
    /// This option has effect only if CA certificate is set.
    ///
    /// # Default
    /// By default, this option is set to `false`.
    pub fn client_auth_optional(self, optional: bool) -> Self {
        ServerTlsConfig {
            client_auth_optional: optional,
            ..self
        }
    }

    /// Sets a custom certificate verifier.
    #[cfg(feature = "tls-danger")]
    pub fn certificate_verifier(self, verifier: Arc<dyn ClientCertVerifier>) -> Self {
        ServerTlsConfig {
            verifier: Some(verifier),
            ..self
        }
    }

    pub(crate) fn tls_acceptor(&self) -> Result<TlsAcceptor, crate::Error> {
        TlsAcceptor::new(
            self.identity.clone().unwrap(),
            self.client_ca_root.clone(),
            self.client_auth_optional,
            #[cfg(feature = "tls-danger")]
            self.verifier.clone(),
        )
    }
}
