// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The process-default rustls provider (`suites.md` 2.6, "Providers are
//! passed explicitly").
//!
//! `libp2p-tls` and `libp2p-quic` build their rustls configurations on
//! `aws_lc_rs::default_provider()` themselves and never read the process
//! default. This crate still installs that provider as the default before it
//! builds a transport, so that a dependency calling rustls's default
//! builders gets it rather than a panic or another provider. If a default is
//! already installed, it is accepted only when it is that provider: the same
//! key-exchange groups and cipher suites, compared by identity (the same
//! `aws-lc-rs` statics, in the same order, so X25519MLKEM768 first and TLS 1.3
//! only), not merely by name; anything else is an error, and the transport is
//! not built.
//!
//! First-party code builds no rustls configuration of its own: the two
//! transports use `libp2p-tls`'s.

use core::fmt;

use rustls::crypto::CryptoProvider;
use rustls::NamedGroup;

/// Why the process-default provider is not the one `suites.md` 2.6 requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderError {
    /// The installed default does not list X25519MLKEM768 first; `first` is
    /// the group it does list first, if any.
    NotPostQuantumFirst {
        /// The installed default's first key-exchange group.
        first: Option<NamedGroup>,
    },
    /// The installed default is not `aws_lc_rs::default_provider()`: its
    /// key-exchange groups or cipher suites are other objects, or in another
    /// order, even where the names agree.
    NotAwsLcRsDefault,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPostQuantumFirst { first: Some(group) } => write!(
                f,
                "the installed rustls provider offers {group:?} first, not X25519MLKEM768"
            ),
            Self::NotPostQuantumFirst { first: None } => {
                f.write_str("the installed rustls provider offers no key-exchange group")
            }
            Self::NotAwsLcRsDefault => {
                f.write_str("the installed rustls provider is not aws-lc-rs's default provider")
            }
        }
    }
}

impl std::error::Error for ProviderError {}

/// Installs `rustls::crypto::aws_lc_rs::default_provider()` as the process
/// default, or checks the one already installed. Idempotent: a second call
/// finds this crate's own provider and returns `Ok`.
///
/// # Errors
///
/// [`ProviderError`] when a default was already installed (by another crate,
/// before this call) that is not `aws_lc_rs::default_provider()`.
pub fn install_default_provider() -> Result<(), ProviderError> {
    // An `Err` here only says that a default was installed first; which one
    // it is decides, below.
    let _first_install = rustls::crypto::aws_lc_rs::default_provider().install_default();
    match CryptoProvider::get_default() {
        Some(installed) => check(installed),
        None => Err(ProviderError::NotPostQuantumFirst { first: None }),
    }
}

/// Whether `provider` is `aws_lc_rs::default_provider()` (`suites.md` 2.6):
/// X25519MLKEM768 first, and every key-exchange group and cipher suite the
/// very object `aws-lc-rs` defines, in its order. Comparing addresses rather
/// than names means a look-alike, another provider's group or suite under the
/// same name, is refused. The provider's random source and key loader are not
/// compared: `aws-lc-rs` gives them as zero-sized values, whose addresses mean
/// nothing.
///
/// # Errors
///
/// As [`install_default_provider`].
pub fn check(provider: &CryptoProvider) -> Result<(), ProviderError> {
    let first = provider.kx_groups.first().map(|group| group.name());
    if first != Some(NamedGroup::X25519MLKEM768) {
        return Err(ProviderError::NotPostQuantumFirst { first });
    }
    let reference = rustls::crypto::aws_lc_rs::default_provider();
    let same_groups = provider.kx_groups.len() == reference.kx_groups.len()
        && provider
            .kx_groups
            .iter()
            .zip(&reference.kx_groups)
            .all(|(ours, theirs)| core::ptr::addr_eq(*ours, *theirs));
    let same_suites = provider.cipher_suites.len() == reference.cipher_suites.len()
        && provider
            .cipher_suites
            .iter()
            .zip(&reference.cipher_suites)
            .all(|(ours, theirs)| match (ours.tls13(), theirs.tls13()) {
                (Some(ours), Some(theirs)) => core::ptr::eq(ours, theirs),
                _ => false,
            });
    if same_groups && same_suites {
        Ok(())
    } else {
        Err(ProviderError::NotAwsLcRsDefault)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use rustls::crypto::{ActiveKeyExchange, SupportedKxGroup};

    use super::*;

    /// A key-exchange group that calls itself X25519MLKEM768 and is not
    /// `aws-lc-rs`'s.
    #[derive(Debug)]
    struct LookAlike(u8);

    impl SupportedKxGroup for LookAlike {
        fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
            // Not zero-sized, so that its address is its own.
            Err(rustls::Error::General(format!("look-alike {}", self.0)))
        }

        fn name(&self) -> NamedGroup {
            NamedGroup::X25519MLKEM768
        }
    }

    static LOOK_ALIKE: LookAlike = LookAlike(0);

    #[test]
    fn the_aws_lc_rs_default_passes() {
        assert_eq!(
            check(&rustls::crypto::aws_lc_rs::default_provider()),
            Ok(())
        );
    }

    #[test]
    fn a_provider_that_differs_from_the_default_is_refused() {
        let base = rustls::crypto::aws_lc_rs::default_provider;
        // A look-alike group under the hybrid's name, first.
        let mut look_alike = base();
        *look_alike.kx_groups.first_mut().unwrap() = &LOOK_ALIKE;
        assert_eq!(
            look_alike.kx_groups.first().map(|g| g.name()),
            Some(NamedGroup::X25519MLKEM768)
        );
        // The default's suites in another order.
        let mut reordered = base();
        reordered.cipher_suites.reverse();
        // The hybrid alone.
        let mut fewer = base();
        fewer.kx_groups.truncate(1);
        for provider in [look_alike, reordered, fewer] {
            assert_eq!(check(&provider), Err(ProviderError::NotAwsLcRsDefault));
        }
        let mut classical_first = base();
        classical_first.kx_groups.rotate_left(1);
        assert_eq!(
            check(&classical_first),
            Err(ProviderError::NotPostQuantumFirst {
                first: Some(NamedGroup::X25519)
            })
        );
        for e in [
            ProviderError::NotAwsLcRsDefault,
            ProviderError::NotPostQuantumFirst { first: None },
            ProviderError::NotPostQuantumFirst {
                first: Some(NamedGroup::X25519),
            },
        ] {
            assert_ne!(e.to_string(), "");
        }
    }
}
