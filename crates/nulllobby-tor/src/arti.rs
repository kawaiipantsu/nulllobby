//! Reviewed extension point, deliberately unavailable until per-service RAM-only
//! storage is supported and verified. See docs/wiki/Arti-Review.md.
use nulllobby_transport::{Transport, TransportError};
pub const REVIEWED_ARTI_VERSION: &str = "0.47.0";
/// Explicit failure, with no network operation or transport substitution.
pub fn experimental_backend() -> Result<Box<dyn Transport>, TransportError> {
    Err(TransportError::Unsupported)
}
#[cfg(test)]
mod tests {
    #[test]
    fn unavailable_backend_cannot_fall_back() {
        assert!(matches!(
            super::experimental_backend(),
            Err(nulllobby_transport::TransportError::Unsupported)
        ));
    }
}
