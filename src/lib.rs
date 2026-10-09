//! Ed25519 agent identity: signing and verification of messages.
//! This module does not establish a PKI, revocation, or secure key storage.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Verify that a message was signed by the matching private key.
/// This does not establish that the signer is trustworthy or that the message is true.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let signature = Signature::from_bytes(signature);
    key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_signature_verifies() {
        let agent = Identity::generate();
        let signature = agent.sign(b"task:42");
        assert!(verify(&agent.public_key(), b"task:42", &signature));
    }

    #[test]
    fn modified_message_fails() {
        let agent = Identity::generate();
        let signature = agent.sign(b"task:42");
        assert!(!verify(&agent.public_key(), b"task:43", &signature));
    }

    #[test]
    fn other_agent_cannot_verify() {
        let agent = Identity::generate();
        let other = Identity::generate();
        let signature = agent.sign(b"task:42");
        assert!(!verify(&other.public_key(), b"task:42", &signature));
    }
}
