pub mod keys;
pub mod token;
pub mod verifier;

pub use keys::*;
pub use token::*;
pub use verifier::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_claims() -> SubscriptionClaims {
        SubscriptionClaims {
            key_id: 1,

            token_id: [10u8; TOKEN_ID_SIZE],

            client_id: [20u8; CLIENT_ID_SIZE],

            issued_at: 1_000,

            not_before: 1_000,

            expires_at: 2_000,

            plan: SubscriptionPlan::Pro,

            device_limit: 5,

            max_mbps: 500,
        }
    }

    #[test]
    fn token_roundtrip() {
        let signing_key = generate_signing_key().unwrap();

        let original = SubscriptionToken::sign(test_claims(), &signing_key);

        let encoded = original.encode();

        assert_eq!(encoded.len(), TOKEN_SIZE);

        let decoded = SubscriptionToken::decode(encoded).unwrap();

        assert_eq!(decoded.claims, original.claims);

        assert_eq!(decoded.signature, original.signature);
    }

    #[test]
    fn valid_token_passes() {
        let signing_key = generate_signing_key().unwrap();

        let verifying_key = signing_key.verifying_key();

        let token = SubscriptionToken::sign(test_claims(), &signing_key);

        let mut keys = VerificationKeyRing::new();

        keys.insert(1, verifying_key);

        let verifier = SubscriptionVerifier::new(keys, MemoryRevocationStore::new());

        let claims = verifier.verify_at(&token, 1_500).unwrap();

        assert_eq!(claims.plan, SubscriptionPlan::Pro);
    }

    #[test]
    fn expired_token_fails() {
        let signing_key = generate_signing_key().unwrap();

        let mut keys = VerificationKeyRing::new();

        keys.insert(1, signing_key.verifying_key());

        let token = SubscriptionToken::sign(test_claims(), &signing_key);

        let verifier = SubscriptionVerifier::new(keys, MemoryRevocationStore::new());

        let result = verifier.verify_at(&token, 2_001);

        assert!(matches!(result, Err(AuthError::Expired)));
    }

    #[test]
    fn modified_token_signature_fails() {
        let signing_key = generate_signing_key().unwrap();

        let mut token = SubscriptionToken::sign(test_claims(), &signing_key);

        //
        // Пользователь решил:
        //
        // "А сделаю-ка себе подписку
        // до далёкого будущего".
        //
        token.claims.expires_at = 99_999_999;

        let mut keys = VerificationKeyRing::new();

        keys.insert(1, signing_key.verifying_key());

        let verifier = SubscriptionVerifier::new(keys, MemoryRevocationStore::new());

        let result = verifier.verify_at(&token, 1_500);

        assert!(matches!(result, Err(AuthError::InvalidSignature)));
    }

    #[test]
    fn revoked_token_fails() {
        let signing_key = generate_signing_key().unwrap();

        let token = SubscriptionToken::sign(test_claims(), &signing_key);

        let mut keys = VerificationKeyRing::new();

        keys.insert(1, signing_key.verifying_key());

        let mut revocations = MemoryRevocationStore::new();

        revocations.revoke(token.claims.token_id);

        let verifier = SubscriptionVerifier::new(keys, revocations);

        let result = verifier.verify_at(&token, 1_500);

        assert!(matches!(result, Err(AuthError::Revoked)));
    }

    #[test]
    fn wrong_signing_key_fails() {
        let real_key = generate_signing_key().unwrap();

        let wrong_key = generate_signing_key().unwrap();

        let token = SubscriptionToken::sign(test_claims(), &real_key);

        let mut keys = VerificationKeyRing::new();

        //
        // key_id совпадает,
        // но public key другой.
        //
        keys.insert(1, wrong_key.verifying_key());

        let verifier = SubscriptionVerifier::new(keys, MemoryRevocationStore::new());

        let result = verifier.verify_at(&token, 1_500);

        assert!(matches!(result, Err(AuthError::InvalidSignature)));
    }
}
