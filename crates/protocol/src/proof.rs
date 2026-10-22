// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Step 4 of the handshake (`protocol.md` 3.5): the folder proof, one for
//! every tier (ruling S-1). The prover seals a `ProofPayload` naming the tier
//! it reports under the proof key of the transcript, with the hint as
//! associated data; a payload that opens proves that its sender holds the
//! folder's access key (TM-32). Every value is the keys crate's
//! ([`HandshakeKeys`], `keys.md` 4, which draws each proof's nonce from the
//! caller's randomness); this module only frames them.

use licketysync_keys::folder::FolderKey;
use licketysync_keys::handshake::HandshakeKeys;
use licketysync_keys::{FolderId, FolderVerifier, RandomFill, Role, SealError, Suite, Tier};
use prost::Message as _;

use crate::hello::TranscriptHash;
use crate::limits::PROOF_NONCE_LEN;
use crate::messages::{FolderProof, ProofPayload};
use crate::parse::Parse;

/// What a device holds of one folder for its handshakes: the handshake keys
/// derived from its folder key, the folder's verifier (suite, verification
/// key and folder ID, which every record of the folder is checked against)
/// and the device's own tier.
/// The engine builds one per folder it holds and has not paused, and hands
/// them to the connection on every call that needs them. Zeroized on drop
/// (the keys); its `Debug` names only the folder.
#[derive(Debug)]
pub struct FolderCredential {
    keys: HandshakeKeys,
    verifier: FolderVerifier,
    tier: Tier,
}

impl FolderCredential {
    /// The credential of the folder `key` is a key to, at its tier.
    #[must_use]
    pub fn new(key: &FolderKey) -> Self {
        Self {
            keys: key.handshake_keys(),
            verifier: *key.verifier(),
            tier: key.tier(),
        }
    }

    /// The folder's verifier.
    #[must_use]
    pub fn verifier(&self) -> &FolderVerifier {
        &self.verifier
    }

    /// The folder.
    #[must_use]
    pub fn folder_id(&self) -> FolderId {
        self.keys.folder_id()
    }

    /// The folder's suite.
    #[must_use]
    pub fn suite(&self) -> Suite {
        self.verifier.suite()
    }

    /// This device's tier for the folder, the one its proofs report.
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// The folder's hint for the transcript `th` and the prover's `role`.
    #[must_use]
    pub fn hint(&self, th: &TranscriptHash, role: Role) -> [u8; 32] {
        self.keys.hint(&th.0, role)
    }

    /// This device's `FolderProof` for the folder on the connection whose
    /// transcript is `th`, as the side with `role`.
    ///
    /// # Errors
    /// [`SealError`] only for a payload beyond the cipher's limit, which a
    /// two-byte payload never is.
    pub fn prove(
        &self,
        th: &TranscriptHash,
        role: Role,
        rng: &mut RandomFill<'_>,
    ) -> Result<FolderProof, SealError> {
        seal_proof(&self.keys, th, role, self.tier, rng)
    }

    /// Opens a peer's `FolderProof` whose hint matched this folder (3.5 steps
    /// 3 and 4); `peer_role` is the prover's.
    ///
    /// # Errors
    /// [`ProofFailure`], every one answered REJECTED.
    pub fn open(
        &self,
        th: &TranscriptHash,
        peer_role: Role,
        proof: &FolderProof,
    ) -> Result<Tier, ProofFailure> {
        // A proof whose hint is not this folder's for the prover's role does
        // not open (step 2 matched it already in the connection).
        if proof.hint.as_slice() != self.keys.hint(&th.0, peer_role) {
            return Err(ProofFailure::Seal);
        }
        let nonce = <[u8; PROOF_NONCE_LEN]>::try_from(proof.nonce.as_slice())
            .map_err(|_| ProofFailure::Seal)?;
        let opened = self
            .keys
            .open_proof(&th.0, peer_role, &nonce, &proof.sealed)
            .map_err(|_| ProofFailure::Seal)?;
        let payload = ProofPayload::parse(&opened).map_err(|_| ProofFailure::Payload)?;
        Tier::from_wire(payload.tier).ok_or(ProofFailure::Tier(payload.tier))
    }
}

/// Why a `FolderProof` whose hint matched did not open the folder (3.5 steps
/// 3 and 4). Each is answered with the same uniform REJECTED.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofFailure {
    /// The sealed payload did not open under this connection's proof key.
    Seal,
    /// The opened payload does not parse.
    Payload,
    /// The reported tier is not 1, 2 or 3.
    Tier(u32),
}

/// The `FolderProof` of the folder whose handshake keys are `keys`, for the
/// transcript `th` and the prover's `role`, reporting `tier`: the hint, and the
/// keys crate's `seal_proof` of `ProofPayload { tier }` (24 fresh bytes from
/// `rng` as the nonce, the hint as associated data). Crate-private: a device
/// proves through [`FolderCredential::prove`], which reports its own tier; the
/// vectors seal every tier under one folder's keys.
pub(crate) fn seal_proof(
    keys: &HandshakeKeys,
    th: &TranscriptHash,
    role: Role,
    tier: Tier,
    rng: &mut RandomFill<'_>,
) -> Result<FolderProof, SealError> {
    let payload = ProofPayload {
        tier: tier.to_wire(),
    }
    .encode_to_vec();
    let (nonce, sealed) = keys.seal_proof(&th.0, role, &payload, rng)?;
    Ok(FolderProof {
        hint: keys.hint(&th.0, role).to_vec(),
        sealed,
        nonce: nonce.to_vec(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use licketysync_keys::secret::WriteSecret;
    use licketysync_keys::WriteKey;

    use super::*;

    fn folder(byte: u8) -> WriteKey {
        WriteKey::from_secret(Suite::ONE, WriteSecret::from_bytes([byte; 32])).unwrap()
    }

    fn tiers(byte: u8) -> [FolderKey; 3] {
        let w = folder(byte);
        let r = w.read_key();
        let s = w.sealed_key();
        [
            FolderKey::from(folder(byte)),
            FolderKey::from(r),
            FolderKey::from(s),
        ]
    }

    #[test]
    fn every_tier_proves_to_every_tier_and_reports_its_own() {
        let th = TranscriptHash([3; 32]);
        let mut fill = |b: &mut [u8]| b.fill(0x55);
        for prover in tiers(1) {
            let p = FolderCredential::new(&prover);
            let proof = p.prove(&th, Role::A, &mut fill).unwrap();
            assert_eq!(proof.sealed.len(), 18, "a full payload seals to 18 bytes");
            assert_eq!(proof.nonce, vec![0x55; 24]);
            for verifier in tiers(1) {
                let v = FolderCredential::new(&verifier);
                assert_eq!(v.hint(&th, Role::A), proof.hint.as_slice());
                assert_eq!(v.open(&th, Role::A, &proof), Ok(prover.tier()));
            }
        }
    }

    #[test]
    fn the_proof_is_bound_to_the_transcript_role_and_folder() {
        let th = TranscriptHash([3; 32]);
        let mut fill = |b: &mut [u8]| b.fill(1);
        let [w, _, _] = tiers(1);
        let c = FolderCredential::new(&w);
        assert_eq!(c.folder_id(), w.folder_id());
        assert_eq!(c.suite(), Suite::ONE);
        assert_eq!(c.tier(), Tier::Write);
        let proof = c.prove(&th, Role::A, &mut fill).unwrap();
        // Replayed into another connection: another proof key.
        assert_eq!(
            c.open(&TranscriptHash([4; 32]), Role::A, &proof),
            Err(ProofFailure::Seal)
        );
        // Reflected: the sender's hint for role B is another hint.
        assert_ne!(c.hint(&th, Role::B), proof.hint.as_slice());
        let mut moved = proof.clone();
        moved.hint = c.hint(&th, Role::B).to_vec();
        assert_eq!(c.open(&th, Role::B, &moved), Err(ProofFailure::Seal));
        // Another folder's key opens nothing.
        let [other, _, _] = tiers(2);
        let o = FolderCredential::new(&other);
        assert_ne!(o.hint(&th, Role::A), proof.hint.as_slice());
        assert_eq!(o.open(&th, Role::A, &proof), Err(ProofFailure::Seal));
        let mut bad_nonce = proof.clone();
        bad_nonce.nonce.truncate(23);
        assert_eq!(c.open(&th, Role::A, &bad_nonce), Err(ProofFailure::Seal));
    }

    #[test]
    fn a_payload_that_opens_but_is_wrong_is_refused() {
        let th = TranscriptHash([3; 32]);
        let [w, _, _] = tiers(1);
        let keys = w.handshake_keys();
        let c = FolderCredential::new(&w);
        let seal = |payload: &[u8]| {
            let (nonce, sealed) = keys
                .seal_proof(&th.0, Role::A, payload, &mut |b: &mut [u8]| b.fill(9))
                .unwrap();
            FolderProof {
                hint: keys.hint(&th.0, Role::A).to_vec(),
                sealed,
                nonce: nonce.to_vec(),
            }
        };
        assert_eq!(
            c.open(&th, Role::A, &seal(&[0x20, 0])),
            Err(ProofFailure::Tier(0))
        );
        assert_eq!(
            c.open(&th, Role::A, &seal(&[0x20, 4])),
            Err(ProofFailure::Tier(4))
        );
        assert_eq!(c.open(&th, Role::A, &seal(&[])), Err(ProofFailure::Tier(0)));
        assert_eq!(
            c.open(&th, Role::A, &seal(&[0x0b])),
            Err(ProofFailure::Payload)
        );
        // Fields a later release adds are skipped.
        assert_eq!(
            c.open(&th, Role::A, &seal(&[0x28, 1, 0x20, 3])),
            Ok(Tier::Sealed)
        );
    }
}
