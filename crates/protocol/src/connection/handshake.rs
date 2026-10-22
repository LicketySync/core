// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Steps 3 and 4 of the handshake (`protocol.md` 3.2 to 3.5) on one
//! connection: the peer's Hello, the device proofs, the folder proofs both
//! ways and the opening of folders (TM-30, TM-32).

use std::collections::BTreeMap;

use licketysync_keys::{FolderId, RandomFill, Signature};

use super::{Connection, Event, Keys, Output, ProveError, State};
use crate::frame::Frame;
use crate::hello::{check_peer_hello, role_of, transcript_hash, TranscriptHash};
use crate::limits::{MAX_OPEN_FOLDERS_PER_CONNECTION, MAX_PROOFS_PER_CONNECTION};
use crate::messages::{
    CloseReason, DeviceProof, FolderProof, Hello, Message, ProofResult, ProofStatus,
};
use crate::rules::Cause;
use crate::PROTOCOL_ID;

impl Connection {
    pub(super) fn on_hello(
        &mut self,
        keys: &Keys<'_>,
        hello: Hello,
        frame: &Frame,
        out: &mut Output,
    ) {
        let peer = match check_peer_hello(
            hello,
            frame,
            &self.config.suites,
            self.config.transport_identity.as_ref(),
        ) {
            Ok(peer) => peer,
            Err(reason) => {
                let cause = match reason {
                    CloseReason::NoCommonSuite => Cause::NoCommonSuite,
                    CloseReason::LimitTooSmall => Cause::LimitTooSmall,
                    _ => Cause::Malformed,
                };
                return self.close_with(reason, Some(cause), out);
            }
        };
        // Equal keys: a device connected to itself.
        let Some(role) = role_of(&self.device_public, &peer.device) else {
            return self.fail(Cause::Malformed, out);
        };
        if *keys.device.public() != self.device_public {
            // The engine passed another device key than the Hello's: a local
            // error, never a peer's; close without blaming anyone.
            return self.close_with(CloseReason::Unspecified, None, out);
        }
        let ours = self.hello_frame.type_and_body();
        let own_id = self.config.libp2p_identity;
        let th = match role {
            licketysync_keys::Role::A => transcript_hash(
                PROTOCOL_ID,
                &own_id,
                &peer.libp2p_identity,
                &ours,
                &peer.bytes,
            ),
            licketysync_keys::Role::B => transcript_hash(
                PROTOCOL_ID,
                &peer.libp2p_identity,
                &own_id,
                &peer.bytes,
                &ours,
            ),
        };
        let signature = keys.device.sign_device_proof(&th.0, role);
        self.peer = Some(peer);
        self.role = Some(role);
        self.th = Some(th);
        self.state = State::AwaitingDeviceProof;
        self.send_own(
            &Message::DeviceProof(DeviceProof {
                signature: signature.as_bytes().to_vec(),
            }),
            out,
        );
    }

    pub(super) fn on_device_proof(
        &mut self,
        keys: &Keys<'_>,
        rng: &mut RandomFill<'_>,
        proof: &DeviceProof,
        out: &mut Output,
    ) {
        let (Some(peer), Some(role), Some(th)) = (self.peer.as_ref(), self.role, self.th) else {
            return self.fail(Cause::Malformed, out);
        };
        let Some(signature) = Signature::from_slice(&proof.signature) else {
            return self.fail(Cause::Malformed, out);
        };
        if peer
            .device
            .verify_device_proof(&th.0, role.peer(), &signature)
            .is_err()
        {
            return self.fail(Cause::DeviceProofRejected, out);
        }
        let device_id = peer.device_id;
        self.state = State::Established;
        self.decoder.set_limit(self.config.max_message_size);
        self.hello_deadline = None;
        self.proof_deadline = Some(self.now.saturating_add(self.config.timing.proof));
        out.events.push(Event::Authenticated {
            device_id,
            role: role.peer(),
        });
        for folder in core::mem::take(&mut self.pending) {
            self.send_proof(keys, rng, folder, out);
        }
    }

    /// Asks to open `folder` on this connection: sends its `FolderProof`, or
    /// keeps it until the peer's device key is proven (nothing about a folder
    /// leaves before then). A folder already proven here is left as it is.
    ///
    /// # Errors
    /// [`ProveError`].
    pub fn prove(
        &mut self,
        keys: &Keys<'_>,
        rng: &mut RandomFill<'_>,
        tick: super::Tick,
        folder: FolderId,
    ) -> Result<Output, ProveError> {
        if self.state == State::Closed {
            return Err(ProveError::Closed);
        }
        if keys.folder(&folder).is_none() {
            return Err(ProveError::UnknownFolder);
        }
        let mut out = Output::default();
        self.observe(tick, &mut out);
        if self.state == State::Established {
            if !self.folders.get(&folder).is_some_and(|f| f.proof_sent) {
                if self.proofs_sent >= MAX_PROOFS_PER_CONNECTION {
                    return Err(ProveError::TooMany);
                }
                self.send_proof(keys, rng, folder, &mut out);
            }
        } else if !self.pending.contains(&folder) {
            if self.pending.len() >= MAX_PROOFS_PER_CONNECTION {
                return Err(ProveError::TooMany);
            }
            self.pending.push(folder);
        }
        self.finish(&mut out);
        Ok(out)
    }

    /// Sends this side's one `FolderProof` for `folder`, if it holds a
    /// credential for it and has room under `MAX_PROOFS_PER_CONNECTION`.
    fn send_proof(
        &mut self,
        keys: &Keys<'_>,
        rng: &mut RandomFill<'_>,
        folder: FolderId,
        out: &mut Output,
    ) {
        let (Some(th), Some(role)) = (self.th, self.role) else {
            return;
        };
        let Some(credential) = keys.folder(&folder) else {
            return;
        };
        let state = self.folders.entry(folder).or_default();
        if state.proof_sent || self.proofs_sent >= MAX_PROOFS_PER_CONNECTION {
            return;
        }
        state.proof_sent = true;
        state.verifier = Some(*credential.verifier());
        self.proofs_sent += 1;
        // Sealing two bytes cannot fail; were it to, no proof goes and the
        // folder simply does not open here.
        let Ok(proof) = credential.prove(&th, role, rng) else {
            return;
        };
        if let Ok(hint) = <[u8; 32]>::try_from(proof.hint.as_slice()) {
            self.our_hints.insert(hint, (folder, false));
        }
        self.send_own(&Message::FolderProof(proof), out);
    }

    /// The folder a hint names for the peer's role, from a table built once
    /// per connection over every folder held and not paused.
    fn hint_folder(
        &mut self,
        keys: &Keys<'_>,
        th: &TranscriptHash,
        hint: &[u8; 32],
    ) -> Option<FolderId> {
        let peer_role = self.role?.peer();
        let cache = self.hint_cache.get_or_insert_with(|| {
            keys.folders
                .iter()
                .map(|f| (f.hint(th, peer_role), f.folder_id()))
                .collect::<BTreeMap<_, _>>()
        });
        cache.get(hint).copied()
    }

    /// The verifier's steps of 3.5 for one `FolderProof`.
    pub(super) fn on_folder_proof(
        &mut self,
        keys: &Keys<'_>,
        rng: &mut RandomFill<'_>,
        proof: &FolderProof,
        out: &mut Output,
    ) {
        // Step 1: the envelope (its sizes were checked at parse), a hint not
        // seen before on this connection, at most 256 proofs.
        let (Some(th), Some(role)) = (self.th, self.role) else {
            return self.fail(Cause::Malformed, out);
        };
        let Ok(hint) = <[u8; 32]>::try_from(proof.hint.as_slice()) else {
            return self.fail(Cause::Malformed, out);
        };
        if self.received_hints.len() >= MAX_PROOFS_PER_CONNECTION
            || !self.received_hints.insert(hint)
        {
            return self.fail(Cause::Malformed, out);
        }
        let accepted = self.verify_proof(keys, &th, role.peer(), &hint, proof);
        let status = if accepted.is_some() {
            ProofStatus::Accepted
        } else {
            ProofStatus::Rejected
        };
        self.send_own(
            &Message::ProofResult(ProofResult {
                hint: hint.to_vec(),
                status: status.as_u32(),
            }),
            out,
        );
        let Some((folder, tier)) = accepted else {
            return;
        };
        self.accepted += 1;
        let state = self.folders.entry(folder).or_default();
        state.peer_tier = Some(tier);
        if !state.proof_sent {
            self.send_proof(keys, rng, folder, out);
        }
        self.check_open(folder, out);
    }

    /// Steps 2 to 6: the hint, the seal, the payload, the peer's suites, the
    /// open-folder bound. `None` is the uniform REJECTED.
    fn verify_proof(
        &mut self,
        keys: &Keys<'_>,
        th: &TranscriptHash,
        peer_role: licketysync_keys::Role,
        hint: &[u8; 32],
        proof: &FolderProof,
    ) -> Option<(FolderId, licketysync_keys::Tier)> {
        let folder = self.hint_folder(keys, th, hint)?;
        let credential = keys.folder(&folder)?;
        let tier = credential.open(th, peer_role, proof).ok()?;
        let peer_lists_suite = self
            .peer
            .as_ref()
            .is_some_and(|p| p.suites.contains(&credential.suite().to_wire()));
        if !peer_lists_suite || self.accepted >= MAX_OPEN_FOLDERS_PER_CONNECTION {
            return None;
        }
        self.folders.entry(folder).or_default().verifier = Some(*credential.verifier());
        Some((folder, tier))
    }

    pub(super) fn on_proof_result(&mut self, result: &ProofResult, out: &mut Output) {
        let entry = <[u8; 32]>::try_from(result.hint.as_slice())
            .ok()
            .and_then(|h| self.our_hints.get_mut(&h));
        // A stray result, or a second one for one proof (3.5).
        let Some((folder, answered)) = entry.filter(|(_, answered)| !*answered) else {
            return self.fail(Cause::Malformed, out);
        };
        *answered = true;
        let folder = *folder;
        match ProofStatus::from_u32(result.status) {
            Some(ProofStatus::Accepted) => {
                self.folders.entry(folder).or_default().ours_accepted = true;
                self.check_open(folder, out);
            }
            Some(ProofStatus::Rejected) => out.events.push(Event::ProofRejected { folder }),
            None => self.fail(Cause::Malformed, out),
        }
    }

    /// A folder is open when both sides have accepted each other's proof.
    fn check_open(&mut self, folder: FolderId, out: &mut Output) {
        let Some(state) = self.folders.get_mut(&folder) else {
            return;
        };
        let (Some(peer_tier), true, true, Some(verifier)) = (
            state.peer_tier,
            state.ours_accepted,
            state.open.is_none(),
            state.verifier,
        ) else {
            return;
        };
        state.open = Some(Box::new(super::index::Exchange::new(verifier)));
        if !self.opened_any {
            self.opened_any = true;
            self.proof_deadline = None;
            self.next_status = Some(self.now.saturating_add(self.config.timing.status));
        }
        out.events.push(Event::FolderOpened { folder, peer_tier });
        self.round_on_open(folder, out);
        out.events.push(Event::StatusDue);
    }
}
