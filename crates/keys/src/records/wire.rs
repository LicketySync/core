// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The Protocol Buffers schemas of the key records, mirroring the field tables
//! of `keys.md` sections 2.2, 5.1, 5.3, 7.1, 7.2 and 7.3 exactly (prost
//! derives; the tables are normative). Producers encode canonically (section
//! 5.2: fields in number order, defaults omitted, minimal varints, which prost
//! does); verifiers decode and never re-encode. Field numbers 1 to 3 mean the
//! same in every body so that [`Prefix`] can read the suite and type first.

use super::SignedRecord;

/// The common prefix of every body.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub(crate) struct Prefix {
    #[prost(uint32, tag = "1")]
    pub(crate) suite: u32,
    #[prost(uint32, tag = "2")]
    pub(crate) record_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) folder_id: Vec<u8>,
}

/// The Folder record body (type 1, section 2.2).
#[allow(
    clippy::struct_field_names,
    reason = "field names mirror the spec's table"
)]
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub(crate) struct Folder {
    #[prost(uint32, tag = "1")]
    pub(crate) suite: u32,
    #[prost(uint32, tag = "2")]
    pub(crate) record_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) folder_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub(crate) root_signing_pk: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub(crate) root_kem_pk: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub(crate) folder_nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub(crate) root_wrapped_data_key: Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub(crate) created_at: u64,
    #[prost(uint32, tag = "9")]
    pub(crate) minimum_suite: u32,
    #[prost(string, repeated, tag = "10")]
    pub(crate) required_features: Vec<String>,
    #[prost(bytes = "vec", tag = "11")]
    pub(crate) confirm: Vec<u8>,
}

/// The Grant body (type 2, section 5.3).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub(crate) struct Grant {
    #[prost(uint32, tag = "1")]
    pub(crate) suite: u32,
    #[prost(uint32, tag = "2")]
    pub(crate) record_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) folder_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub(crate) key_id: Vec<u8>,
    #[prost(uint32, tag = "5")]
    pub(crate) tier: u32,
    #[prost(bool, tag = "6")]
    pub(crate) may_share: bool,
    #[prost(uint64, tag = "7")]
    pub(crate) expires_at: u64,
    #[prost(bytes = "vec", tag = "8")]
    pub(crate) issuer_key_id: Vec<u8>,
    #[prost(uint64, tag = "9")]
    pub(crate) epoch: u64,
    #[prost(bytes = "vec", tag = "10")]
    pub(crate) signing_pk: Vec<u8>,
    #[prost(bytes = "vec", tag = "11")]
    pub(crate) kem_pk: Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    pub(crate) wrapped_data_key: Vec<u8>,
    #[prost(uint64, tag = "13")]
    pub(crate) issued_at: u64,
    #[prost(bytes = "vec", tag = "14")]
    pub(crate) issuer_device_id: Vec<u8>,
}

/// One wrap inside a Rotation (section 7.1).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub(crate) struct KeyWrap {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) key_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) wrapped_data_key: Vec<u8>,
}

/// The Rotation body (type 3, section 7.1).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub(crate) struct Rotation {
    #[prost(uint32, tag = "1")]
    pub(crate) suite: u32,
    #[prost(uint32, tag = "2")]
    pub(crate) record_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) folder_id: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub(crate) new_epoch: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub(crate) signer_key_id: Vec<u8>,
    #[prost(message, repeated, tag = "6")]
    pub(crate) wraps: Vec<KeyWrap>,
    #[prost(bytes = "vec", tag = "7")]
    pub(crate) ladder: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub(crate) cause: Vec<u8>,
    #[prost(uint64, tag = "9")]
    pub(crate) issued_at: u64,
    #[prost(bytes = "vec", repeated, tag = "10")]
    pub(crate) view: Vec<Vec<u8>>,
    #[prost(bytes = "vec", tag = "11")]
    pub(crate) confirm: Vec<u8>,
}

/// The Wrap body (type 4, section 7.1).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub(crate) struct Wrap {
    #[prost(uint32, tag = "1")]
    pub(crate) suite: u32,
    #[prost(uint32, tag = "2")]
    pub(crate) record_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) folder_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub(crate) key_id: Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub(crate) epoch: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub(crate) wrapped_data_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub(crate) signer_key_id: Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub(crate) issued_at: u64,
    #[prost(uint32, tag = "9")]
    pub(crate) tier: u32,
}

/// A cutoff (`protocol.md` 4.5), shared by Revocation and Suspension.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub(crate) struct Cutoff {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) key_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) device_id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub(crate) seq: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub(crate) head_hash: Vec<u8>,
}

/// The Revocation body (type 5, section 7.2).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub(crate) struct Revocation {
    #[prost(uint32, tag = "1")]
    pub(crate) suite: u32,
    #[prost(uint32, tag = "2")]
    pub(crate) record_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) folder_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub(crate) revoked_key_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub(crate) signer_key_id: Vec<u8>,
    #[prost(message, repeated, tag = "6")]
    pub(crate) cutoffs: Vec<Cutoff>,
    #[prost(uint64, tag = "7")]
    pub(crate) issued_at: u64,
}

/// The Suspension body (type 6, section 7.3).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub(crate) struct Suspension {
    #[prost(uint32, tag = "1")]
    pub(crate) suite: u32,
    #[prost(uint32, tag = "2")]
    pub(crate) record_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) folder_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub(crate) key_id: Vec<u8>,
    #[prost(uint32, tag = "5")]
    pub(crate) acting_tier: u32,
    #[prost(uint64, tag = "6")]
    pub(crate) until: u64,
    #[prost(bytes = "vec", tag = "7")]
    pub(crate) signer_key_id: Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub(crate) issued_at: u64,
    #[prost(message, repeated, tag = "9")]
    pub(crate) cutoffs: Vec<Cutoff>,
}

/// The Lift body (type 7, section 7.3): names the Suspension by record hash.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub(crate) struct Lift {
    #[prost(uint32, tag = "1")]
    pub(crate) suite: u32,
    #[prost(uint32, tag = "2")]
    pub(crate) record_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) folder_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub(crate) suspension: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub(crate) signer_key_id: Vec<u8>,
    #[prost(uint64, tag = "6")]
    pub(crate) issued_at: u64,
}

/// The records a link carries (section 6.2): the Folder record, then the
/// grant chain parent-first.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub(crate) struct KeyBundle {
    #[prost(message, repeated, tag = "1")]
    pub(crate) records: Vec<SignedRecord>,
}
