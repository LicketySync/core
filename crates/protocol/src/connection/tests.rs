// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The connection's behaviour, scenario by scenario, between two real
//! connections (the test kit's `Pair`) or against a peer scripted by hand.
//! Each test names the section 5 rows it reaches; TM numbers in comments.

mod chunks;
mod exchange;
mod handshake;
