// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Regression tests of a chunk withheld from an honest holder: peers that
//! hold node 2's request for it and let go, by a refusal, a disconnect or
//! the patience, while the holder's pass cannot act on the freed-hash
//! trigger, has stalled, or never looked at the hash (`protocol.md` 4.6,
//! "Several connections"; TM-22). Each fails without the hash kept for a
//! waiting connection, up to its room, or without the place kept for a
//! hash still lacking, and each fetches within the bound TM-22 states
//! ([`bound`]).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "test code"
)]

use core::cell::Cell;
use core::time::Duration;

use licketysync_keys::chunk::seal_chunk;
use licketysync_keys::{CipherHash, RecordHash};
use licketysync_protocol::connection::SendError;
use licketysync_protocol::frame::{Frame, MessageType};

use crate::config::EngineConfig;
use crate::regressions::{first_chunk, key_config, read, requested};
use crate::runtime::PeerId;
use crate::testkit::{Net, chunk_hash, config, folder_key, write_key};
use crate::tests::{folder, write};

/// A second, in the net's nanoseconds.
const S: u64 = 1_000_000_000;

/// The seconds TM-22 bounds a fetch by: a turn each, at most the patience
/// (60 s), of the connection that holds the hash and of the `ahead`
/// connections ahead of the holder in line; the holder's own wait for its
/// trigger, at most the hold (31 s); and a second for its request and the
/// answer.
const fn bound(ahead: u64) -> u64 {
    (ahead + 1) * 60 + 31 + 1
}

/// Moves the net's clock to `at`, if it is not there yet.
fn to_at(net: &mut Net, at: u64) {
    if at > net.now {
        net.advance(Duration::from_nanos(at - net.now));
    }
}

/// The requests for `chunk` node `from` sent node `to`.
fn asked(net: &Net, from: usize, to: usize, chunk: CipherHash) -> usize {
    requested(net, from, to)
        .iter()
        .filter(|c| **c == chunk)
        .count()
}

/// Whether node `r`'s pass to node `to` may ask now, or why not.
fn state(net: &Net, r: usize, to: usize) -> Result<Option<CipherHash>, SendError> {
    let n = &net.nodes[r];
    let peer = PeerId::new(to as u64);
    let Some(c) = n.engine.conns.get(&peer) else {
        return Err(SendError::Closed);
    };
    c.protocol
        .chunk_position(crate::engine::tick(&n.cx, peer), &folder())
}

/// Whether node `r`'s pass to node `to` skipped a hash for another
/// connection's request or turn.
fn skipped(net: &Net, r: usize, to: usize) -> bool {
    net.nodes[r].engine.conns[&PeerId::new(to as u64)]
        .protocol
        .skipped(&folder())
}

/// Whether a reply of node `from` to node `to` for `chunk` is held.
fn held_by(net: &Net, from: usize, to: usize, chunk: CipherHash) -> bool {
    net.gate
        .held
        .get(&(from, to))
        .is_some_and(|v| v.iter().any(|f| chunk_hash(f) == Some(chunk)))
}

/// Node `i` reports one more chunk stored in its next Status, a count a
/// peer may raise at will, which triggers its next pass.
fn more_stored(net: &mut Net, i: usize) {
    net.with(i, |e, cx| {
        e.run(cx, |e, cx, w| e.notify_stored(cx, w, folder(), 1));
    });
}

/// The most internal errors any node counted.
fn errors(net: &Net) -> u64 {
    net.nodes
        .iter()
        .map(|n| n.engine.counters().internal_errors)
        .max()
        .unwrap_or(0)
}

/// What [`aimed_at_the_window`] set up: node 2 asks; node 3 holds h.bin;
/// node 0 holds node 2's request for h; node 1 wrote y.bin and z.bin, and
/// w.bin if [`aimed_with_two_decoys`] set it up, which nobody can fetch.
struct Aimed {
    net: Net,
    record: RecordHash,
    content: Vec<u8>,
    h: CipherHash,
    y: CipherHash,
    z: CipherHash,
    w: Option<CipherHash>,
}

impl Aimed {
    fn fetched(&self) -> bool {
        read(&self.net, 2, self.record) == Ok(self.content.clone())
    }
}

/// Node 2 meets node 0, a key holder whose chunk replies to it are held,
/// and node 3 (first when `holder_first`); node 1, which meets node 3 alone
/// and never answers it, writes y.bin and z.bin, and node 3 writes h.bin.
/// Node 0 is asked for y, z and h and lets z go, so that node 3 is asked
/// for z, refuses it and waits, its pass having skipped h and y.
fn aimed_at_the_window(holder_first: bool) -> Aimed {
    aimed(holder_first, false)
}

/// As [`aimed_at_the_window`], with a second decoy: node 1 writes w.bin
/// too, which node 0 is asked for and node 3's pass skips.
fn aimed_with_two_decoys(holder_first: bool) -> Aimed {
    aimed(holder_first, true)
}

fn aimed(holder_first: bool, two: bool) -> Aimed {
    let mut net = Net::new((0..4).map(key_config).collect());
    net.gate.rules.extend([
        (0, 2, MessageType::ChunkReply, None),
        (1, 3, MessageType::ChunkReply, None),
    ]);
    if holder_first {
        net.connect(3, 2);
        net.connect(0, 2);
    } else {
        net.connect(0, 2);
        net.connect(3, 2);
    }
    net.advance(Duration::from_secs(2));
    net.connect(1, 3);
    net.advance(Duration::from_secs(2));
    let y_record = write(&mut net, 1, "y.bin", &[4u8; 500]).unwrap();
    let z_record = write(&mut net, 1, "z.bin", &[5u8; 500]).unwrap();
    let w_record = two.then(|| write(&mut net, 1, "w.bin", &[6u8; 500]).unwrap());
    net.advance(Duration::from_secs(2));
    let content = vec![9u8; 500];
    let record = write(&mut net, 3, "h.bin", &content).unwrap();
    let (h, y, z) = (
        first_chunk(&net, 3, record),
        first_chunk(&net, 2, y_record),
        first_chunk(&net, 2, z_record),
    );
    let w = w_record.map(|r| first_chunk(&net, 2, r));
    assert_eq!(
        [y, z, h].map(|c| asked(&net, 2, 0, c)),
        [1, 1, 1],
        "node 0 holds them"
    );
    assert!(w.is_none_or(|w| asked(&net, 2, 0, w) == 1));
    net.deliver(0, 2, |f| chunk_hash(f) == Some(z));
    assert_eq!(asked(&net, 2, 3, h), 0);
    Aimed {
        net,
        record,
        content,
        h,
        y,
        z,
        w,
    }
}

/// How node 0 of [`aimed_at_the_window`] lets go of y, if it does: `at`
/// seconds after it was last asked for h, or at once whenever asked; or,
/// set up by [`aimed_with_two_decoys`], y `.0` s after it was last asked
/// for h and w `.1` s after y.
#[derive(Clone, Copy, Debug)]
enum LetY {
    At(u64),
    AtOnce,
    Two(u64, u64),
}

/// Node 0 refuses z whenever asked, y (and w) as `let_y` says (a freed hash
/// node 3 is owed, which makes node 3's trigger act and spends a window of
/// its), and h 59 s after each ask, inside the patience, reporting one more chunk
/// stored so that its own pass asks for h again a second later. Node 3,
/// when `every` is given, stores a chunk every `every.0` s at `every.1`, so
/// that its own Status restarts its pass too. Returns the second at which
/// node 2 held h.bin, within `secs`.
fn let_go_into_the_window(
    mut a: Aimed,
    let_y: Option<LetY>,
    every: Option<(u64, u64)>,
    secs: u64,
) -> Option<u64> {
    let (h, y, z) = (a.h, a.y, a.z);
    let start = a.net.now;
    let (mut asked_at, mut seen) = (0, asked(&a.net, 2, 0, h));
    for second in 1..=secs {
        to_at(&mut a.net, start + second * S);
        let now_seen = asked(&a.net, 2, 0, h);
        if now_seen > seen {
            (seen, asked_at) = (now_seen, second);
        }
        a.net.deliver(0, 2, |f| chunk_hash(f) == Some(z));
        let (y_now, w_now) = match let_y {
            Some(LetY::At(after)) => (second == asked_at + after, false),
            Some(LetY::AtOnce) => (true, false),
            Some(LetY::Two(after, apart)) => (
                second == asked_at + after,
                second == asked_at + after + apart,
            ),
            None => (false, false),
        };
        if y_now {
            a.net.deliver(0, 2, |f| chunk_hash(f) == Some(y));
        }
        if let Some(w) = a.w.filter(|_| w_now) {
            a.net.deliver(0, 2, |f| chunk_hash(f) == Some(w));
        }
        if every.is_some_and(|(every, phase)| second % every == phase) {
            more_stored(&mut a.net, 3);
        }
        if second == asked_at + 59 {
            a.net.deliver(0, 2, |f| chunk_hash(f) == Some(h));
            more_stored(&mut a.net, 0);
        }
        if a.fetched() {
            assert_eq!(errors(&a.net), 0);
            return Some(second);
        }
    }
    assert_eq!(errors(&a.net), 0);
    None
}

#[test]
fn one_peer_that_lets_go_of_a_chunk_while_the_holders_trigger_cannot_act_never_keeps_it() {
    // Node 3 stood first in line for h whenever node 0 let go of it, but
    // its trigger could not act then: node 0 had spent node 3's window by
    // letting go of y, which node 3 was owed, 35 to 50 s earlier. So h went
    // to node 0 again a second later, and node 3 was never asked for it in
    // 15 minutes, whichever of the two node 2 met first. The hash is kept
    // for node 3 until its trigger acts.
    for holder_first in [false, true] {
        for let_y in [
            None,
            Some(LetY::AtOnce),
            Some(LetY::At(35)),
            Some(LetY::At(40)),
            Some(LetY::At(45)),
            Some(LetY::At(50)),
        ] {
            let a = aimed_at_the_window(holder_first);
            let at = let_go_into_the_window(a, let_y, None, bound(1));
            assert!(at.is_some(), "{holder_first} {let_y:?}");
        }
    }
}

#[test]
fn one_peer_that_spends_both_of_the_holders_trigger_windows_with_decoys_never_keeps_a_chunk() {
    // Attack 2 against both windows: a decoy freed hash node 3 is owed
    // spends one of its windows, and a freed hash may use either, so node 0
    // lets two go, y and then w 5 to 25 s later, both before h. When h is
    // kept for node 3 both windows are spent; the hold keeps h for it until
    // the first of them ends, within TM-22's bound. With a waiting
    // connection in line only while a window it may use is open, h went
    // back to node 0 each time and node 3 was never asked for it.
    for holder_first in [false, true] {
        for apart in [5, 10, 15, 20, 25] {
            let a = aimed_with_two_decoys(holder_first);
            let at = let_go_into_the_window(a, Some(LetY::Two(33, apart)), None, bound(1));
            assert!(at.is_some(), "{holder_first} {apart}");
        }
    }
}

#[test]
fn one_peer_never_keeps_a_chunk_from_a_holder_whose_own_status_spends_its_trigger_window() {
    // As above, with node 3 storing chunks now and then: each Status of its
    // with more chunks stored restarted its pass and spent its window, into
    // which node 0 let go of h.
    for every in [(1000, 999), (30, 0), (30, 10), (30, 20), (60, 45), (60, 50)] {
        let a = aimed_at_the_window(false);
        let at = let_go_into_the_window(a, Some(LetY::AtOnce), Some(every), bound(1));
        assert!(at.is_some(), "{every:?}");
    }
}

/// Node 3 holds x.bin, written by node 1; node 2 asks; nodes 0 and 4, read
/// holders (node 4 only with `two`), hold every reply to node 2 and let go
/// of x by turns, each only while node 3's trigger window is spent (5 to 25
/// s after node 3's pass last restarted) and the other can take it, or
/// before 59 s. y, which nobody can fetch, keeps node 3's pass waiting.
/// Returns the seconds after x.bin was written at which node 2 held it,
/// within `secs`, and the requests for x node 2 sent node 3.
fn taking_turns_at_the_window(two: bool, secs: u64) -> (Option<u64>, usize) {
    const A1: usize = 0;
    const W: usize = 1;
    const R: usize = 2;
    const H: usize = 3;
    const A2: usize = 4;
    let attackers: &[usize] = if two { &[A1, A2] } else { &[A1] };
    let read_tier = |n: u8| config(n, vec![folder_key(1, 2)]);
    let mut net = Net::new(vec![
        read_tier(0),
        key_config(1),
        key_config(2),
        key_config(3),
        read_tier(4),
    ]);
    net.gate.rules.push((W, H, MessageType::ChunkReply, None));
    for &a in attackers {
        net.gate.rules.push((a, R, MessageType::ChunkReply, None));
    }
    net.connect(W, H);
    net.connect(H, R);
    net.advance(Duration::from_secs(2));
    let y_record = write(&mut net, W, "y.bin", &[4u8; 500]).unwrap();
    net.advance(Duration::from_secs(2));
    let y = first_chunk(&net, R, y_record);
    assert_eq!(asked(&net, R, H, y), 1, "node 3 refused y");
    assert_eq!(state(&net, R, H), Err(SendError::PassWaiting));
    for &a in attackers {
        net.connect(a, R);
    }
    // Silent, the peers that withhold hold y for good once its patience has
    // run out on each.
    net.advance(Duration::from_secs(if two { 130 } else { 70 }));
    let content = vec![9u8; 500];
    let record = write(&mut net, H, "x.bin", &content).unwrap();
    let x = first_chunk(&net, R, record);
    let start = net.now;
    let mut restarted = (requested(&net, R, H).len(), start);
    let mut since = [0u64; 5];
    for step in 1..=secs * 4 {
        to_at(&mut net, start + step * S / 4);
        if read(&net, R, record) == Ok(content.clone()) {
            assert_eq!(errors(&net), 0);
            return (Some(step / 4), asked(&net, R, H, x));
        }
        let to_h = requested(&net, R, H).len();
        if to_h != restarted.0 {
            restarted = (to_h, net.now);
        }
        let Some(&a) = attackers.iter().find(|&&a| held_by(&net, a, R, x)) else {
            continue;
        };
        if since[a] == 0 {
            since[a] = net.now;
        }
        let other_ready = attackers
            .iter()
            .any(|&b| b != a && state(&net, R, b).is_ok());
        let window = restarted.1;
        let go = if two && a == A1 {
            since[a] < window && net.now >= window + S && other_ready
        } else if two {
            net.now >= window + 5 * S && net.now <= window + 25 * S && other_ready
        } else {
            since[a] < window && net.now >= window + 5 * S && net.now <= window + 25 * S
        };
        if go || net.now - since[a] > 58 * S {
            assert!(net.deliver(a, R, |f| chunk_hash(f) == Some(x)) > 0);
            since[a] = 0;
            more_stored(&mut net, a);
        }
    }
    assert_eq!(errors(&net), 0);
    (None, asked(&net, R, H, x))
}

#[test]
fn one_peer_that_aims_its_refusals_at_the_holders_spent_trigger_window_never_keeps_a_chunk() {
    // Node 0 let go of x only while node 3's window was spent, so that
    // nobody could ask and the hash was forgotten, and asked for it afresh a
    // second later: node 3 was never asked for x in 30 minutes, its pass
    // restarted 62 times.
    let (at, to_holder) = taking_turns_at_the_window(false, bound(1));
    assert!(at.is_some());
    assert_eq!(to_holder, 1);
}

#[test]
fn two_peers_that_aim_their_refusals_at_the_holders_spent_trigger_window_never_keep_a_chunk() {
    // Nodes 0 and 4 handed x to each other while node 3's window was spent:
    // node 3 was never asked for it in 30 minutes.
    let (at, to_holder) = taking_turns_at_the_window(true, bound(2));
    assert!(at.is_some());
    assert_eq!(to_holder, 1);
}

/// A peer of a random swarm that withholds what the requester asks it for.
#[derive(Clone, Copy, Debug)]
enum Withholder {
    /// Never answers.
    Silent,
    /// Lets go of everything it holds at random, once in `0` s on average.
    Slow(u64),
    /// As `Slow`, and reports one more chunk stored as it lets go, to be
    /// asked again.
    Refuser(u64),
    /// Disconnects and reconnects at random, once in `0` s on average.
    Reconnector(u64),
}

/// A small generator for the swarms (xorshift).
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n.max(1)
    }
}

/// A random swarm from `seed`: withholders from node 0 (one to three, some
/// holding the files), the writer, a writer of chunks nobody can fetch, the
/// requester and two honest holders, which the requester meets in a random
/// order. Returns the seconds the requester took to hold every file, within
/// `secs`, the number of withholders, and the most internal errors a node
/// counted.
fn swarm(seed: u64, secs: u64) -> (Option<u64>, u64, u64) {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let withholders = 1 + rng.below(3) as usize;
    let (writer, lost, asker) = (withholders, withholders + 1, withholders + 2);
    let (h1, h2) = (withholders + 3, withholders + 4);
    let mut configs: Vec<EngineConfig> = (0..withholders as u8 + 5).map(key_config).collect();
    let mut kinds = Vec::new();
    let mut holds = Vec::new();
    for c in configs.iter_mut().take(withholders) {
        c.max_requests_in_flight = [1, 2, 64][rng.below(3) as usize];
        kinds.push(match rng.below(4) {
            0 => Withholder::Silent,
            1 => Withholder::Slow(10 + rng.below(70)),
            2 => Withholder::Refuser(10 + rng.below(70)),
            _ => Withholder::Reconnector(20 + rng.below(80)),
        });
        holds.push(rng.below(3) == 0);
    }
    configs[h2].max_requests_in_flight = [1, 4, 64][rng.below(3) as usize];
    let mut net = Net::new(configs);
    for a in 0..withholders {
        net.gate
            .rules
            .push((a, asker, MessageType::ChunkReply, None));
    }
    net.gate
        .rules
        .push((lost, h1, MessageType::ChunkReply, None));
    net.gate
        .rules
        .push((lost, h2, MessageType::ChunkReply, None));
    let mut order: Vec<usize> = (0..withholders).chain([h1, h2]).collect();
    for i in (1..order.len()).rev() {
        order.swap(i, rng.below(i as u64 + 1) as usize);
    }
    for &peer in &order {
        net.connect(peer, asker);
    }
    net.connect(lost, h1);
    net.connect(lost, h2);
    net.advance(Duration::from_secs(2));
    for k in 0..=rng.below(2) {
        let content = vec![200 + k as u8; 400];
        write(&mut net, lost, &format!("u{k}.bin"), &content).unwrap();
    }
    net.advance(Duration::from_secs(3));
    net.disconnect(lost, h1);
    net.disconnect(lost, h2);
    net.connect(writer, h1);
    net.connect(writer, h2);
    for a in (0..withholders).filter(|&a| holds[a]) {
        net.connect(writer, a);
    }
    net.advance(Duration::from_secs(2));
    let mut files = Vec::new();
    for k in 0..=rng.below(4) as usize {
        let content: Vec<u8> = (0..300 + 97 * k)
            .map(|i| (i * (k + 3) + seed as usize) as u8)
            .collect();
        let record = write(&mut net, writer, &format!("f{k}.bin"), &content).unwrap();
        files.push((record, content));
    }
    net.advance(Duration::from_secs(1));
    let start = net.now;
    for second in 1..=secs {
        to_at(&mut net, start + second * S);
        if second == 3 {
            for a in (0..withholders).filter(|&a| holds[a]) {
                net.disconnect(writer, a);
            }
            net.disconnect(writer, h1);
            net.disconnect(writer, h2);
        }
        for (a, kind) in kinds.iter().enumerate() {
            match *kind {
                Withholder::Silent => {}
                Withholder::Slow(every) => {
                    if rng.below(every) == 0 {
                        net.deliver(a, asker, |_| true);
                    }
                }
                Withholder::Refuser(every) => {
                    if rng.below(every) == 0 {
                        net.deliver(a, asker, |_| true);
                        more_stored(&mut net, a);
                    }
                }
                Withholder::Reconnector(every) => {
                    if rng.below(every) == 0 {
                        net.disconnect(a, asker);
                        net.connect(a, asker);
                    }
                }
            }
        }
        if files
            .iter()
            .all(|(record, c)| read(&net, asker, *record).as_ref() == Ok(c))
        {
            return (Some(second), withholders as u64, errors(&net));
        }
    }
    (None, withholders as u64, errors(&net))
}

#[test]
fn random_swarms_of_peers_that_withhold_fetch_every_file_within_the_bound() {
    // Seed 398 (one reconnecting withholder) never fetched in 20 minutes,
    // and seed 34 took 564 s, while the honest holders' passes waited.
    // `LICKETYSYNC_SWARM_SEEDS` runs that many seeds from 1 instead of 40.
    let count = std::env::var("LICKETYSYNC_SWARM_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);
    let mut worst = (0, 0);
    let mut over = Vec::new();
    for seed in (1..=count).chain([34, 398]) {
        let (at, m, bugs) = swarm(seed, bound(3));
        match at {
            Some(at) if at <= bound(m) && bugs == 0 => worst = worst.max((at, seed)),
            _ => over.push((seed, at, m, bugs)),
        }
    }
    assert!(
        over.is_empty(),
        "past the bound: {over:?}; the worst within it took {} s (seed {})",
        worst.0,
        worst.1
    );
}

/// Node 3 holds x.bin and has room for one request; node 1, a read holder,
/// holds node 2's request for x; node 0 writes y.bin and goes before anyone
/// fetched it, so that node 2's pass to node 3, which skipped x for node 1's
/// request, asks for y and stalls on its one slot, the answer held. Node 1
/// refuses x `x_refused_at` seconds after it was asked, if given, and node 3's
/// refusal of y reaches node 2 at `y_refused_at` (y hashes above x when
/// `y_above_x`). Returns whether node 2 held x.bin 2 s after x was free and
/// node 3's refusal arrived, whichever came later.
fn stalled_holder(y_above_x: bool, x_refused_at: Option<u64>, y_refused_at: u64) -> bool {
    let keys = write_key(1).chunk_keys();
    let x_content = vec![7u8; 500];
    let x = seal_chunk(&keys, &x_content).unwrap().cipher_hash;
    let y_content = (0u8..=255)
        .filter(|k| *k != 7)
        .map(|k| vec![k; 500])
        .find(|c| (seal_chunk(&keys, c).unwrap().cipher_hash > x) == y_above_x)
        .unwrap();
    let y = seal_chunk(&keys, &y_content).unwrap().cipher_hash;
    let tier = |n: u8, t: u8| config(n, vec![folder_key(1, t)]);
    let mut configs = vec![tier(0, 1), tier(1, 2), tier(2, 1), tier(3, 1)];
    configs[3].max_requests_in_flight = 1;
    let mut net = Net::new(configs);
    net.gate
        .rules
        .push((1, 2, MessageType::ChunkReply, Some(x)));
    net.connect(1, 2);
    net.connect(3, 2);
    net.advance(Duration::from_secs(2));
    let x_record = write(&mut net, 3, "x.bin", &x_content).unwrap();
    let x_asked = net.now;
    assert_eq!(requested(&net, 2, 1), vec![x], "node 1 holds x");
    net.advance(Duration::from_secs(10));
    net.gate.rules.extend([
        (0, 2, MessageType::ChunkReply, None),
        (0, 3, MessageType::ChunkReply, None),
        (3, 2, MessageType::ChunkReply, Some(y)),
    ]);
    net.connect(0, 2);
    net.connect(0, 3);
    net.advance(Duration::from_secs(2));
    write(&mut net, 0, "y.bin", &y_content).unwrap();
    net.advance(Duration::from_secs(1));
    net.disconnect(0, 2);
    net.disconnect(0, 3);
    assert!(held_by(&net, 3, 2, y), "node 3's answer for y is held");
    assert_eq!(asked(&net, 2, 3, x), 0, "node 3 skipped x");
    if let Some(at) = x_refused_at {
        to_at(&mut net, x_asked + at * S);
        assert!(net.deliver(1, 2, |_| true) > 0, "node 1 refuses x");
        assert_eq!(state(&net, 2, 3), Err(SendError::InFlightFull));
    }
    to_at(&mut net, x_asked + y_refused_at * S);
    assert!(net.deliver(3, 2, |_| true) > 0, "node 3 refuses y");
    let free_at = x_refused_at.unwrap_or(60);
    to_at(&mut net, x_asked + (y_refused_at.max(free_at) + 2) * S);
    assert_eq!(errors(&net), 0);
    read(&net, 2, x_record) == Ok(x_content)
}

#[test]
fn a_holder_whose_pass_is_stalled_when_the_patience_runs_out_is_asked_once_its_pass_ends() {
    // Node 3's pass, past x, came to wait in a run of the passes after the
    // freed-hash trigger was worked out, and never again: node 3 was never
    // asked for x in an hour. Who is owed a hash is checked again as the
    // passes run, and after them.
    assert!(stalled_holder(true, None, 65), "y above x");
    // Controls: node 3's refusal of y before the patience runs out, and y
    // below x, so that node 3's pass reaches x once y is refused.
    assert!(stalled_holder(true, None, 30));
    assert!(stalled_holder(false, None, 65));
}

#[test]
fn a_holder_whose_pass_is_stalled_when_another_refuses_the_chunk_is_asked_once_its_pass_ends() {
    // Node 1 refused x 30 s in, while node 3's pass was stalled: nobody could
    // ask, the requester forgot who was asked last for x, and node 3 was
    // never asked for it in an hour. A hash still lacking keeps its place
    // once its requests end.
    assert!(stalled_holder(true, Some(30), 50));
}

/// Node 3, honest with the default room, holds x.bin, whose chunk hashes
/// below every other, and big.bin, of 100 chunks, and lacks y.bin, which
/// nobody can fetch; node 1, a read holder, holds node 2's request for x.
/// Node 3's answers are held, so that node 2's pass to node 3, past x, has
/// filled its room when node 1 lets go of x, 30 s in (`hang_up`: it
/// disconnects, as a laptop going to sleep would; else it refuses). Node 3's
/// answers then come, sixteen a second. Returns the seconds after node 3's
/// last answer came at which node 2 held x.bin, within the bound for no
/// connection ahead of node 3.
fn mid_pass(hang_up: bool) -> Option<u64> {
    let keys = write_key(1).chunk_keys();
    let big: Vec<u8> = (0..100 * 1024usize)
        .map(|b| ((b * 11 + b / 1024 * 17) % 253) as u8)
        .collect();
    let x_content = (0u8..=255)
        .map(|k| vec![k; 500])
        .min_by_key(|c| seal_chunk(&keys, c).unwrap().cipher_hash)
        .unwrap();
    let x = seal_chunk(&keys, &x_content).unwrap().cipher_hash;
    let tier = |n: u8, t: u8| config(n, vec![folder_key(1, t)]);
    let mut net = Net::new(vec![tier(0, 1), tier(1, 2), tier(2, 1), tier(3, 1)]);
    net.gate.rules.extend([
        (1, 2, MessageType::ChunkReply, Some(x)),
        (3, 2, MessageType::ChunkReply, None),
    ]);
    net.connect(1, 2);
    net.connect(3, 2);
    net.advance(Duration::from_secs(2));
    let x_record = write(&mut net, 3, "x.bin", &x_content).unwrap();
    let x_asked = net.now;
    assert_eq!(requested(&net, 2, 1), vec![x], "node 1 holds x");
    net.gate.rules.extend([
        (0, 2, MessageType::ChunkReply, None),
        (0, 3, MessageType::ChunkReply, None),
    ]);
    net.connect(0, 2);
    net.connect(0, 3);
    net.advance(Duration::from_secs(2));
    let y_record = write(&mut net, 0, "y.bin", &[42u8; 600]).unwrap();
    net.advance(Duration::from_secs(1));
    net.disconnect(0, 2);
    net.disconnect(0, 3);
    net.gate.rules.retain(|rule| rule.0 != 0);
    assert!(read(&net, 2, y_record).is_err() && read(&net, 3, y_record).is_err());
    write(&mut net, 3, "big.bin", &big).unwrap();
    assert_eq!(asked(&net, 2, 3, x), 0, "node 3 skipped x");
    assert_eq!(state(&net, 2, 3), Err(SendError::InFlightFull));
    to_at(&mut net, x_asked + 30 * S);
    if hang_up {
        net.disconnect(1, 2);
    } else {
        assert!(net.deliver(1, 2, |_| true) > 0, "node 1 refuses x");
    }
    loop {
        let at = net.now + S;
        to_at(&mut net, at);
        let sent = Cell::new(0);
        let sixteen = |_: &Frame| {
            sent.set(sent.get() + 1);
            sent.get() <= 16
        };
        if net.deliver(3, 2, sixteen) == 0 {
            break;
        }
    }
    net.gate.rules.retain(|rule| rule.0 != 3);
    assert_eq!(state(&net, 2, 3), Err(SendError::PassWaiting));
    let ended = net.now;
    for second in 0..=bound(0) {
        to_at(&mut net, ended + second * S);
        if read(&net, 2, x_record) == Ok(x_content.clone()) {
            assert_eq!(errors(&net), 0);
            assert_eq!(asked(&net, 2, 3, x), 1);
            return Some(second);
        }
    }
    None
}

#[test]
fn a_holder_mid_pass_when_another_disconnects_is_asked_for_the_chunk_once_its_pass_ends() {
    // Node 1 disconnected while node 3's pass, past x, had filled its room:
    // the requester forgot who was asked last for x, and node 3 was never
    // asked for it in an hour. No peer that withholds is needed.
    assert!(mid_pass(true).is_some_and(|s| s <= 2));
    // The control: node 1 refuses x instead, and, the one connection that
    // could ask meanwhile, asks for it again; node 3 is asked once that
    // turn ends.
    assert!(mid_pass(false).is_some());
}

/// What [`kept_for_a_waiting_peer`] set up.
struct KeptFor {
    net: Net,
    record: RecordHash,
    content: Vec<u8>,
    x: CipherHash,
    /// When node 2 asked node 1 for x.
    asked_at: u64,
}

impl KeptFor {
    fn fetched(&self) -> bool {
        read(&self.net, 2, self.record) == Ok(self.content.clone())
    }

    /// Node 4 lets one of the refusals it holds come.
    fn refusal(&mut self) {
        let x = self.x;
        let one = Cell::new(true);
        assert_eq!(
            self.net
                .deliver(4, 2, |f| chunk_hash(f) != Some(x) && one.replace(false)),
            1
        );
    }
}

/// Node 2 meets node 1, a key holder that holds its request for x and never
/// answers it, node 4 and node 3, in that order. Node 3 writes x.bin, or node
/// 4 when `four_holds`; node 0 then writes l.bin, of 48 chunks, and goes
/// before anyone fetched one. Node 1 refuses them, and node 4 holds node 2's
/// requests for them all, its pass having skipped x, its answers held; a
/// refusal of node 4's ([`KeptFor::refusal`]) makes its pass wait, and frees
/// that chunk for node 3, which refuses it and waits, having skipped x as
/// well. Next in line for x once node 1's patience runs out: node 4, then
/// node 3.
fn kept_for_a_waiting_peer(four_holds: bool) -> KeptFor {
    let mut net = Net::new((0..5).map(key_config).collect());
    let content = vec![9u8; 500];
    let x = seal_chunk(&write_key(1).chunk_keys(), &content)
        .unwrap()
        .cipher_hash;
    net.gate.rules.extend([
        (1, 2, MessageType::ChunkReply, Some(x)),
        (4, 2, MessageType::ChunkReply, None),
        (0, 2, MessageType::ChunkReply, None),
    ]);
    for i in [1, 4, 3] {
        net.connect(i, 2);
    }
    net.advance(Duration::from_secs(2));
    let writer = if four_holds { 4 } else { 3 };
    let record = write(&mut net, writer, "x.bin", &content).unwrap();
    let asked_at = net.now;
    assert_eq!(requested(&net, 2, 1), vec![x], "node 1 holds x");
    net.connect(0, 2);
    net.advance(Duration::from_secs(1));
    let lost: Vec<u8> = (0..48 * 1024usize)
        .map(|b| (b * 7 + b / 1024) as u8)
        .collect();
    write(&mut net, 0, "l.bin", &lost).unwrap();
    net.advance(Duration::from_secs(1));
    net.disconnect(0, 2);
    assert_eq!(requested(&net, 2, 4).len(), 48, "node 4 holds them");
    assert!(skipped(&net, 2, 4));
    let mut k = KeptFor {
        net,
        record,
        content,
        x,
        asked_at,
    };
    k.refusal();
    k.net.advance(Duration::from_secs(1));
    for to in [1, 3] {
        assert_eq!(
            state(&k.net, 2, to),
            Err(SendError::PassWaiting),
            "node {to}"
        );
    }
    assert_eq!(
        [1, 4, 3].map(|to| skipped(&k.net, 2, to)),
        [false, true, true]
    );
    assert_eq!(asked(&k.net, 2, 4, x), 0);
    k
}

#[test]
fn a_peer_that_keeps_its_trigger_from_acting_holds_a_chunk_kept_for_it_only_the_hold() {
    // Node 4 is owed x once node 1's patience runs out, and keeps its
    // trigger from acting by letting a refusal come every 0.9 s, each of
    // which restarts the trigger's 1 s. x is kept for it 31 s, then goes on
    // to node 3, which holds it.
    let mut k = kept_for_a_waiting_peer(false);
    let free = k.asked_at + 60 * S;
    to_at(&mut k.net, free - 5 * S);
    while k.net.now < free + 31 * S {
        let at = k.net.now + 9 * S / 10;
        to_at(&mut k.net, at);
        k.refusal();
        if k.net.now < free + 30 * S {
            assert!(!k.fetched(), "node 4's turn lasts the hold");
        }
    }
    to_at(&mut k.net, free + (31 + 31 + 1) * S);
    assert!(
        k.fetched(),
        "node 3's turn: its own trigger within the hold"
    );
    assert_eq!(asked(&k.net, 2, 4, k.x), 0, "node 4 never asked");
    assert_eq!(errors(&k.net), 0);
}

/// Spends node 4's first trigger window some 10 s before x is kept for it,
/// as a Status of its with one more chunk stored restarts its pass between
/// two refusals of its, each of which makes the pass wait.
fn status_spends_the_window(k: &mut KeptFor, free: u64) {
    to_at(&mut k.net, free - 12 * S);
    k.refusal();
    to_at(&mut k.net, free - 11 * S);
    more_stored(&mut k.net, 4);
    to_at(&mut k.net, free - 5 * S);
    k.refusal();
    k.net.advance(Duration::from_secs(1));
    assert_eq!(state(&k.net, 2, 4), Err(SendError::PassWaiting));
}

#[test]
fn a_chunk_kept_for_a_waiting_peer_whose_status_spent_its_window_is_asked_within_a_second() {
    // The bug: x was kept for node 4, which holds it, some 10 s after a
    // Status of node 4's had restarted its pass and spent the one window its
    // triggers shared, so node 4 asked for x only 20 s into its turn (and a
    // ready holder behind it waited as long). The freed-hash trigger acts in
    // a window of its own. Node 3 holds what it is asked for, so that no
    // chunk node 4 refuses comes back to it.
    let mut k = kept_for_a_waiting_peer(true);
    k.net.gate.rules.push((3, 2, MessageType::ChunkReply, None));
    let (x, free) = (k.x, k.asked_at + 60 * S);
    status_spends_the_window(&mut k, free);
    for tenth in 1..=20 {
        to_at(&mut k.net, free + tenth * S / 10);
        k.net.deliver(4, 2, |f| chunk_hash(f) == Some(x));
    }
    assert!(k.fetched(), "within 2 s of its turn");
    assert_eq!(asked(&k.net, 2, 4, x), 1);
    assert_eq!(errors(&k.net), 0);
}

#[test]
fn a_chunk_kept_for_a_waiting_peer_that_asks_late_counts_its_patience_from_when_it_was_kept() {
    // Both of node 4's trigger windows are spent as x is kept for it: the
    // first by a Status of its 10 s before, and the freed hash's by x's own
    // trigger, whose pass a refusal of node 4's then stops before it starts
    // (a CHUNK_NOT_FOUND restarts its 1 s). So it asks for x 20 s into its
    // turn and never answers. Its turn ends 60 s after x was kept for it,
    // not 60 s after it asked. Node 3 holds what it is asked for but x, so
    // that its own trigger plays no part.
    let mut k = kept_for_a_waiting_peer(false);
    k.net.gate.rules.push((3, 2, MessageType::ChunkReply, None));
    let (x, free) = (k.x, k.asked_at + 60 * S);
    status_spends_the_window(&mut k, free);
    to_at(&mut k.net, free - S / 2);
    k.refusal();
    to_at(&mut k.net, free + 2 * S / 5);
    k.refusal();
    to_at(&mut k.net, free + 19 * S);
    assert_eq!(asked(&k.net, 2, 4, x), 0);
    to_at(&mut k.net, free + 21 * S);
    assert_eq!(asked(&k.net, 2, 4, x), 1, "asked 20 s into its turn");
    for second in 22..=60 {
        to_at(&mut k.net, free + second * S);
        k.net.deliver(3, 2, |f| chunk_hash(f) == Some(x));
        assert_eq!(k.fetched(), second >= 60, "{second}");
    }
    assert_eq!(errors(&k.net), 0);
}

#[test]
fn a_late_refusal_from_a_waiting_peer_a_chunk_is_kept_for_never_spends_its_turn() {
    // Node 4 holds x and answers for it at once; a refusal of an earlier
    // request of its comes just after x was kept for it, which spends every
    // trigger fired before it. The freed-hash trigger is given again
    // whenever the passes run while x is kept for node 4, so node 4 asks for
    // x within its turn rather than losing it.
    let mut k = kept_for_a_waiting_peer(true);
    // Node 3 holds what it is asked for from now on, so that no chunk node 4
    // refuses comes back to it.
    k.net.gate.rules.push((3, 2, MessageType::ChunkReply, None));
    let free = k.asked_at + 60 * S;
    to_at(&mut k.net, free - S / 2);
    k.refusal();
    to_at(&mut k.net, free + S / 4);
    k.refusal();
    let x = k.x;
    for second in 1..=31 {
        to_at(&mut k.net, free + second * S);
        k.net.deliver(4, 2, |f| chunk_hash(f) == Some(x));
    }
    assert!(k.fetched(), "fetched from node 4 within its turn");
    assert_eq!(
        asked(&k.net, 2, 3, x),
        0,
        "node 3, which lacks x, never asked"
    );
    assert_eq!(errors(&k.net), 0);
}

#[test]
fn a_waiting_peer_whose_pass_skipped_nothing_is_passed_over_for_one_whose_pass_did() {
    // Node 2 meets node 5, node 3 and node 1, in that order, so that once
    // node 1, which holds x's request, lets go, node 5 and then node 3 are
    // next in line; node 1 asks for x once it reports one more chunk
    // stored. All three refused y and wait. Node 5's pass skipped nothing;
    // node 3's is marked as having skipped a hash, as a pass that skipped
    // one would be. x is kept for node 3, which holds it, not for node 5,
    // whose trigger would never act on it.
    let keys = write_key(1).chunk_keys();
    let content = vec![7u8; 500];
    let x = seal_chunk(&keys, &content).unwrap().cipher_hash;
    let tier = |n: u8, t: u8| config(n, vec![folder_key(1, t)]);
    let mut net = Net::new(vec![
        tier(0, 1),
        tier(1, 2),
        tier(2, 1),
        tier(3, 1),
        tier(4, 1),
        tier(5, 1),
    ]);
    // Node 2 learns of x from node 1 alone, which lacks its chunk.
    net.gate.rules.extend([
        (3, 2, MessageType::IndexRecords, None),
        (1, 2, MessageType::IndexRecords, None),
        (1, 2, MessageType::ChunkReply, Some(x)),
        (0, 1, MessageType::ChunkReply, None),
        (4, 2, MessageType::ChunkReply, None),
    ]);
    for i in [5, 3, 1] {
        net.connect(i, 2);
    }
    net.connect(0, 3);
    net.connect(0, 1);
    net.advance(Duration::from_secs(2));
    let record = write(&mut net, 0, "x.bin", &content).unwrap();
    net.advance(Duration::from_secs(10));
    assert_eq!(read(&net, 3, record), Ok(content.clone()), "node 3 holds x");
    net.disconnect(0, 3);
    net.disconnect(0, 1);
    net.connect(4, 2);
    net.advance(Duration::from_secs(2));
    write(&mut net, 4, "y.bin", &[8u8; 500]).unwrap();
    net.advance(Duration::from_secs(1));
    net.disconnect(4, 2);
    net.advance(Duration::from_secs(5));
    for to in [5, 3, 1] {
        assert_eq!(state(&net, 2, to), Err(SendError::PassWaiting), "node {to}");
        assert!(!skipped(&net, 2, to), "node {to}");
    }
    net.gate
        .rules
        .retain(|rule| rule.2 != MessageType::IndexRecords || rule.0 != 1);
    assert!(net.deliver(1, 2, |f| chunk_hash(f).is_none()) > 0);
    more_stored(&mut net, 1);
    let start = net.now;
    while asked(&net, 2, 1, x) == 0 {
        assert!(net.now < start + 5 * S, "node 1 asked for x");
        let at = net.now + S / 4;
        to_at(&mut net, at);
    }
    let asked_at = net.now;
    net.nodes[2]
        .engine
        .conns
        .get_mut(&PeerId::new(3))
        .unwrap()
        .protocol
        .pass_skipped(folder());
    to_at(&mut net, asked_at + 62 * S);
    assert_eq!(read(&net, 2, record), Ok(content), "from node 3");
    assert_eq!(asked(&net, 2, 5, x), 0);
    assert_eq!(errors(&net), 0);
}

/// Node 1, a read holder with room for `batch` requests, holds node 2's
/// requests for all `batch` chunks of b.bin, which node 3 wrote, and never
/// answers them; node 3 has room for `room`. Nodes 4 and 5 (node 5 only
/// with `two`), read holders with room for `waiting_room` and met before
/// node 3, each hold node 2's requests for 256 other chunks of node 3's,
/// and then let one refusal come, so that each waits with its skip bit set,
/// first in line for b once node 1's patience runs out; with `trickle`,
/// each lets another come every 0.9 s, so that its trigger never acts.
/// Returns the seconds from b.bin's write until node 2 held it, within
/// `secs`.
fn batch_held_by_waiting_peers(
    batch: usize,
    two: bool,
    trickle: bool,
    room: u32,
    waiting_room: u32,
    secs: u64,
) -> Option<u64> {
    const R: usize = 2;
    let waiters: &[usize] = if two { &[4, 5] } else { &[4] };
    let read_tier = |n: usize| matches!(n, 1 | 4 | 5);
    let mut configs: Vec<EngineConfig> = (0..6u8)
        .map(|n| {
            config(
                n,
                vec![folder_key(1, if read_tier(n.into()) { 2 } else { 1 })],
            )
        })
        .collect();
    configs[1].max_requests_in_flight = batch as u32;
    configs[3].max_requests_in_flight = room;
    for &w in waiters {
        configs[w].max_requests_in_flight = waiting_room;
    }
    let mut net = Net::new(configs);
    for i in [1].iter().chain(waiters) {
        net.gate.rules.push((*i, R, MessageType::ChunkReply, None));
    }
    for i in [1].iter().chain(waiters).chain(&[3]) {
        net.connect(*i, R);
    }
    net.advance(Duration::from_secs(2));
    // Each chunk begins with its number, so that no two are alike.
    let b: Vec<u8> = (0..batch * 1024)
        .map(|i| match i % 1024 {
            0 => (i / 1024) as u8,
            1 => (i / 1024 / 256) as u8,
            _ => (i * 13 + i / 1024 * 7) as u8,
        })
        .collect();
    let record = write(&mut net, 3, "b.bin", &b).unwrap();
    let start = net.now;
    assert_eq!(requested(&net, R, 1).len(), batch, "node 1 holds b");
    let one_refusal = |net: &mut Net, w: usize| {
        let one = Cell::new(true);
        net.deliver(w, R, |_| one.replace(false))
    };
    for (k, &w) in waiters.iter().enumerate() {
        let pool: Vec<u8> = (0..256 * 1024usize)
            .map(|i| (i * (29 + 2 * k) + i / 1024 * (3 + 2 * k) + 1 + k) as u8)
            .collect();
        write(&mut net, 3, &format!("l{k}.bin"), &pool).unwrap();
        net.advance(Duration::from_millis(500));
        assert_eq!(one_refusal(&mut net, w), 1);
        net.advance(Duration::from_millis(500));
        assert_eq!(state(&net, R, w), Err(SendError::PassWaiting));
    }
    for &w in waiters {
        assert!(skipped(&net, R, w), "node {w} skipped b");
    }
    while net.now < start + secs * S {
        let at = net.now + 9 * S / 10;
        to_at(&mut net, at);
        if trickle {
            for &w in waiters {
                one_refusal(&mut net, w);
            }
        }
        if read(&net, R, record) == Ok(b.clone()) {
            assert_eq!(errors(&net), 0);
            return Some((net.now - start) / S);
        }
    }
    None
}

#[test]
fn waiting_peers_that_keep_their_triggers_from_acting_hold_no_more_of_a_batch_than_their_room() {
    // Every hash of a batch was kept for a waiting peer first in line,
    // whatever its room, so two that kept their triggers from acting held
    // the whole batch 31 s each by turns, and the holder got only its
    // room's worth a round: 400 chunks took over 400 s. Each is now kept no
    // more than it could ask for, and the holder asks for the rest.
    for (batch, waiting_room) in [(400, 260), (1000, 300)] {
        let at = batch_held_by_waiting_peers(batch, true, true, 64, waiting_room, bound(2));
        assert!(at.is_some(), "{batch} chunks, room {waiting_room}");
    }
    // Controls: one waiting peer; and two that let their triggers act.
    assert!(batch_held_by_waiting_peers(40, false, true, 4, 1024, bound(1)).is_some());
    assert!(batch_held_by_waiting_peers(40, true, false, 4, 1024, bound(2)).is_some());
}

/// Node 0 writes l.bin, of `lacking` chunks, which nobody can fetch, and
/// goes. Node 1, a read holder with room for one request, holds node 2's
/// request for one of them; node 3, honest, lacks them too, so its pass
/// waits, having skipped the one node 1 holds. Node 1 lets the request it
/// holds go every `every` s, reporting one more chunk stored to be asked
/// again: each time a freed hash node 3 is owed. Returns the requests node 2
/// sent node 3 over `secs` from then.
fn restarted_by_refusals(lacking: usize, every: u64, secs: u64) -> usize {
    let tier = |n: u8, t: u8| config(n, vec![folder_key(1, t)]);
    let mut configs = vec![tier(0, 1), tier(1, 2), tier(2, 1), tier(3, 1)];
    configs[1].max_requests_in_flight = 1;
    let mut net = Net::new(configs);
    net.gate.rules.extend([
        (0, 2, MessageType::ChunkReply, None),
        (1, 2, MessageType::ChunkReply, None),
    ]);
    for i in [1, 3, 0] {
        net.connect(i, 2);
    }
    net.advance(Duration::from_secs(2));
    let lost: Vec<u8> = (0..lacking * 1024)
        .map(|b| (b * 7 + b / 1024 * 3 + 1) as u8)
        .collect();
    write(&mut net, 0, "l.bin", &lost).unwrap();
    net.advance(Duration::from_secs(1));
    net.disconnect(0, 2);
    net.advance(Duration::from_secs(2));
    assert_eq!(requested(&net, 2, 1).len(), 1, "node 1 holds one");
    assert_eq!(state(&net, 2, 3), Err(SendError::PassWaiting));
    let before = requested(&net, 2, 3).len();
    let start = net.now;
    for second in 1..=secs {
        to_at(&mut net, start + second * S);
        if second % every == 0 && net.deliver(1, 2, |_| true) > 0 {
            more_stored(&mut net, 1);
        }
    }
    assert_eq!(errors(&net), 0);
    requested(&net, 2, 3).len() - before
}

#[test]
fn a_peer_that_lets_requests_go_restarts_a_waiting_peers_pass_at_most_twice_per_status_interval() {
    // TM-22: each request node 1 lets go is a freed hash for node 3, whose
    // pass then asks again for every chunk node 2 lacks. A waiting pass
    // restarts at most twice per STATUS_INTERVAL (one window for any
    // trigger, one for a freed hash), so node 3 receives at most two full
    // passes of requests per 30 s, however often node 1 lets one go.
    for (lacking, every) in [(200, 1), (200, 5), (48, 1)] {
        let asked = restarted_by_refusals(lacking, every, 120);
        let passes = 2 * (120 / 30 + 1);
        assert!(
            asked <= passes * lacking,
            "{lacking} lacking, one every {every} s: {asked} requests"
        );
    }
}
