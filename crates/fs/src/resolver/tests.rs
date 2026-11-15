// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The resolver on real directories. Each test makes a scratch directory
//! holding `root`, the folder, and `outside`, where nothing may ever land,
//! and runs on every way a root resolves: on Linux by `openat2` and by the
//! walk (the test-only switch), elsewhere by the walk. The tests that need a
//! mount (a casefold file system, a bind mount) run again in a child process
//! under a new user and mount namespace (`unshare -Urm`), and are skipped,
//! saying why, where no such namespace can be made.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "test code"
)]

use std::error::Error as _;
use std::ffi::OsStr;
use std::fs::{self, Permissions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustix::fs::{FileType, Mode};
use rustix::io::Errno;

use super::unix::{Bounds, DIRECTORY, Meta};
use super::*;
use crate::name::{HIDDEN_DIR, IndexPath, Name, NameError, NamePolicy};

const POLICY: NamePolicy = NamePolicy::native();

/// A fresh directory in the system's temporary directory, holding `root`
/// and `outside`; removed when dropped.
struct Scratch {
    base: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            // Semgrep's community rule flags every std::env::temp_dir(): a
            // name there can be taken first by anyone. The name is used only
            // once this test made it, by create_dir, which fails on anything
            // already there, a link included; then the next is tried.
            // nosemgrep: rust.lang.security.temp-dir.temp-dir
            let tmp = std::env::temp_dir();
            let base = tmp.join(format!("licketysync-fs-{}-{n}", std::process::id()));
            match fs::create_dir(&base) {
                Ok(()) => {
                    fs::create_dir(base.join("root")).unwrap();
                    fs::create_dir(base.join("outside")).unwrap();
                    return Self { base };
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(e) => panic!("cannot make a scratch directory: {e}"),
            }
        }
    }

    fn root(&self) -> PathBuf {
        self.base.join("root")
    }

    fn outside(&self) -> PathBuf {
        self.base.join("outside")
    }

    /// A name beneath the root, for the test's own setting up.
    fn at(&self, rel: &str) -> PathBuf {
        self.root().join(rel)
    }

    fn outside_is_empty(&self) -> bool {
        fs::read_dir(self.outside()).unwrap().next().is_none()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn ip(s: &str) -> IndexPath {
    POLICY.index_path(s).unwrap()
}

fn name(s: &str) -> Name {
    POLICY.name(s).unwrap()
}

/// The root at `dir` twice: as it opens, and switched to the walk. On Linux
/// the first resolves by `openat2`; elsewhere both walk.
fn roots(dir: &Path) -> [Root; 2] {
    let first = Root::open(dir, POLICY).unwrap();
    let mut walking = Root::open(dir, POLICY).unwrap();
    force_walk(&mut walking);
    [first, walking]
}

/// As [`roots`], for a system directory where no hidden directory may be
/// made (`/`, `/dev`).
fn unmarked_roots(dir: &Path) -> [Root; 2] {
    let first = Root::open_unmarked(dir, POLICY).unwrap();
    let mut walking = Root::open_unmarked(dir, POLICY).unwrap();
    force_walk(&mut walking);
    [first, walking]
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn force_walk(root: &mut Root) {
    root.force_walk();
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn force_walk(_: &mut Root) {}

/// A regular file's entry that matches nothing on the disk, for the calls
/// that must refuse before comparing.
fn some_file() -> Entry {
    Entry {
        kind: Kind::File,
        id: FileId { dev: 0, ino: 0 },
        size: 0,
        mtime: Time { secs: 0, nanos: 0 },
        ctime: Time { secs: 0, nanos: 0 },
        mode: 0o644,
        nlink: 1,
    }
}

/// The variable that marks the child [`in_namespace`] starts.
const CHILD: &str = "LICKETYSYNC_FS_TEST_IN_NAMESPACE";

/// Whether this process is a child that [`in_namespace`] started, under a
/// user and mount namespace of its own, where it may mount.
fn in_child() -> bool {
    std::env::var_os(CHILD).is_some()
}

/// Runs the test `test` (its full name) again in a child process under a new
/// user and mount namespace, `unshare -Urm`, and asserts that it passed
/// there. Where no such namespace can be made (no unshare, or the kernel or
/// a security module forbids it to unprivileged users), prints why and
/// returns.
fn in_namespace(test: &str) {
    match Command::new("unshare").args(["-Urm", "true"]).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let why = String::from_utf8_lossy(&out.stderr);
            eprintln!("skipped {test}: `unshare -Urm` fails here: {}", why.trim());
            return;
        }
        Err(e) => {
            eprintln!("skipped {test}: no unshare here: {e}");
            return;
        }
    }
    // Semgrep's community rule flags every std::env::current_exe(): whoever
    // runs a binary can change the path it gives. Here it only names this
    // test's own binary, to start it again.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let exe = std::env::current_exe().unwrap();
    let out = Command::new("unshare")
        .arg("-Urm")
        .arg("--")
        .arg(exe)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{test} in a namespace:\n{stdout}\n{stderr}"
    );
    eprint!("{stderr}");
}

/// A mount in the child's namespace, undone when dropped (before the
/// scratch directory it is in, when declared after it).
struct Mount(PathBuf);

impl Mount {
    /// `mount <args> <target>`, or `None`, saying why, when it fails.
    fn new(args: &[&OsStr], target: &Path) -> Option<Self> {
        let out = Command::new("mount")
            .args(args)
            .arg(target)
            .output()
            .unwrap();
        if out.status.success() {
            Some(Self(target.to_owned()))
        } else {
            eprintln!(
                "mount {args:?} {}: {}",
                target.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
            None
        }
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg("-l").arg(&self.0).status();
    }
}

/// TM-4's sequence at the resolver: there is no symbolic link in the
/// protocol, so the link is local, here `a` leading outside the root. A
/// peer's directory `a` and then its file `a/x` must not reach through it,
/// and nothing may appear outside.
#[test]
fn tm_4_symlink_then_directory() {
    let s = Scratch::new();
    symlink(s.outside(), s.at("a")).unwrap();
    fs::create_dir(s.at("d")).unwrap();
    symlink(s.outside(), s.at("d/e")).unwrap();
    // A link that stays inside the root is not followed either.
    symlink("d", s.at("inner")).unwrap();
    // A link to a file outside.
    fs::write(s.base.join("secret"), b"secret").unwrap();
    symlink(s.base.join("secret"), s.at("f")).unwrap();
    for root in roots(&s.root()) {
        for (p, create) in [
            ("a/x", Create::No),
            // Making `a` a directory, as for a peer's directory record: the
            // link is neither followed nor replaced.
            ("a/x", Create::Directories),
            ("a/b/x", Create::Directories),
            ("d/e/x", Create::Directories),
            ("inner/x", Create::No),
        ] {
            let got = root.parent(&ip(p), create);
            assert!(
                matches!(got, Err(ResolveError::Symlink)),
                "{p} {create:?}: {got:?}"
            );
        }
        let (top, a) = root.parent(&ip("a"), Create::No).unwrap();
        assert!(matches!(top.stat(&a), Err(ResolveError::Symlink)));
        let f = name("f");
        assert!(matches!(top.stat(&f), Err(ResolveError::Symlink)));
        assert!(matches!(
            top.open_file(&f, &some_file()),
            Err(ResolveError::Symlink)
        ));
    }
    assert!(s.outside_is_empty());
    assert!(
        fs::symlink_metadata(s.at("a"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

/// The race: one thread swaps `a` between a directory and a link outside,
/// atomically, while resolutions of `a/b/x` (making `b`) and of `a/x` run on
/// both ways, until each way has both gone through the directory and been
/// refused at the link at least [`RACE_EACH`] times. Nothing lands outside.
/// Bounded by counts, never by time: each resolving thread stops after
/// [`RACE_CAP`] resolutions, and the swapping thread after [`RACE_SWAPS`]
/// swaps. Linux only: it swaps with `RENAME_EXCHANGE`, which the file
/// systems the tests meet there all have.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn tm_4_symlink_then_directory_race() {
    const RACE_EACH: usize = 20;
    const RACE_CAP: usize = 200_000;
    const RACE_SWAPS: usize = 20_000_000;
    let s = Scratch::new();
    fs::create_dir(s.at("a")).unwrap();
    symlink(s.outside(), s.at("spare")).unwrap();
    let top = rustix::fs::open(s.root(), DIRECTORY, Mode::empty()).unwrap();
    let both = roots(&s.root());
    let stop = std::sync::atomic::AtomicBool::new(false);
    let outcomes: Vec<(usize, usize)> = std::thread::scope(|scope| {
        let swapper = scope.spawn(|| {
            let mut swaps = 0;
            while !stop.load(Ordering::Relaxed) && swaps < RACE_SWAPS {
                rustix::fs::renameat_with(
                    &top,
                    "a",
                    &top,
                    "spare",
                    rustix::fs::RenameFlags::EXCHANGE,
                )
                .unwrap();
                swaps += 1;
            }
        });
        let resolvers: Vec<_> = both
            .iter()
            .map(|root| {
                scope.spawn(move || {
                    let deep = ip("a/b/x");
                    let shallow = ip("a/x");
                    let (mut through, mut refused) = (0, 0);
                    for _ in 0..RACE_CAP {
                        if through >= RACE_EACH && refused >= RACE_EACH {
                            break;
                        }
                        match root.parent(&deep, Create::Directories) {
                            Ok(_) => through += 1,
                            // A link when opened, and a directory again when
                            // examined: refused as not a directory.
                            Err(ResolveError::Symlink | ResolveError::NotADirectory) => {
                                refused += 1;
                            }
                            Err(e) => panic!("{e}"),
                        }
                        if let Ok((dir, x)) = root.parent(&shallow, Create::No) {
                            assert!(matches!(dir.stat(&x), Ok(None | Some(_))));
                        }
                    }
                    (through, refused)
                })
            })
            .collect();
        let outcomes = resolvers.into_iter().map(|r| r.join().unwrap()).collect();
        stop.store(true, Ordering::Relaxed);
        swapper.join().unwrap();
        outcomes
    });
    for (through, refused) in outcomes {
        assert!(
            through >= RACE_EACH && refused >= RACE_EACH,
            "through {through}, refused {refused}"
        );
    }
    assert!(s.outside_is_empty());
}

#[test]
fn fifos_sockets_and_devices_are_special() {
    let s = Scratch::new();
    let _socket = std::os::unix::net::UnixListener::bind(s.at("socket")).unwrap();
    // rustix makes FIFOs on Linux only; macOS's are the same file type.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    rustix::fs::mkfifoat(rustix::fs::CWD, s.at("fifo"), Mode::RUSR | Mode::WUSR).unwrap();
    let specials: &[&str] = if cfg!(any(target_os = "linux", target_os = "android")) {
        &["socket", "fifo"]
    } else {
        &["socket"]
    };
    for root in roots(&s.root()) {
        for special in specials {
            let (dir, n) = root.parent(&ip(special), Create::No).unwrap();
            assert!(
                matches!(dir.stat(&n), Err(ResolveError::Special)),
                "{special}"
            );
            let opened = dir.open_file(&n, &some_file());
            assert!(
                matches!(opened, Err(ResolveError::Special)),
                "{special}: {opened:?}"
            );
            for create in [Create::No, Create::Directories] {
                let got = root.parent(&ip(&format!("{special}/x")), create);
                assert!(
                    matches!(got, Err(ResolveError::Special)),
                    "{special}: {got:?}"
                );
            }
        }
    }
    // A device, through a root at /dev: never read for its content.
    for dev in unmarked_roots(Path::new("/dev")) {
        let (dir, null) = dev.parent(&ip("null"), Create::No).unwrap();
        assert!(matches!(dir.stat(&null), Err(ResolveError::Special)));
        assert!(matches!(
            dir.open_file(&null, &some_file()),
            Err(ResolveError::Special)
        ));
    }
}

/// A mount point of another file system beneath the root, without
/// privileges: `/dev` is a file system of its own on Linux (devtmpfs) and
/// macOS (devfs), so a root at `/` holds one. A mount of the root's own file
/// system (a bind mount) is another case, tested in a namespace below.
#[test]
fn a_mount_point_beneath_the_root_is_another_file_system() {
    let slash = fs::metadata("/").unwrap().dev();
    assert_ne!(
        fs::metadata("/dev").unwrap().dev(),
        slash,
        "/dev must be mounted apart from /"
    );
    for root in unmarked_roots(Path::new("/")) {
        let (top, dev) = root.parent(&ip("dev"), Create::No).unwrap();
        assert!(matches!(top.stat(&dev), Err(ResolveError::OtherFileSystem)));
        for (p, create) in [("dev/null", Create::No), ("dev/x/y", Create::Directories)] {
            let got = root.parent(&ip(p), create);
            assert!(
                matches!(got, Err(ResolveError::OtherFileSystem)),
                "{p}: {got:?}"
            );
        }
    }
}

/// A bind mount beneath the root of a directory beside it, on the same
/// device: found by its mount ID on Linux 5.8 and later, on both ways, for
/// a directory on the way, a last component and a file bound over a file.
/// In a namespace (`unshare -Urm`), skipped where none can be made.
#[test]
fn a_bind_mount_beneath_the_root_is_another_file_system() {
    if !in_child() {
        in_namespace("resolver::tests::a_bind_mount_beneath_the_root_is_another_file_system");
        return;
    }
    let s = Scratch::new();
    fs::create_dir(s.at("b")).unwrap();
    fs::write(s.at("f"), b"inside").unwrap();
    fs::write(s.base.join("g"), b"outside").unwrap();
    let bind = OsStr::new("--bind");
    let _b = Mount::new(&[bind, s.outside().as_os_str()], &s.at("b")).unwrap();
    let _f = Mount::new(&[bind, s.base.join("g").as_os_str()], &s.at("f")).unwrap();
    assert_eq!(
        fs::metadata(s.at("b")).unwrap().dev(),
        fs::metadata(s.root()).unwrap().dev(),
        "a bind mount on the same device"
    );
    for root in roots(&s.root()) {
        let (top, b) = root.parent(&ip("b"), Create::No).unwrap();
        assert!(matches!(top.stat(&b), Err(ResolveError::OtherFileSystem)));
        let f = name("f");
        assert!(matches!(top.stat(&f), Err(ResolveError::OtherFileSystem)));
        assert!(matches!(
            top.open_file(&f, &some_file()),
            Err(ResolveError::OtherFileSystem)
        ));
        for (p, create) in [("b/made1/x", Create::Directories), ("b/x", Create::No)] {
            let got = root.parent(&ip(p), create);
            assert!(
                matches!(got, Err(ResolveError::OtherFileSystem)),
                "{p}: {got:?}"
            );
        }
    }
    assert!(s.outside_is_empty());
}

/// A file system that folds names (a casefold directory on tmpfs, Linux
/// 6.13 and later) takes case variants and names with ignorable characters
/// for the hidden directory; the policy refuses every one, and a root whose
/// hidden directory is removed and made again refuses until it is opened
/// again. In a namespace (`unshare -Urm`), skipped where none can be made.
#[test]
fn tm_4_hidden_directory_aliases_on_a_folding_file_system() {
    if !in_child() {
        in_namespace("resolver::tests::tm_4_hidden_directory_aliases_on_a_folding_file_system");
        return;
    }
    let s = Scratch::new();
    let mnt = s.base.join("casefold");
    fs::create_dir(&mnt).unwrap();
    let options = [
        OsStr::new("-t"),
        OsStr::new("tmpfs"),
        OsStr::new("-o"),
        OsStr::new("casefold"),
        OsStr::new("tmpfs"),
    ];
    let Some(_casefold) = Mount::new(&options, &mnt) else {
        eprintln!("skipped: this kernel's tmpfs has no casefold (Linux 6.13 and later)");
        return;
    };
    let folder = mnt.join("root");
    fs::create_dir(&folder).unwrap();
    match Command::new("chattr").arg("+F").arg(&folder).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let why = String::from_utf8_lossy(&out.stderr);
            eprintln!("skipped: chattr +F fails here: {}", why.trim());
            return;
        }
        Err(e) => {
            eprintln!("skipped: no chattr here: {e}");
            return;
        }
    }
    let both = roots(&folder);
    let hidden = fs::metadata(folder.join(HIDDEN_DIR)).unwrap().ino();
    for alias in [
        ".LicketySync",
        ".lick\u{200C}etysync",
        ".licketysync\u{FEFF}",
        ".licketysync\u{AD}",
        ".licketyſync",
    ] {
        // The policy refuses it, at the root and deeper, whether or not this
        // kernel folds it...
        for p in [format!("{alias}/tmp0/x"), format!("a/{alias}/x")] {
            assert_eq!(POLICY.index_path(&p), Err(NameError::Hidden), "{alias:?}");
        }
        // ...and this kernel takes it for the hidden directory, or says so.
        match fs::symlink_metadata(folder.join(alias)) {
            Ok(meta) if meta.ino() == hidden => {}
            _ => eprintln!("this kernel does not fold {alias:?} onto {HIDDEN_DIR}"),
        }
    }
    let (looked, aliases) = sweep(&folder, hidden);
    eprintln!("swept {looked} names; this kernel folds {aliases} onto {HIDDEN_DIR}");
    assert!(aliases > 0, "the casefold directory folds nothing");
    // The hidden directory removed and made again while the roots are open.
    fs::remove_dir(folder.join(HIDDEN_DIR)).unwrap();
    fs::create_dir(folder.join(".LicketySync")).unwrap();
    for root in &both {
        let got = root.parent(&ip("tmp0/x"), Create::Directories);
        assert!(matches!(got, Err(ResolveError::RootChanged)), "{got:?}");
    }
    assert!(!folder.join("tmp0").exists());
    assert!(
        fs::read_dir(folder.join(HIDDEN_DIR))
            .unwrap()
            .next()
            .is_none()
    );
}

/// An oracle apart from the policy: every name the kernel takes for the
/// hidden directory, among those made from `.licketysync` and each code point
/// of U+0020 to U+2FFFF and U+E0000 to U+E0FFF (put before it, after it,
/// after `.lick`, and in place of each of its characters), must be refused by
/// every policy, as an index path's component and as a disk name. Returns how
/// many names it looked at and how many the kernel folded.
fn sweep(root: &Path, hidden: u64) -> (usize, usize) {
    let dir = rustix::fs::open(root, DIRECTORY, Mode::empty()).unwrap();
    let base: Vec<char> = HIDDEN_DIR.chars().collect();
    let points = (0x20..=0x2_FFFF).chain(0xE_0000..=0xE_0FFF);
    let (mut looked, mut aliases) = (0, 0);
    for c in points.filter_map(char::from_u32).filter(|c| *c != '/') {
        let mut names = vec![
            format!("{c}{HIDDEN_DIR}"),
            format!("{HIDDEN_DIR}{c}"),
            format!(".lick{c}etysync"),
        ];
        for i in 0..base.len() {
            let mut swapped = base.clone();
            swapped[i] = c;
            names.push(swapped.into_iter().collect());
        }
        for n in names {
            looked += 1;
            let Ok(st) =
                rustix::fs::statat(&dir, n.as_str(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            else {
                continue;
            };
            if st.st_ino != hidden {
                continue;
            }
            aliases += 1;
            for policy in [NamePolicy::Linux, NamePolicy::Macos, NamePolicy::Windows] {
                assert!(policy.name(&n).is_err(), "{policy:?} admits {n:?}");
                assert!(
                    policy.from_disk(n.as_bytes()).is_err(),
                    "{policy:?} reads {n:?}"
                );
            }
        }
    }
    (looked, aliases)
}

/// What a root checks on each call: the hidden directory's name leads to a
/// directory of the identity it holds, and the directory held is still
/// linked (one removed, whose inode number another took, is not), where its
/// file system counted links when the root opened.
#[test]
fn the_hidden_directory_held_must_still_be_linked() {
    use super::unix::still_held;
    let id = FileId { dev: 1, ino: 7 };
    let held = meta(id, Some(30));
    assert!(still_held(Some(&held), &held, id, true));
    let removed = Meta {
        nlink: 0,
        ..meta(id, Some(30))
    };
    assert!(!still_held(Some(&held), &removed, id, true));
    // A file system that reports no links, at open and since: not counted.
    assert!(still_held(Some(&removed), &removed, id, false));
    assert!(super::unix::counts_links(&held));
    assert!(!super::unix::counts_links(&removed));
    assert!(!still_held(None, &held, id, true));
    let other = meta(FileId { dev: 1, ino: 8 }, Some(30));
    assert!(!still_held(Some(&other), &held, id, true));
    let file = Meta {
        file_type: FileType::RegularFile,
        ..meta(id, Some(30))
    };
    assert!(!still_held(Some(&file), &held, id, true));
}

/// The hidden directory must be this user's, and only its owner may write
/// it: the decision, on stub metadata.
#[test]
fn the_hidden_directory_must_be_this_users_and_private() {
    use super::unix::{owned_by, private};
    let ours = Meta {
        uid: 1000,
        mode: 0o700,
        ..meta(FileId { dev: 1, ino: 7 }, Some(30))
    };
    assert!(owned_by(&ours, 1000).is_ok());
    assert!(matches!(
        owned_by(&ours, 1001),
        Err(OpenError::HiddenNotOwned)
    ));
    assert!(private(&ours).is_ok());
    for mode in [0o500, 0o711, 0o755, 0o1700] {
        assert!(private(&Meta { mode, ..ours }).is_ok(), "{mode:o}");
    }
    for mode in [0o720, 0o702, 0o777, 0o770] {
        assert!(
            matches!(
                private(&Meta { mode, ..ours }),
                Err(OpenError::HiddenWritable)
            ),
            "{mode:o}"
        );
    }
}

/// A hidden directory another user owns, such as one a local user who can
/// write the folder swapped in: refused. In a namespace (`unshare -Urm`),
/// where a directory of the host's root shows as `nobody`, bound in as the
/// hidden directory; skipped where none can be made.
#[test]
fn a_hidden_directory_of_another_user_is_refused() {
    if !in_child() {
        in_namespace("resolver::tests::a_hidden_directory_of_another_user_is_refused");
        return;
    }
    let s = Scratch::new();
    fs::create_dir(s.at(HIDDEN_DIR)).unwrap();
    let foreign = Path::new("/usr");
    let owner = fs::metadata(foreign).unwrap().uid();
    assert_ne!(
        owner,
        rustix::process::geteuid().as_raw(),
        "/usr must be another user's"
    );
    let bind = OsStr::new("--bind");
    let _m = Mount::new(&[bind, foreign.as_os_str()], &s.at(HIDDEN_DIR)).unwrap();
    let got = Root::open(&s.root(), POLICY);
    assert!(matches!(got, Err(OpenError::HiddenNotOwned)), "{got:?}");
}

#[test]
fn dot_dot_and_absolute_components_never_reach_the_resolver() {
    for p in [
        "..",
        "../x",
        "a/../../x",
        "/etc/passwd",
        "a//b",
        "./a",
        "a/.",
        "a\\..\\b",
    ] {
        assert!(POLICY.index_path(p).is_err(), "{p}");
    }
    for raw in [&b".."[..], b".", b"/", b"a/../b"] {
        assert!(POLICY.from_disk(raw).is_err(), "{raw:?}");
    }
    // Three dots is an ordinary name.
    let s = Scratch::new();
    fs::create_dir(s.at("...")).unwrap();
    fs::write(s.at(".../f"), b"x").unwrap();
    for root in roots(&s.root()) {
        let (dir, f) = root.parent(&ip(".../f"), Create::No).unwrap();
        assert_eq!(dir.stat(&f).unwrap().unwrap().size, 1);
    }
}

/// The deepest path an index holds, 4 095 bytes in 2 048 components: made
/// and resolved one descriptor at a time, so no descriptor limit is reached.
#[test]
fn very_deep_paths_resolve() {
    let s = Scratch::new();
    let deepest = "a/".repeat(2047) + "b";
    assert_eq!(deepest.len(), 4095);
    for root in roots(&s.root()) {
        let (dir, b) = root.parent(&ip(&deepest), Create::Directories).unwrap();
        assert_eq!(dir.stat(&b).unwrap(), None);
        let (dir, a) = root
            .parent(&ip(&("a/".repeat(2046) + "a")), Create::No)
            .unwrap();
        assert_eq!(dir.stat(&a).unwrap().unwrap().kind, Kind::Directory);
    }
    assert!(POLICY.index_path(&("a/".repeat(2048) + "b")).is_err());
    flatten(&s.root());
}

/// Moves each directory of the chain `a/a/…` up to the root, so that the
/// scratch directory's removal never goes deep.
fn flatten(root: &Path) {
    let top = rustix::fs::open(root, DIRECTORY, Mode::empty()).unwrap();
    let mut at = rustix::fs::openat(&top, "a", DIRECTORY, Mode::empty()).unwrap();
    let mut n = 0;
    while let Ok(next) = rustix::fs::openat(&at, "a", DIRECTORY, Mode::empty()) {
        rustix::fs::renameat(&at, "a", &top, format!("level-{n}")).unwrap();
        at = next;
        n += 1;
    }
}

#[test]
fn another_folders_root_is_never_entered() {
    let s = Scratch::new();
    fs::create_dir_all(s.at("sub/.licketysync")).unwrap();
    fs::create_dir(s.at("sub/inner")).unwrap();
    fs::create_dir(s.at("plain")).unwrap();
    fs::write(s.at("plain/.licketysync"), b"a file makes no folder").unwrap();
    for root in roots(&s.root()) {
        for (p, create) in [
            ("sub/x", Create::No),
            ("sub/inner/x", Create::No),
            ("sub/new/x", Create::Directories),
        ] {
            let got = root.parent(&ip(p), create);
            assert!(
                matches!(got, Err(ResolveError::NestedFolder)),
                "{p}: {got:?}"
            );
        }
        // The other folder's root is a directory of this one.
        let (top, sub) = root.parent(&ip("sub"), Create::No).unwrap();
        assert_eq!(top.stat(&sub).unwrap().unwrap().kind, Kind::Directory);
        assert!(root.parent(&ip("plain/x"), Create::No).is_ok());
    }
    assert!(!s.at("sub/new").exists());
}

fn meta(id: FileId, mount: Option<u64>) -> Meta {
    Meta {
        file_type: FileType::Directory,
        id,
        mount,
        size: 0,
        mtime: Time { secs: 0, nanos: 0 },
        ctime: Time { secs: 0, nanos: 0 },
        mode: 0o755,
        nlink: 2,
        uid: 0,
    }
}

/// What a component is checked against: the root's device, its mount (where
/// the system reports one), and the hidden directory's identity, which a
/// file system can give a name the policy does not know.
#[test]
fn a_component_is_checked_for_its_mount_and_the_hidden_directory() {
    let hidden = FileId { dev: 1, ino: 7 };
    let bounds = Bounds {
        dev: 1,
        mount: Some(30),
        hidden: Some(hidden),
    };
    let other = FileId { dev: 1, ino: 8 };
    assert!(bounds.check(&meta(other, Some(30))).is_ok());
    for (id, mount) in [
        (other, Some(31)),
        (other, None),
        (FileId { dev: 2, ino: 8 }, Some(30)),
    ] {
        let got = bounds.check(&meta(id, mount));
        assert!(
            matches!(got, Err(ResolveError::OtherFileSystem)),
            "{id:?} {mount:?}"
        );
    }
    assert!(matches!(
        bounds.check(&meta(hidden, Some(30))),
        Err(ResolveError::HiddenDirectory)
    ));
    // Where the system reports no mount ID, the device alone decides.
    let unreported = Bounds {
        mount: None,
        ..bounds
    };
    assert!(unreported.check(&meta(other, None)).is_ok());
    assert!(matches!(
        unreported.check(&meta(FileId { dev: 2, ino: 8 }, None)),
        Err(ResolveError::OtherFileSystem)
    ));
}

#[test]
fn a_root_makes_its_hidden_directory_and_holds_it() {
    let s = Scratch::new();
    let root = Root::open(&s.root(), POLICY).unwrap();
    let made = fs::symlink_metadata(s.at(HIDDEN_DIR)).unwrap();
    assert!(made.is_dir());
    assert_eq!(made.mode() & 0o777, 0o700);
    fs::write(s.at(".licketysync/marker"), b"m").unwrap();
    let hidden = root.hidden_dir().unwrap();
    assert_eq!(hidden.stat(&name("marker")).unwrap().unwrap().size, 1);
    // A second root takes the one that is there.
    fs::set_permissions(s.at(HIDDEN_DIR), Permissions::from_mode(0o755)).unwrap();
    let again = Root::open(&s.root(), POLICY).unwrap();
    // A looser mode, as a copy may leave, is narrowed.
    assert_eq!(
        fs::symlink_metadata(s.at(HIDDEN_DIR)).unwrap().mode() & 0o7777,
        0o700
    );
    // A tighter one is left as it is.
    fs::set_permissions(s.at(HIDDEN_DIR), Permissions::from_mode(0o500)).unwrap();
    drop(Root::open(&s.root(), POLICY).unwrap());
    assert_eq!(
        fs::symlink_metadata(s.at(HIDDEN_DIR)).unwrap().mode() & 0o7777,
        0o500
    );
    fs::set_permissions(s.at(HIDDEN_DIR), Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        again
            .hidden_dir()
            .unwrap()
            .stat(&name("marker"))
            .unwrap()
            .unwrap()
            .size,
        1
    );
}

/// The hidden directory removed, made again, or moved away and back while
/// the root is open: the root refuses from the first time it sees it, for
/// good, until it is opened again.
#[test]
fn a_hidden_directory_removed_or_replaced_makes_the_root_refuse() {
    let s = Scratch::new();
    for root in roots(&s.root()) {
        assert!(root.parent(&ip("x"), Create::No).is_ok());
        fs::rename(s.at(HIDDEN_DIR), s.at("away")).unwrap();
        assert!(matches!(
            root.parent(&ip("x"), Create::No),
            Err(ResolveError::RootChanged)
        ));
        // Back again, the same directory: the root still refuses.
        fs::rename(s.at("away"), s.at(HIDDEN_DIR)).unwrap();
        assert!(matches!(
            root.parent(&ip("x"), Create::No),
            Err(ResolveError::RootChanged)
        ));
        assert!(matches!(root.hidden_dir(), Err(ResolveError::RootChanged)));
    }
    let root = Root::open(&s.root(), POLICY).unwrap();
    fs::remove_dir(s.at(HIDDEN_DIR)).unwrap();
    fs::create_dir(s.at(HIDDEN_DIR)).unwrap();
    assert!(matches!(root.hidden_dir(), Err(ResolveError::RootChanged)));
    assert!(matches!(
        root.parent(&ip("p/x"), Create::Directories),
        Err(ResolveError::RootChanged)
    ));
    assert!(!s.at("p").exists());
    // Opened again, it takes the new one.
    let reopened = Root::open(&s.root(), POLICY).unwrap();
    assert!(reopened.parent(&ip("p/x"), Create::Directories).is_ok());
}

#[test]
fn a_root_opens_only_with_a_hidden_directory_of_its_own() {
    let linked = Scratch::new();
    symlink(linked.outside(), linked.at(HIDDEN_DIR)).unwrap();
    assert!(matches!(
        Root::open(&linked.root(), POLICY),
        Err(OpenError::Hidden)
    ));
    assert!(linked.outside_is_empty());
    let file = Scratch::new();
    fs::write(file.at(HIDDEN_DIR), b"").unwrap();
    assert!(matches!(
        Root::open(&file.root(), POLICY),
        Err(OpenError::Hidden)
    ));
    // A file is no root, nor is nothing.
    let not_dir = Root::open(&file.at(HIDDEN_DIR), POLICY);
    assert!(
        matches!(&not_dir, Err(OpenError::Io(e)) if e.raw_os_error() == Some(Errno::NOTDIR.raw_os_error()))
    );
    let missing = Root::open(&file.at("missing"), POLICY);
    assert!(matches!(&missing, Err(OpenError::Io(e)) if e.kind() == ErrorKind::NotFound));
    // A root where the hidden directory cannot be made. Skipped where the
    // tests run with privileges that write anyway.
    let locked = Scratch::new();
    fs::set_permissions(locked.root(), Permissions::from_mode(0o500)).unwrap();
    if fs::create_dir(locked.at("probe")).is_err() {
        let got = Root::open(&locked.root(), POLICY);
        assert!(
            matches!(&got, Err(OpenError::Io(e)) if e.kind() == ErrorKind::PermissionDenied),
            "{got:?}"
        );
    }
    fs::set_permissions(locked.root(), Permissions::from_mode(0o700)).unwrap();
}

/// The person's path to the root may lead through links: it is their choice.
#[test]
fn the_root_itself_is_reached_through_a_link() {
    let s = Scratch::new();
    fs::write(s.at("f"), b"x").unwrap();
    symlink(s.root(), s.base.join("link")).unwrap();
    let root = Root::open(&s.base.join("link"), POLICY).unwrap();
    assert_eq!(root.policy(), POLICY);
    let (dir, f) = root.parent(&ip("f"), Create::No).unwrap();
    assert_eq!(dir.stat(&f).unwrap().unwrap().size, 1);
}

#[test]
fn a_file_is_examined_and_opened_as_it_was_found() {
    let s = Scratch::new();
    fs::create_dir(s.at("d")).unwrap();
    fs::write(s.at("d/f"), b"hello").unwrap();
    fs::set_permissions(s.at("d/f"), Permissions::from_mode(0o640)).unwrap();
    let meta = fs::metadata(s.at("d/f")).unwrap();
    for root in roots(&s.root()) {
        let (dir, f) = root.parent(&ip("d/f"), Create::No).unwrap();
        let e = dir.stat(&f).unwrap().unwrap();
        assert_eq!(e.kind, Kind::File);
        assert_eq!(e.size, 5);
        assert_eq!(e.mode, 0o640);
        assert_eq!(e.nlink, 1);
        assert_eq!(
            e.id,
            FileId {
                dev: meta.dev(),
                ino: meta.ino()
            }
        );
        let time = |secs: i64, nanos: i64| Time {
            secs,
            nanos: u32::try_from(nanos).unwrap(),
        };
        assert_eq!(e.mtime, time(meta.mtime(), meta.mtime_nsec()));
        assert_eq!(e.ctime, time(meta.ctime(), meta.ctime_nsec()));
        let mut text = String::new();
        dir.open_file(&f, &e)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "hello");
        // A directory is examined, never opened as a file.
        let (top, d) = root.parent(&ip("d"), Create::No).unwrap();
        let de = top.stat(&d).unwrap().unwrap();
        assert_eq!(de.kind, Kind::Directory);
        assert_eq!(de.mode, fs::metadata(s.at("d")).unwrap().mode() & 0o7777);
        assert!(matches!(top.open_file(&d, &de), Err(ResolveError::Changed)));
        // Nothing there.
        assert_eq!(dir.stat(&name("none")).unwrap(), None);
        assert!(matches!(
            dir.open_file(&name("none"), &e),
            Err(ResolveError::NotFound)
        ));
    }
    // A second name: the link count says so, and the file is changed.
    let root = Root::open(&s.root(), POLICY).unwrap();
    let (dir, f) = root.parent(&ip("d/f"), Create::No).unwrap();
    let before = dir.stat(&f).unwrap().unwrap();
    fs::hard_link(s.at("d/f"), s.base.join("other-name")).unwrap();
    let after = dir.stat(&f).unwrap().unwrap();
    assert_eq!(after.nlink, 2);
    assert!(matches!(
        dir.open_file(&f, &before),
        Err(ResolveError::Changed)
    ));
}

#[test]
fn a_file_replaced_or_changed_since_it_was_examined_is_not_opened() {
    let s = Scratch::new();
    fs::write(s.at("f"), b"one").unwrap();
    for root in roots(&s.root()) {
        let (dir, f) = root.parent(&ip("f"), Create::No).unwrap();
        // Replaced: another file by the same name.
        let before = dir.stat(&f).unwrap().unwrap();
        fs::write(s.at("g"), b"two").unwrap();
        fs::rename(s.at("g"), s.at("f")).unwrap();
        assert!(matches!(
            dir.open_file(&f, &before),
            Err(ResolveError::Changed)
        ));
        // Changed in place: the same file, another size.
        let before = dir.stat(&f).unwrap().unwrap();
        fs::write(s.at("f"), b"three").unwrap();
        assert!(matches!(
            dir.open_file(&f, &before),
            Err(ResolveError::Changed)
        ));
        // Another mode or link count than it was examined with.
        let now = dir.stat(&f).unwrap().unwrap();
        let mut moded = now;
        moded.mode ^= 0o077;
        assert!(matches!(
            dir.open_file(&f, &moded),
            Err(ResolveError::Changed)
        ));
        let mut linked = now;
        linked.nlink += 1;
        assert!(matches!(
            dir.open_file(&f, &linked),
            Err(ResolveError::Changed)
        ));
        assert!(dir.open_file(&f, &now).is_ok());
        // Replaced by a link: never opened.
        let before = dir.stat(&f).unwrap().unwrap();
        fs::remove_file(s.at("f")).unwrap();
        symlink(s.outside(), s.at("f")).unwrap();
        assert!(matches!(
            dir.open_file(&f, &before),
            Err(ResolveError::Symlink)
        ));
        fs::remove_file(s.at("f")).unwrap();
        fs::write(s.at("f"), b"one").unwrap();
    }
}

#[test]
fn missing_directories_are_made_only_when_asked() {
    let s = Scratch::new();
    for root in roots(&s.root()) {
        assert!(matches!(
            root.parent(&ip("p/q/r"), Create::No),
            Err(ResolveError::NotFound)
        ));
        assert!(!s.at("p").exists());
        let (dir, r) = root.parent(&ip("p/q/r"), Create::Directories).unwrap();
        assert!(s.at("p/q").is_dir());
        assert_eq!(dir.stat(&r).unwrap(), None);
        fs::write(s.at("p/q/r"), b"x").unwrap();
        assert_eq!(dir.stat(&r).unwrap().unwrap().size, 1);
        // Made already: found, not made again.
        assert!(root.parent(&ip("p/q/r"), Create::Directories).is_ok());
        fs::remove_dir_all(s.at("p")).unwrap();
    }
}

/// A directory that cannot be written: making one in it is the system's
/// refusal. Skipped where the tests run with privileges that write anyway.
#[test]
fn a_directory_that_cannot_be_made_is_the_systems_refusal() {
    let s = Scratch::new();
    fs::create_dir(s.at("ro")).unwrap();
    fs::set_permissions(s.at("ro"), Permissions::from_mode(0o500)).unwrap();
    let privileged = fs::create_dir(s.at("ro/probe")).is_ok();
    if !privileged {
        for root in roots(&s.root()) {
            let got = root.parent(&ip("ro/new/x"), Create::Directories);
            assert!(
                matches!(&got, Err(ResolveError::Io(e)) if e.kind() == ErrorKind::PermissionDenied),
                "{got:?}"
            );
        }
    }
    fs::set_permissions(s.at("ro"), Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn a_file_on_the_way_is_not_a_directory() {
    let s = Scratch::new();
    fs::write(s.at("f"), b"").unwrap();
    for root in roots(&s.root()) {
        for create in [Create::No, Create::Directories] {
            let got = root.parent(&ip("f/x"), create);
            assert!(matches!(got, Err(ResolveError::NotADirectory)), "{got:?}");
        }
    }
}

#[test]
fn a_directory_lists_its_raw_names() {
    let s = Scratch::new();
    fs::write(s.at("b"), b"").unwrap();
    fs::create_dir(s.at("a")).unwrap();
    symlink(s.outside(), s.at("l")).unwrap();
    let mut want = vec![
        HIDDEN_DIR.as_bytes().to_vec(),
        b"a".to_vec(),
        b"b".to_vec(),
        b"l".to_vec(),
    ];
    // Linux takes any bytes but / and NUL in a name.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::ffi::OsStrExt;
        fs::write(s.root().join(OsStr::from_bytes(b"\xff")), b"").unwrap();
        want.push(vec![0xff]);
    }
    want.sort();
    for root in roots(&s.root()) {
        let (dir, _) = root.parent(&ip("x"), Create::No).unwrap();
        let mut names: Vec<Vec<u8>> = dir.entries().unwrap().map(Result::unwrap).collect();
        names.sort();
        assert_eq!(names, want);
    }
}

#[test]
fn a_path_from_another_policy_is_judged_by_the_roots() {
    let s = Scratch::new();
    let linux = Root::open(&s.root(), NamePolicy::Linux).unwrap();
    let windows = Root::open(&s.root(), NamePolicy::Windows).unwrap();
    assert_eq!(windows.policy(), NamePolicy::Windows);
    for p in ["d/CON", "CON/x"] {
        let con = NamePolicy::Linux.index_path(p).unwrap();
        let got = windows.parent(&con, Create::Directories);
        assert!(
            matches!(got, Err(ResolveError::Unstorable(NameError::Device))),
            "{p}: {got:?}"
        );
    }
    assert!(!s.at("d").exists());
    assert!(!s.at("CON").exists());
    let fine = NamePolicy::Windows.index_path("d/x").unwrap();
    let (_, x) = linux.parent(&fine, Create::Directories).unwrap();
    assert!(s.at("d").is_dir());
    assert_eq!(x.policy(), NamePolicy::Linux);
}

#[test]
fn a_name_from_another_policy_is_judged_by_the_directory_policy() {
    let s = Scratch::new();
    fs::write(s.at("CON"), b"c").unwrap();
    let windows = Root::open(&s.root(), NamePolicy::Windows).unwrap();
    let (dir, _) = windows.parent(&ip("x"), Create::No).unwrap();
    let con = NamePolicy::Linux.name("CON").unwrap();
    let refused = [
        dir.stat(&con).map(|_| ()),
        dir.open_file(&con, &some_file()).map(|_| ()),
    ];
    for got in refused {
        assert!(
            matches!(got, Err(ResolveError::Unstorable(NameError::Device))),
            "{got:?}"
        );
    }
    let x = NamePolicy::Linux.name("x").unwrap();
    assert_eq!(dir.stat(&x).unwrap(), None);
}

/// The kernel's answers, as the resolver reports them.
#[test]
fn system_errors_are_reported_as_what_they_mean() {
    use super::unix::classify;
    assert!(matches!(classify(Errno::LOOP), ResolveError::Symlink));
    assert!(matches!(classify(Errno::NOENT), ResolveError::NotFound));
    assert!(matches!(
        classify(Errno::XDEV),
        ResolveError::OtherFileSystem
    ));
    assert!(matches!(
        classify(Errno::NAMETOOLONG),
        ResolveError::Unstorable(NameError::TooLong)
    ));
    assert!(
        matches!(classify(Errno::ACCESS), ResolveError::Io(e) if e.kind() == ErrorKind::PermissionDenied)
    );
}

#[test]
fn every_refusal_says_why() {
    let resolve = [
        ResolveError::Unstorable(NameError::Device),
        ResolveError::NotFound,
        ResolveError::Symlink,
        ResolveError::NotADirectory,
        ResolveError::OtherFileSystem,
        ResolveError::Special,
        ResolveError::NestedFolder,
        ResolveError::HiddenDirectory,
        ResolveError::Changed,
        ResolveError::RootChanged,
        ResolveError::Io(std::io::Error::from(ErrorKind::PermissionDenied)),
    ];
    let open = [
        OpenError::Unsupported,
        OpenError::Hidden,
        OpenError::Io(std::io::Error::from(ErrorKind::NotFound)),
        OpenError::HiddenNotOwned,
        OpenError::HiddenWritable,
    ];
    let mut texts: Vec<String> = resolve.iter().map(ToString::to_string).collect();
    texts.extend(open.iter().map(ToString::to_string));
    let distinct: std::collections::BTreeSet<&String> = texts.iter().collect();
    assert_eq!(distinct.len(), texts.len());
    assert!(texts.iter().all(|t| !t.is_empty()));
    assert!(
        resolve[0]
            .to_string()
            .contains(&NameError::Device.to_string())
    );
    assert!(resolve[1].to_string().contains("file"));
    assert!(resolve[0].source().is_some());
    assert!(resolve[10].source().is_some());
    assert!(resolve[1].source().is_none());
    assert!(open[2].source().is_some());
    assert!(open[0].source().is_none());
    let from: ResolveError = std::io::Error::from(ErrorKind::Other).into();
    assert!(matches!(from, ResolveError::Io(_)));
}

/// Both Linux ways are taken: the root as it opens resolves by `openat2` on
/// this kernel, decided once when it opens, and the switched one by the walk
/// alone.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn both_linux_ways_are_taken() {
    let s = Scratch::new();
    fs::create_dir_all(s.at("a/b")).unwrap();
    symlink(s.outside(), s.at("l")).unwrap();
    let [fast, walking] = roots(&s.root());
    assert!(!fast.walks(), "this kernel refused openat2");
    assert!(walking.walks());
    fast.parent(&ip("a/b/x"), Create::No).unwrap();
    walking.parent(&ip("a/b/x"), Create::No).unwrap();
    assert!(!fast.walks());
    assert_eq!(fast.by_openat2(), 2);
    assert_eq!(walking.by_openat2(), 0);
    // A refusal by openat2 is the answer: no walk after it, and the root
    // keeps its way.
    for p in ["l/x", "missing/x"] {
        assert!(fast.parent(&ip(p), Create::No).is_err(), "{p}");
    }
    assert_eq!(fast.fell_back(), 0);
    assert!(!fast.walks());
}

/// Where Linux has no `statx` (before 4.11), `stat` gives the same: the
/// fallback's conversion, checked against `statx` here.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn stat_and_statx_agree() {
    use super::linux::meta_at;
    use super::unix::meta_from_stat;
    use std::os::fd::AsFd;
    let s = Scratch::new();
    fs::write(s.at("f"), b"four").unwrap();
    fs::set_permissions(s.at("f"), Permissions::from_mode(0o4751)).unwrap();
    fs::create_dir(s.at("d")).unwrap();
    let root = rustix::fs::open(s.root(), DIRECTORY, Mode::empty()).unwrap();
    for n in ["f", "d"] {
        let by_statx = meta_at(root.as_fd(), n).unwrap();
        let st = rustix::fs::statat(&root, n, rustix::fs::AtFlags::SYMLINK_NOFOLLOW).unwrap();
        let by_stat = meta_from_stat(&st).unwrap();
        assert_eq!(by_stat.file_type, by_statx.file_type, "{n}");
        assert_eq!(by_stat.id, by_statx.id, "{n}");
        assert_eq!(by_stat.size, by_statx.size, "{n}");
        assert_eq!(by_stat.mtime, by_statx.mtime, "{n}");
        assert_eq!(by_stat.ctime, by_statx.ctime, "{n}");
        assert_eq!(by_stat.mode, by_statx.mode, "{n}");
        assert_eq!(by_stat.nlink, by_statx.nlink, "{n}");
        assert_eq!(by_stat.mount, None);
        assert!(by_statx.mount.is_some(), "this kernel reports no mount ID");
    }
    assert_eq!(
        meta_from_stat(
            &rustix::fs::statat(&root, "f", rustix::fs::AtFlags::SYMLINK_NOFOLLOW).unwrap()
        )
        .unwrap()
        .mode,
        0o4751
    );
}
