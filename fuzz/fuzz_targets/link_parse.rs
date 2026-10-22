#![no_main]
//! A join link and a `.lskey` file. What parses writes back to a link and a
//! file that parse to the same key, addresses and certificate hash.
use libfuzzer_sys::fuzz_target;
use licketysync_keys::keystring::Link;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        for link in [Link::parse(text), Link::parse_file(text)]
            .into_iter()
            .flatten()
        {
            let written = link.to_text().expect("a parsed link writes back");
            let file = link.to_file().expect("and as a file");
            for again in [Link::parse(&written), Link::parse_file(&file)] {
                let again = again.expect("what was written parses");
                assert_eq!(again.addresses, link.addresses);
                assert_eq!(again.cert_hash, link.cert_hash);
                assert_eq!(*again.key.payload(), *link.key.payload());
            }
        }
    }
});
