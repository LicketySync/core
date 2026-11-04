#![no_main]
//! wtransport-proto 0.7.2, the HTTP/3 and WebTransport framing beneath net's
//! WebTransport listener (feature `webtransport`, spike B), over bytes from a
//! peer: a stream header, then frames as a stream carries them; a HEADERS
//! frame goes through QPACK decoding into a session request, a SETTINGS frame
//! into settings. TM-3 and TM-23: none of it may panic.
use libfuzzer_sys::fuzz_target;
use wtransport_proto::bytes::BufferReader;
use wtransport_proto::frame::{Frame, FrameKind};
use wtransport_proto::headers::Headers;
use wtransport_proto::session::SessionRequest;
use wtransport_proto::settings::Settings;
use wtransport_proto::stream_header::StreamHeader;

fuzz_target!(|data: &[u8]| {
    let mut reader = BufferReader::new(data);
    let _ = StreamHeader::read_from_buffer(&mut reader);
    let mut reader = BufferReader::new(data);
    // Each frame read consumes at least its type and length, so this ends.
    while let Ok(Some(frame)) = Frame::read_from_buffer(&mut reader) {
        match frame.kind() {
            FrameKind::Headers => {
                if let Ok(headers) = Headers::with_frame(&frame) {
                    let _ = SessionRequest::try_from(headers);
                }
            }
            FrameKind::Settings => {
                let _ = Settings::with_frame(&frame);
            }
            _ => {}
        }
    }
});
