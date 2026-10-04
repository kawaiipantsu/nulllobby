//! Synthetic valid inputs so fuzzers reach beyond version/length checks.
use nulllobby_core::{
    EphemeralIdentity, LobbyCard, TransportKind,
    governance::RotationOffer,
    membership::{EnrollmentRequest, OrganizationAuthority},
    message::{Packet, Payload, SignedMessage},
    text::ValidatedText,
};
fn save(target: &str, name: &str, bytes: &[u8]) {
    let dir = std::path::Path::new("fuzz/corpus").join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), bytes).unwrap();
}
fn main() {
    use secrecy::ExposeSecret;
    let old = LobbyCard::private(TransportKind::Direct, vec![]).unwrap();
    let id = EphemeralIdentity::generate(old.lobby_id()).unwrap();
    let request = EnrollmentRequest::new(&id, 1000).unwrap();
    let issuer = OrganizationAuthority::generate().unwrap();
    save("membership", "request", &request.encode().unwrap());
    save(
        "membership",
        "credential",
        &issuer
            .issue(&request, "Synthetic Fuzz", "member", 1000, 3600)
            .unwrap()
            .encode()
            .unwrap(),
    );
    let next = LobbyCard::private(TransportKind::Direct, vec![]).unwrap();
    let offer = RotationOffer::new(&id, [2; 32], 1, 1200, &next).unwrap();
    save("rotation", "offer", &offer.encode().unwrap());
    save(
        "application",
        "rotation",
        &Packet::Rotation(offer).encode().unwrap(),
    );
    let message = SignedMessage::new(
        &id,
        1,
        Payload::DurableChat {
            body: ValidatedText::new("synthetic fuzz only").unwrap(),
            created: 1000,
            expires: 2000,
        },
    )
    .unwrap();
    save(
        "application",
        "durable",
        &Packet::Signed(message).encode().unwrap(),
    );
    save(
        "vault",
        "empty",
        &[0x87, 1, 0, 0x80, 0x80, 0x80, 0x80, 0x40],
    );
    let mut issuer_seed = vec![0x87, 1, 0, 0x80, 0x80, 0x80, 0x80, 0x58, 0x20];
    issuer_seed.extend_from_slice(&[0x42; 32]);
    save("vault", "issuer", &issuer_seed);
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(7)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(1000)
        .unwrap()
        .array(1)
        .unwrap()
        .array(7)
        .unwrap()
        .bytes(old.lobby_id().as_bytes())
        .unwrap()
        .bytes(id.persistence_seed().unwrap().expose_secret())
        .unwrap()
        .str(old.export().expose_secret())
        .unwrap()
        .str("synthetic profile")
        .unwrap()
        .u64(4096)
        .unwrap()
        .bool(false)
        .unwrap()
        .bool(false)
        .unwrap()
        .array(0)
        .unwrap()
        .array(0)
        .unwrap()
        .array(0)
        .unwrap()
        .bytes(&[])
        .unwrap();
    let snapshot = e.into_writer();
    nulllobby_store::validate_snapshot(&snapshot).unwrap();
    save("vault", "profile", &snapshot);
}
