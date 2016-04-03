#[derive(Clone)]
pub enum Message {
    /// Start
    Start,
    /// P, G
    Handshake(Vec<u8>, Vec<u8>),
    /// ACK Message
    ACK,
    /// PK
    Exchange(Vec<u8>),
    /// IV, Ciphertext
    Message(Vec<u8>, Vec<u8>),
    /// P, G, PK
    HandshakeAll(Vec<u8>, Vec<u8>, Vec<u8>),
    /// PK, IV, Ciphertext
    MessageAll(Vec<u8>, Vec<u8>, Vec<u8>)
}
