/// fractal-demail: decentralized, gasless agent communication on Sui.
///
/// Phase 1 core objects:
/// - `Mailbox`: an agent's on-chain inbox descriptor. Carries a reserved
///   anti-spam bond field (not enforced in Phase 1; gateway-side allowlist
///   and rate limiting handle spam until bond economics are decided).
/// - `Message`: an encrypted envelope minted by the sender and transferred
///   to the recipient address. Payload is either inline ciphertext or an
///   off-chain reference (e.g. a Walrus blob id). Deleting a processed
///   message returns a storage gas rebate.
module fractal_demail::demail;

use sui::clock::Clock;
use sui::event;

/// Payload kind tag for inline encrypted payloads.
const KIND_INLINE: vector<u8> = b"inline";

/// An agent's on-chain inbox descriptor.
public struct Mailbox has key {
    id: UID,
    owner: address,
    /// Anti-spam bond in MIST required to send to this mailbox.
    /// Reserved for Phase 2; Phase 1 keeps it 0 and does not enforce it.
    required_bond: u64,
    /// Total messages this mailbox owner has burned (processed).
    processed_count: u64,
}

/// An encrypted message envelope.
public struct Message has key, store {
    id: UID,
    sender: address,
    /// Content kind tag, e.g. b"inline" or b"walrus".
    payload_kind: vector<u8>,
    /// Inline ciphertext, or an off-chain storage reference.
    payload: vector<u8>,
    created_at_ms: u64,
}

/// Emitted on every send; gateways (fractalbot) subscribe to this event
/// stream instead of polling.
public struct MessageSent has copy, drop {
    message_id: ID,
    sender: address,
    recipient: address,
    payload_kind: vector<u8>,
    created_at_ms: u64,
}

/// Create a mailbox for the transaction sender.
public fun create_mailbox(ctx: &mut TxContext) {
    let mailbox = Mailbox {
        id: object::new(ctx),
        owner: ctx.sender(),
        required_bond: 0,
        processed_count: 0,
    };
    transfer::transfer(mailbox, ctx.sender());
}

/// Mint a `Message` and transfer it to `recipient`.
/// Designed to run inside a sponsored transaction so zero-balance agent
/// addresses can send.
public fun send(
    recipient: address,
    payload_kind: vector<u8>,
    payload: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let message = Message {
        id: object::new(ctx),
        sender: ctx.sender(),
        payload_kind,
        payload,
        created_at_ms: clock.timestamp_ms(),
    };
    event::emit(MessageSent {
        message_id: object::id(&message),
        sender: message.sender,
        recipient,
        payload_kind: message.payload_kind,
        created_at_ms: message.created_at_ms,
    });
    transfer::public_transfer(message, recipient);
}

/// Convenience wrapper for small inline ciphertext payloads.
public fun send_inline(
    recipient: address,
    payload: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    send(recipient, KIND_INLINE, payload, clock, ctx)
}

/// Delete a processed message for a storage gas rebate, recording the
/// processing on the owner's mailbox.
public fun process(mailbox: &mut Mailbox, message: Message) {
    mailbox.processed_count = mailbox.processed_count + 1;
    burn(message)
}

/// Delete a processed message for a storage gas rebate.
public fun burn(message: Message) {
    let Message { id, sender: _, payload_kind: _, payload: _, created_at_ms: _ } = message;
    id.delete();
}

// === Read accessors ===

public fun sender(message: &Message): address { message.sender }

public fun payload_kind(message: &Message): vector<u8> { message.payload_kind }

public fun payload(message: &Message): vector<u8> { message.payload }

public fun created_at_ms(message: &Message): u64 { message.created_at_ms }

public fun owner(mailbox: &Mailbox): address { mailbox.owner }

public fun required_bond(mailbox: &Mailbox): u64 { mailbox.required_bond }

public fun processed_count(mailbox: &Mailbox): u64 { mailbox.processed_count }
