#[test_only]
module fractal_demail::demail_tests;

use fractal_demail::demail::{Self, Mailbox, Message};
use sui::clock;
use sui::test_scenario;

const ALICE: address = @0xA11CE;
const BOB: address = @0xB0B;

#[test]
fun send_receive_process_roundtrip() {
    let mut scenario = test_scenario::begin(BOB);
    demail::create_mailbox(scenario.ctx());

    scenario.next_tx(ALICE);
    let mut clock = clock::create_for_testing(scenario.ctx());
    clock.set_for_testing(42);
    demail::send_inline(BOB, b"ciphertext", &clock, scenario.ctx());

    scenario.next_tx(BOB);
    let mut mailbox = scenario.take_from_sender<Mailbox>();
    let message = scenario.take_from_sender<Message>();
    assert!(demail::sender(&message) == ALICE);
    assert!(demail::payload_kind(&message) == b"inline");
    assert!(demail::payload(&message) == b"ciphertext");
    assert!(demail::created_at_ms(&message) == 42);
    assert!(demail::processed_count(&mailbox) == 0);

    demail::process(&mut mailbox, message);
    assert!(demail::processed_count(&mailbox) == 1);

    scenario.return_to_sender(mailbox);
    clock.destroy_for_testing();
    scenario.end();
}

#[test]
fun mailbox_defaults_reserved_bond_zero() {
    let mut scenario = test_scenario::begin(BOB);
    demail::create_mailbox(scenario.ctx());

    scenario.next_tx(BOB);
    let mailbox = scenario.take_from_sender<Mailbox>();
    assert!(demail::owner(&mailbox) == BOB);
    assert!(demail::required_bond(&mailbox) == 0);
    scenario.return_to_sender(mailbox);
    scenario.end();
}
