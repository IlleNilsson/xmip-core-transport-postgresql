//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): this transport held to how long Xmip takes — the millisecond rule
//! (`CONTRIBUTING.md`, *Rust is here for one reason*). A plain `cargo test`
//! leaves it out; the landing runs it after every other test of the module,
//! alone, one test at a time
//! (`cargo test --test measured --all-features -- --test-threads=1`), so
//! what is measured is Xmip's work and not its neighbors':
//!
//! - a thousand inserts on one connection take a millisecond each at most;
//! - a thousand receives on one connection take a millisecond a query at
//!   most.
//!
//! Each the millisecond beyond the round's wakes, round by round beside a
//! plain wake, the fastest of five (`xcore::latency::Rounds`).

use std::assert_matches;
use std::time::Duration;

use postgresql::Event;
use transport::Transport;
use xcore::latency::Rounds;
use xmip_core_transport_postgresql::{PostgresTransport, accept_one, taken};

/// What an insert or a query wakes where a plain wake wakes one: the far
/// end at the query, and this end at its answer.
const WAKES: u32 = 2;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[test]
fn a_thousand_inserts_take_a_millisecond_each_at_most() {
    const SENDS: usize = 1000;
    let far_end = PostgresTransport::new("127.0.0.1:0", "orders", "xmip")
        .with_password("secret")
        .timing_out_after(secs(5));
    let (listener, address) = far_end.bind().expect("binding");
    let near = PostgresTransport::new(address, "orders", "xmip")
        .with_password("secret")
        .timing_out_after(secs(5));
    let sender = std::thread::spawn(move || {
        let mut rounds = Rounds::crossing(WAKES);
        for n in 0..SENDS {
            rounds.round(|| near.send("inbox/payload", n.to_string().as_bytes()))?;
        }
        Ok::<_, transport::TransportError>(rounds)
    });
    let mut session = accept_one(&far_end, &listener).expect("accepting");
    for n in 0..SENDS {
        let insert = session.next_insert().expect("insert").expect("one");
        let inserted = taken(&far_end, &session, insert).expect("the column's form");
        assert_eq!(inserted.bytes, n.to_string().as_bytes());
    }
    let rounds = sender.join().expect("thread").expect("sending");
    rounds.hold("an insert");
}

#[test]
fn a_thousand_receives_take_a_millisecond_a_query_at_most() {
    const RECEIVES: usize = 1000;
    let far_end = PostgresTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(5));
    let (listener, address) = far_end.bind().expect("binding");
    let near = PostgresTransport::new(address, "orders", "xmip").timing_out_after(secs(5));
    let receiver = std::thread::spawn(move || {
        let mut rounds = Rounds::crossing(WAKES);
        for _ in 0..RECEIVES {
            assert_eq!(rounds.round(|| near.receive())?.len(), 1);
        }
        Ok::<_, transport::TransportError>(rounds)
    });
    let mut session = accept_one(&far_end, &listener)
        .expect("a login")
        .with_table(&["id", "payload"], &[&[Some("1"), None]]);
    for _ in 0..RECEIVES {
        let event = session.next_event().expect("query");
        assert_matches!(event, Some(Event::Selected(_)), "{event:?}");
    }
    let rounds = receiver.join().expect("thread").expect("receiving");
    rounds.hold("a receive, a query");
}
