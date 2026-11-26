//! Agent audit checks, not application tests or an independent human review.
//! See review-2026-11-26-continuation.json for exact archive hashes and commands.
use phf_shared::{FmtConst, PhfHash};
use std::fmt;
use std::future::{Ready, ready};
use std::task::{Context, Poll, Waker};
use tower_layer::{Identity, Layer, Stack, layer_fn};
use tower_service::Service;

struct Const<'a, T: ?Sized>(&'a T);
impl<T: ?Sized + FmtConst> fmt::Display for Const<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt_const(f)
    }
}

#[test]
fn hostile_text_stays_inside_rust_literals() {
    let input = "\"; panic!(\"injected\"); //\n\\\0";
    assert_eq!(
        Const(input).to_string(),
        "\"\\\"; panic!(\\\"injected\\\"); //\\n\\\\\\0\""
    );
    assert_eq!(Const(&'\'').to_string(), "'\\\''");
    // A one-element tuple currently formats as a parenthesized expression.
    // Record the limitation instead of claiming exact tuple round-tripping.
    assert_eq!(Const(&(7u8,)).to_string(), "(7)");
}

#[test]
fn byte_reinterpretation_preserves_all_values_and_valid_bools() {
    for value in i8::MIN..=i8::MAX {
        let signed = phf_shared::hash(&[value], &42);
        let unsigned = phf_shared::hash(&[value as u8], &42);
        assert_eq!(
            (signed.g, signed.f1, signed.f2),
            (unsigned.g, unsigned.f1, unsigned.f2)
        );
    }
    for value in [false, true] {
        let boolean = phf_shared::hash(&[value], &42);
        let byte = phf_shared::hash(&[u8::from(value)], &42);
        assert_eq!(
            (boolean.g, boolean.f1, boolean.f2),
            (byte.g, byte.f1, byte.f2)
        );
    }
    fn require_hash<T: PhfHash>(_: &T) {}
    require_hash(&[true, false]);
}

#[test]
fn malformed_lookup_metadata_panics_without_unchecked_access() {
    let mut hashes = phf_shared::hash("metadata", &42);
    hashes.g = u32::MAX;
    hashes.f1 = u32::MAX;
    hashes.f2 = u32::MAX;
    assert!(std::panic::catch_unwind(|| phf_shared::get_index(&hashes, &[], 0)).is_err());
    assert!(std::panic::catch_unwind(|| phf_shared::get_index(&hashes, &[(0, 0)], 0)).is_err());
    assert_eq!(
        phf_shared::get_index(&hashes, &[(u32::MAX, u32::MAX)], 1),
        0
    );
    assert_eq!(
        phf_shared::ptrhash::fast_reduct32(u32::MAX, u32::MAX),
        u32::MAX - 1
    );
}

#[derive(Default)]
struct Echo {
    ready: bool,
    calls: usize,
}
impl Service<u8> for Echo {
    type Response = u8;
    type Error = ();
    type Future = Ready<Result<u8, ()>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), ()>> {
        self.ready = true;
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, input: u8) -> Self::Future {
        assert!(std::mem::take(&mut self.ready));
        self.calls += 1;
        ready(Ok(input))
    }
}

#[test]
fn reference_and_box_forward_to_the_same_ready_service() {
    let mut inner = Echo::default();
    let mut boxed: Box<&mut Echo> = Box::new(&mut inner);
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(boxed.poll_ready(&mut context), Poll::Ready(Ok(())));
    let mut future = boxed.call(42);
    assert_eq!(
        std::future::Future::poll(std::pin::Pin::new(&mut future), &mut context),
        Poll::Ready(Ok(42))
    );
    drop(boxed);
    assert_eq!(inner.calls, 1);
    assert!(!inner.ready);
}

fn suffix(text: &'static str) -> impl Layer<String, Service = String> {
    layer_fn(move |mut input: String| {
        input.push_str(text);
        input
    })
}

#[test]
fn layer_composition_preserves_documented_order() {
    assert_eq!(Identity::new().layer(String::from("x")), "x");
    assert_eq!(().layer(String::from("x")), "x");
    assert_eq!((suffix("a"),).layer(String::from("x")), "xa");
    assert_eq!(
        Stack::new(suffix("a"), suffix("b")).layer(String::from("x")),
        "xab"
    );
    assert_eq!((suffix("a"), suffix("b")).layer(String::from("x")), "xba");
    assert_eq!(
        (
            suffix("a"),
            suffix("b"),
            suffix("c"),
            suffix("d"),
            suffix("e"),
            suffix("f"),
            suffix("g"),
            suffix("h"),
            suffix("i"),
            suffix("j"),
            suffix("k"),
            suffix("l"),
            suffix("m"),
            suffix("n"),
            suffix("o"),
            suffix("p")
        )
            .layer(String::new()),
        "ponmlkjihgfedcba"
    );
}
