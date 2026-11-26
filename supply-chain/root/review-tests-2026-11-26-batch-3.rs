// Synthetic source-review checks; compiled by review-tests-2026-11-26-batch-3.mjs.
// These are not full upstream suites, Miri, a timing proof, or cross-target CI.
#![allow(dead_code)]

use enumflags2::{bitflags, BitFlags};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

struct Noop;
impl Wake for Noop {
    fn wake(self: Arc<Self>) {}
}

fn complete<T>(future: impl Future<Output = T>) -> T {
    let waker = Waker::from(Arc::new(Noop));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    for _ in 0..1024 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
    panic!("synthetic immediately-ready future did not finish");
}

#[bitflags(default = A)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum Sparse {
    A = 1,
    B = 4,
    C = 128,
}

#[test]
fn flag_masks_never_produce_invalid_discriminants() {
    assert_eq!(BitFlags::<Sparse>::default().bits(), 1);
    for bits in 0..=u8::MAX {
        let flags = BitFlags::<Sparse>::from_bits_truncate(bits);
        assert_eq!(flags.bits(), bits & 0x85);
        assert_eq!(
            BitFlags::<Sparse>::from_bits(bits).is_ok(),
            bits & !0x85 == 0
        );
        let actual: Vec<u8> = flags.iter().map(|flag| flag as u8).collect();
        let expected: Vec<u8> = [1, 4, 128]
            .into_iter()
            .filter(|flag| bits & flag != 0)
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(flags.exactly_one().map(|f| f as u8), {
            if expected.len() == 1 {
                Some(expected[0])
            } else {
                None
            }
        });
        assert_eq!((!flags).bits(), !bits & 0x85);
        assert!(
            serde_json::from_str::<BitFlags<Sparse>>(&bits.to_string()).is_ok()
                == (bits & !0x85 == 0)
        );
        for other in 0..=u8::MAX {
            let rhs = BitFlags::<Sparse>::from_bits_truncate(other);
            assert_eq!((flags | rhs).bits(), (bits | other) & 0x85);
            assert_eq!((flags & rhs).bits(), (bits & other) & 0x85);
            assert_eq!((flags ^ rhs).bits(), (bits ^ other) & 0x85);
        }
    }
}

const HIGH: u128 = 1 << 127;
#[bitflags]
#[repr(u128)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum Wide {
    High = HIGH,
    Inferred,
}

#[test]
fn deferred_and_inferred_discriminants_keep_the_unsafe_contract() {
    assert_eq!(Wide::Inferred as u128, 1);
    let flags: BitFlags<Wide> = Wide::High | Wide::Inferred;
    assert_eq!(
        flags.iter().map(|f| f as u128).collect::<Vec<_>>(),
        vec![1, HIGH]
    );
    const ONLY_HIGH: BitFlags<Wide> =
        BitFlags::<Wide>::from_bits_truncate_c(HIGH | 2, BitFlags::CONST_TOKEN);
    assert_eq!(ONLY_HIGH.exactly_one(), Some(Wide::High));
}

#[async_recursion::async_recursion(?Send)]
async fn borrowed_sum<'a>(values: &'a [u32]) -> u32 {
    match values.split_first() {
        None => 0,
        Some((head, tail)) => *head + borrowed_sum(tail).await,
    }
}

#[async_recursion::async_recursion(Sync)]
async fn generic_identity<T: Send + Sync>(value: T) -> T {
    value
}

#[test]
fn recursive_expansion_preserves_borrows_and_thread_bounds() {
    assert_eq!(complete(borrowed_sum(&[3, 5, 8])), 16);
    fn check<T: Send + Sync>(value: T) -> T {
        value
    }
    assert_eq!(
        complete(check(generic_identity(String::from("synthetic")))),
        "synthetic"
    );
}

#[test]
fn float_formatting_handles_extremes_and_generated_bit_patterns() {
    let mut bits = 0x719d_35f8_a24c_b601_u64;
    for _ in 0..25000 {
        bits = bits.wrapping_mul(6364136223846793005).wrapping_add(1);
        for value in [f64::from_bits(bits), f32::from_bits(bits as u32) as f64] {
            if value.is_finite() {
                let mut output = String::new();
                dtoa_short::write(&mut output, value).unwrap();
                assert!(output.is_ascii());
                let parsed: f64 = output.parse().unwrap();
                let tolerance = value.abs() * 1e-12 + f64::from_bits(1) * 2.0;
                assert!((parsed - value).abs() <= tolerance);
            }
        }
        let value = f32::from_bits(bits as u32);
        if value.is_finite() {
            let mut output = String::new();
            dtoa_short::write(&mut output, value).unwrap();
            assert!(output.is_ascii());
            let parsed: f64 = output.parse().unwrap();
            assert!((parsed - value as f64).abs() <= (value as f64).abs() * 1e-5 + 1e-45);
        }
    }
    for value in [
        0.0_f64,
        -0.0,
        f64::MIN,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::from_bits(1),
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ] {
        let mut output = String::new();
        dtoa_short::write(&mut output, value).unwrap();
        assert!(output.is_ascii());
    }
}

#[test]
fn comparison_checks_all_offsets_tails_and_difference_positions() {
    for offset in 0..32 {
        for len in 0..=257 {
            let left: Vec<u8> = (0..len + offset).map(|n| n as u8).collect();
            let mut right = left.clone();
            assert!(constant_time_eq::constant_time_eq(
                &left[offset..],
                &right[offset..]
            ));
            assert!(constant_time_eq::generic::constant_time_eq(
                &left[offset..],
                &right[offset..]
            ));
            for index in offset..left.len() {
                right[index] ^= 0x80;
                assert!(!constant_time_eq::constant_time_eq(
                    &left[offset..],
                    &right[offset..]
                ));
                assert!(!constant_time_eq::generic::constant_time_eq(
                    &left[offset..],
                    &right[offset..]
                ));
                right[index] ^= 0x80;
            }
            if len > 0 {
                assert!(!constant_time_eq::constant_time_eq(
                    &left[offset..],
                    &right[offset + 1..]
                ));
            }
        }
    }
    assert!(constant_time_eq::constant_time_eq_16(&[7; 16], &[7; 16]));
    assert!(!constant_time_eq::constant_time_eq_32(&[7; 32], &[8; 32]));
    assert!(constant_time_eq::constant_time_eq_64(&[7; 64], &[7; 64]));
}

static MAP: phf::Map<&'static str, u32> = phf::phf_map! {
    "first" | "alias" => 1,
    #[cfg(any())]
    "disabled" => 99,
    "\"}; compile_error!(\"data\"); //" => 2,
};
static ORDERED: phf::OrderedMap<&'static str, u32> = phf::phf_ordered_map! {
    "z" => 1, "a" => 2, "m" => 3,
};
include!(concat!(env!("OUT_DIR"), "/review-generated.rs"));

#[test]
fn static_tables_reject_nonmembers_and_keep_generated_literals_as_data() {
    assert_eq!(MAP.get("alias"), Some(&1));
    assert_eq!(MAP.get("disabled"), None);
    assert_eq!(MAP.get("\"}; compile_error!(\"data\"); //"), Some(&2));
    assert_eq!(MAP.get("other"), None);
    assert_eq!(
        ORDERED.keys().copied().collect::<Vec<_>>(),
        vec!["z", "a", "m"]
    );
    assert_eq!(ORDERED.index(usize::MAX), None);
    assert_eq!(
        GENERATED.get("\"}; compile_error!(\"data\"); //"),
        Some(&41)
    );
    assert_eq!(phf::Map::<&str, ()>::new().get("anything"), None);
}

#[test]
fn layouts_and_packed_spans_match_the_modern_compiler() {
    #[repr(C, packed)]
    struct Packed {
        a: u8,
        b: u64,
        c: u16,
    }
    assert_eq!(memoffset::offset_of!(Packed, b), 1);
    assert_eq!(
        memoffset::offset_of!(Packed, b),
        core::mem::offset_of!(Packed, b)
    );
    assert_eq!(memoffset::span_of!(Packed, b..=c), 1..11);
    assert_eq!(memoffset::span_of!(Packed, ..), 0..11);
}

#[test]
fn byte_hashing_handles_all_short_suffix_boundaries() {
    use std::hash::Hasher;
    for len in 0..512 {
        let bytes: Vec<u8> = (0..len).map(|n| (n * 31) as u8).collect();
        let mut a = rustc_hash::FxHasher::with_seed(7);
        let mut b = a.clone();
        a.write(&bytes);
        b.write(&bytes);
        assert_eq!(a.finish(), b.finish());
    }
}

#[test]
fn deferred_broadcast_zero_capacity_issue_is_reproducible() {
    let (mut sender, _receiver) = async_broadcast::broadcast(1);
    sender.set_capacity(0);
    sender.set_overflow(true);
    for value in 0..32 {
        sender.try_broadcast(value).unwrap();
    }
    // A confirmed reason to leave this package unaudited, not expected product behavior.
    assert_eq!(sender.capacity(), 0);
    assert_eq!(sender.len(), 32);
}

#[derive(zvariant::Value)]
struct Pair {
    a: u32,
    b: u32,
}

#[test]
fn deferred_value_conversion_panics_on_short_untrusted_structure() {
    let value = zvariant::Value::from(zvariant::Structure::from((7_u32,)));
    // Expected repro of the generated unchecked remove(0), not an approved decoder.
    assert!(std::panic::catch_unwind(|| Pair::try_from(value)).is_err());
}

#[test]
fn ordered_join_sorts_items_but_has_the_recorded_hint_limitation() {
    use ordered_stream::{MaybeBorrowed, OrderedStream, PollResult};
    struct Sequence(std::collections::VecDeque<u32>);
    impl OrderedStream for Sequence {
        type Ordering = u32;
        type Data = u32;
        fn poll_next_before(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: Option<&u32>,
        ) -> Poll<PollResult<u32, u32>> {
            Poll::Ready(match self.0.pop_front() {
                Some(value) => PollResult::Item {
                    ordering: value,
                    data: value,
                },
                None => PollResult::Terminated,
            })
        }
        fn position_hint(&self) -> Option<MaybeBorrowed<'_, u32>> {
            self.0.front().map(MaybeBorrowed::Borrowed)
        }
    }
    let mut join = ordered_stream::join(Sequence([1, 2].into()), Sequence([3, 10].into()));
    let waker = Waker::from(Arc::new(Noop));
    let mut context = Context::from_waker(&waker);
    assert_eq!(
        Pin::new(&mut join).poll_next_before(&mut context, None),
        Poll::Ready(PollResult::Item {
            ordering: 1,
            data: 1
        })
    );
    // The hint says 3 although the next result is 2. Do not use it for authorization.
    assert_eq!(join.position_hint().as_deref(), Some(&3));
    for value in [2, 3, 10] {
        assert_eq!(
            Pin::new(&mut join).poll_next_before(&mut context, None),
            Poll::Ready(PollResult::Item {
                ordering: value,
                data: value
            })
        );
    }
    assert_eq!(
        Pin::new(&mut join).poll_next_before(&mut context, None),
        Poll::Ready(PollResult::Terminated)
    );
}
