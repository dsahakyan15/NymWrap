use std::collections::HashSet;

fn inputs(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("synthetic-key-{i:04}-λ")).collect()
}

#[test]
fn default_tables_are_total_permutations_with_matching_lookup() {
    for n in [0, 1, 2, 3, 7, 16, 31, 128, 257] {
        let keys = inputs(n);
        let state = phf_generator::generate_hash(&keys);
        assert_eq!(state.map.len(), n);
        assert_eq!(state.map.iter().copied().collect::<HashSet<_>>().len(), n);
        assert!(state.map.iter().all(|&i| i < n));
        for (i, key) in keys.iter().enumerate() {
            let hash = phf_shared::hash(key, &state.key);
            let slot = phf_shared::get_index(&hash, &state.disps, n) as usize;
            assert_eq!(state.map[slot], i);
        }
        let again = phf_generator::generate_hash(&keys);
        assert_eq!(state.key, again.key);
        assert_eq!(state.disps, again.disps);
        assert_eq!(state.map, again.map);
    }
}

#[test]
fn ptrhash_tables_are_total_permutations_with_matching_lookup() {
    for n in [0, 1, 2, 3, 7, 16, 31, 128, 257] {
        let keys = inputs(n);
        let state = phf_generator::ptrhash::generate_hash(&keys);
        assert_eq!(state.map.len(), n);
        assert_eq!(state.map.iter().copied().collect::<HashSet<_>>().len(), n);
        assert!(state.map.iter().all(|&i| i < n));
        for (i, key) in keys.iter().enumerate() {
            let hash = phf_shared::ptrhash::hash(key, &state.seed);
            let slot =
                phf_shared::ptrhash::get_index(state.seed, hash, &state.pilots, &state.remap, n)
                    as usize;
            assert_eq!(state.map[slot], i);
        }
        let again = phf_generator::ptrhash::generate_hash(&keys);
        assert_eq!(state.seed, again.seed);
        assert_eq!(state.pilots, again.pilots);
        assert_eq!(state.remap, again.remap);
        assert_eq!(state.map, again.map);
    }
}

#[test]
fn codegen_rejects_duplicate_static_keys_before_seed_search() {
    let mut map = phf_codegen::Map::new();
    map.entry("synthetic-duplicate", "0");
    map.entry("synthetic-duplicate", "1");
    assert!(std::panic::catch_unwind(|| map.build().to_string()).is_err());
}

#[test]
fn codegen_produces_a_table_for_distinct_static_keys() {
    let mut map = phf_codegen::Map::new();
    map.entry("synthetic-alpha", "0");
    map.entry("synthetic-beta", "1");
    let generated = map.build().to_string();
    assert!(generated.contains("synthetic-alpha"));
    assert!(generated.contains("synthetic-beta"));
    assert!(generated.contains("phf::Map"));
}
