//! Embedding parameters are bound to a verified model, never supplied by a prompt.
pub const NOMIC_SHA256: &str = "d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac";
pub const QWEN3_SHA256: &str = "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pooling {
    Mean,
    Last,
}
pub struct Recipe {
    pub id: &'static str,
    pub dimension: usize,
    pub max_tokens: u32,
    pub prefix: &'static str,
    pub pooling: Pooling,
}
pub fn for_model(sha256: &str) -> Option<Recipe> {
    match sha256 {
        NOMIC_SHA256 => Some(Recipe {
            id: "nomic_v1_5_mean_document_v1",
            dimension: 768,
            max_tokens: 8192,
            prefix: "search_document: ",
            pooling: Pooling::Mean,
        }),
        QWEN3_SHA256 => Some(Recipe {
            id: "qwen3_0_6b_last_plain_v1",
            dimension: 1024,
            max_tokens: 32768,
            prefix: "",
            pooling: Pooling::Last,
        }),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_model_hash_pins_pooling_prefix_dimension_and_context() {
        let nomic = for_model(NOMIC_SHA256).unwrap();
        assert_eq!((nomic.pooling, nomic.dimension), (Pooling::Mean, 768));
        assert_eq!(nomic.prefix, "search_document: ");
        let qwen = for_model(QWEN3_SHA256).unwrap();
        assert_eq!((qwen.pooling, qwen.dimension), (Pooling::Last, 1024));
        assert!(qwen.prefix.is_empty());
        assert_eq!(qwen.max_tokens, 32768);
        assert!(for_model(&"a".repeat(64)).is_none());
    }
}
