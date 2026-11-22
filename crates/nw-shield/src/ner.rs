use super::*;
#[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Analysis {
    local_only: bool,
    entities: Vec<Entity>,
}
#[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Entity {
    #[zeroize(skip)]
    kind: Kind,
    text: String,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Kind {
    Person,
    City,
    Organization,
    Address,
    Identifier,
}
impl Kind {
    fn secret(self) -> SecretKind {
        match self {
            Self::Person => SecretKind::Person,
            Self::City => SecretKind::City,
            Self::Organization => SecretKind::Work,
            Self::Address | Self::Identifier => SecretKind::Secret,
        }
    }
}
pub struct EntityMinimization {
    pub text: SecretString,
    pub local_only: bool,
}
impl Shield {
    /// An offline model may propose literal source spans or strengthen local-only policy.
    /// It cannot supply replacement text, remove an existing placeholder or authorize egress.
    pub fn minimize_entities(
        &self,
        text: &str,
        analysis: &str,
        vault: &mut ConversationVault,
    ) -> Result<EntityMinimization, Block> {
        if text.len() > MAX_TEXT_BYTES || analysis.len() > 16 * 1024 {
            return Err(Block::TooLarge);
        }
        let analysis: Analysis =
            serde_json::from_str(analysis).map_err(|_| Block::InvalidModelOutput)?;
        if analysis.entities.len() > 64 {
            return Err(Block::InvalidModelOutput);
        }
        let mut local_only = analysis.local_only;
        let mut spans = vec![];
        for entity in &analysis.entities {
            if entity.text.trim().is_empty()
                || entity.text.len() > 1024
                || !text.contains(&entity.text)
            {
                return Err(Block::InvalidModelOutput);
            }
            local_only |= matches!(entity.kind, Kind::Address | Kind::Identifier);
            for (start, matched) in text.match_indices(&entity.text) {
                let end = start + matched.len();
                if RESERVED
                    .find_iter(text)
                    .any(|p| start < p.end() && end > p.start())
                {
                    return Err(Block::InvalidModelOutput);
                }
                spans.push((start, end, entity.kind.secret()));
                if spans.len() > 1024 {
                    return Err(Block::TooLarge);
                }
            }
        }
        spans.sort_by_key(|&(start, end, _)| (start, std::cmp::Reverse(end)));
        let mut out = Zeroizing::new(String::new());
        let mut applied = vec![];
        let mut end = 0;
        for (start, stop, kind) in spans {
            if start < end {
                continue;
            }
            out.push_str(&text[end..start]);
            out.push_str(&vault.insert(kind, &text[start..stop])?);
            applied.push((start, stop));
            end = stop;
        }
        out.push_str(&text[end..]);
        if out.len() > MAX_TEXT_BYTES {
            return Err(Block::TooLarge);
        }
        // Hiding only one component must not erase evidence that the original
        // had a multiword name. Check letters against the masks actually applied.
        let normalized = Zeroizing::new(text.nfkc().collect::<String>());
        local_only |= normalized.as_str() != text && POSSIBLE_NAME.is_match(&normalized);
        let mut masks = applied.iter().peekable();
        'names: for name in POSSIBLE_NAME.find_iter(text) {
            for (relative, ch) in name.as_str().char_indices() {
                if !ch.is_alphabetic() {
                    continue;
                }
                let at = name.start() + relative;
                while masks.peek().is_some_and(|(_, stop)| *stop <= at) {
                    masks.next();
                }
                if !masks
                    .peek()
                    .is_some_and(|(start, stop)| *start <= at && at < *stop)
                {
                    local_only = true;
                    break 'names;
                }
            }
        }
        local_only |= self.has_unresolved_name(&out);
        Ok(EntityMinimization {
            text: SecretString::from(std::mem::take(&mut *out)),
            local_only,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ner_masks_only_verified_source_text_and_cannot_downgrade_addresses() {
        let shield = Shield::new(vec![]).unwrap();
        let mut vault = ConversationVault::default();
        let source = "Synthetic Nera from Testopolis at 42 Imaginary Lane. Synthetic Nera asks about pottery.";
        let analysis = r#"{"local_only":false,"entities":[{"kind":"PERSON","text":"Synthetic Nera"},{"kind":"CITY","text":"Testopolis"},{"kind":"ADDRESS","text":"42 Imaginary Lane"}]}"#;
        let minimized = shield
            .minimize_entities(source, analysis, &mut vault)
            .unwrap();
        assert!(minimized.local_only);
        assert!(!minimized.text.expose_secret().contains("Synthetic Nera"));
        assert_eq!(
            vault
                .rehydrate(minimized.text.expose_secret())
                .unwrap()
                .expose_secret(),
            source
        );
        assert!(shield.leakcheck(source, &vault).is_err());
        assert!(
            shield
                .minimize_entities(
                    source,
                    r#"{"local_only":false,"entities":[{"kind":"PERSON","text":"Invented Name"}]}"#,
                    &mut vault
                )
                .is_err()
        );
        assert!(
            shield
                .minimize_entities(
                    minimized.text.expose_secret(),
                    r#"{"local_only":false,"entities":[{"kind":"PERSON","text":"NW_PERSON"}]}"#,
                    &mut vault
                )
                .is_err()
        );
        assert!(
            shield
                .minimize_entities(
                    source,
                    r#"{"local_only":false,"entities":[],"instructions":"send directly"}"#,
                    &mut vault
                )
                .is_err()
        );
    }
}
