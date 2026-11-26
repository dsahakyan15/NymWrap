//! Test-only JSON bridge for comparing the independent Rust math to anti.py selftest.
use nw_drift::math::{Vector, project, score};
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    persona: Vec<Vector>,
    cover: Vec<Vector>,
    stages: Vec<Vec<Vector>>,
    expected: usize,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    std::io::stdin()
        .take(1024 * 1024)
        .read_to_string(&mut input)?;
    let cases: Vec<Case> = serde_json::from_str(&input)?;
    let scores = cases
        .iter()
        .map(|c| score(&c.persona, &c.cover, &c.stages, c.expected))
        .collect::<Result<Vec<_>, _>>()?;
    let p = [1.0, 0.0];
    let a = [0.0, 1.0];
    println!(
        "{}",
        serde_json::json!({"scores":scores,"projections":[project(&p,&p,&a)?,project(&a,&p,&a)?,project(&[0.5,0.5],&p,&a)?]})
    );
    Ok(())
}
