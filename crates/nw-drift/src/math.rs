//! Independent Rust implementation of the reference equations in anti.py.
use crate::DriftError;
use serde::Serialize;
pub type Vector = Vec<f64>;

fn checked(v: &[f64]) -> Result<f64, DriftError> {
    if v.is_empty() || v.len() > 16384 || v.iter().any(|x| !x.is_finite()) {
        return Err(DriftError::Embedding);
    }
    let norm = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if !norm.is_finite() || norm < 1e-12 {
        return Err(DriftError::Embedding);
    }
    Ok(norm)
}
pub fn cos(a: &[f64], b: &[f64]) -> Result<f64, DriftError> {
    if a.len() != b.len() {
        return Err(DriftError::Embedding);
    }
    let denominator = checked(a)? * checked(b)?;
    Ok((a.iter().zip(b).map(|(x, y)| x * y).sum::<f64>() / denominator).clamp(-1.0, 1.0))
}
pub fn centroid(vectors: &[Vector]) -> Result<Vector, DriftError> {
    let first = vectors.first().ok_or(DriftError::Embedding)?;
    checked(first)?;
    let mut sum = vec![0.0; first.len()];
    for vector in vectors {
        checked(vector)?;
        if vector.len() != sum.len() {
            return Err(DriftError::Embedding);
        }
        for (s, v) in sum.iter_mut().zip(vector) {
            *s += v / vectors.len() as f64;
        }
    }
    let norm = checked(&sum)?;
    Ok(sum.into_iter().map(|x| x / norm).collect())
}
pub fn project(e: &[f64], persona: &[f64], cover: &[f64]) -> Result<f64, DriftError> {
    Ok((cos(e, cover)? - cos(e, persona)?) / (2.0 * (1.0 - cos(persona, cover)?).max(1e-6)) + 0.5)
}
pub struct Axis {
    persona: Vector,
    cover: Vector,
    t0: f64,
    t1: f64,
}
impl Axis {
    pub fn new(persona: &[Vector], cover: &[Vector]) -> Result<Self, DriftError> {
        let p = centroid(persona)?;
        let a = centroid(cover)?;
        if 1.0 - cos(&p, &a)? < 1e-6 {
            return Err(DriftError::Embedding);
        }
        let t0 = mean_projection(persona, &p, &a)?;
        let t1 = mean_projection(cover, &p, &a)?;
        if t1 - t0 < 1e-6 {
            return Err(DriftError::Embedding);
        }
        Ok(Self {
            persona: p,
            cover: a,
            t0,
            t1,
        })
    }
    pub fn position(&self, vectors: &[Vector]) -> Result<f64, DriftError> {
        Ok(
            (mean_projection(vectors, &self.persona, &self.cover)? - self.t0)
                / (self.t1 - self.t0).max(1e-6),
        )
    }
}
fn mean_projection(vectors: &[Vector], p: &[f64], a: &[f64]) -> Result<f64, DriftError> {
    if vectors.is_empty() {
        return Err(DriftError::Embedding);
    }
    Ok(vectors
        .iter()
        .map(|v| project(v, p, a))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .sum::<f64>()
        / vectors.len() as f64)
}
/// A stage may move back toward the persona by at most this much.
pub const BACKSLIDE_TOLERANCE: f64 = 0.05;
/// Neighbouring stages must be this much more alike than the first and last.
pub const SMOOTH_MARGIN: f64 = 0.05;
/// Largest allowed step between neighbouring stages: 2/(n-1).
pub fn step_limit(stages: usize) -> Result<f64, DriftError> {
    if stages < 3 {
        return Err(DriftError::Plan);
    }
    Ok(round3(2.0 / (stages - 1) as f64))
}
/// Even pace from the persona (0) to the cover (1), as in the lesson:
/// stage k (1-based) targets (k-1)/(n-1) of the way.
pub fn stage_targets(stages: usize) -> Result<Vec<f64>, DriftError> {
    if !(3..=30).contains(&stages) {
        return Err(DriftError::Plan);
    }
    Ok((0..stages)
        .map(|k| k as f64 / (stages - 1) as f64)
        .collect())
}
fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanChecks {
    pub positions: Vec<f64>,
    pub cos_next: Vec<f64>,
    pub min_cos: f64,
    pub cos_ends: f64,
    pub max_step: f64,
    pub step_limit: f64,
    pub backslides: usize,
    pub coverage: f64,
    pub valid: bool,
}
pub fn score(
    persona: &[Vector],
    cover: &[Vector],
    stages: &[Vec<Vector>],
    expected: usize,
) -> Result<PlanChecks, DriftError> {
    if expected < 3 || stages.len() < 3 || stages.len() > 30 {
        return Err(DriftError::Plan);
    }
    let axis = Axis::new(persona, cover)?;
    let positions = stages
        .iter()
        .map(|s| axis.position(s).map(round3))
        .collect::<Result<Vec<_>, _>>()?;
    let centers = stages
        .iter()
        .map(|s| centroid(s))
        .collect::<Result<Vec<_>, _>>()?;
    let cos_next = centers
        .windows(2)
        .map(|pair| cos(&pair[0], &pair[1]).map(round3))
        .collect::<Result<Vec<_>, _>>()?;
    let cos_ends = round3(cos(
        &centers[0],
        centers.last().ok_or(DriftError::Embedding)?,
    )?);
    let min_cos = cos_next.iter().copied().fold(1.0, f64::min);
    let steps: Vec<f64> = positions.windows(2).map(|w| w[1] - w[0]).collect();
    let backslides = steps.iter().filter(|s| **s < -BACKSLIDE_TOLERANCE).count();
    let max_step = round3(steps.iter().copied().fold(f64::NEG_INFINITY, f64::max));
    let step_limit = step_limit(expected)?;
    let mut reached = 0;
    for interest in cover {
        let mut hit = false;
        for v in stages[stages.len() / 2..].iter().flatten() {
            if cos(interest, v)? >= 0.55 {
                hit = true;
            }
        }
        reached += usize::from(hit);
    }
    let coverage = round3(reached as f64 / cover.len() as f64);
    let valid = stages.len() == expected
        && backslides == 0
        && min_cos >= cos_ends + SMOOTH_MARGIN
        && max_step <= step_limit
        && coverage >= 0.7;
    Ok(PlanChecks {
        positions,
        cos_next,
        min_cos,
        cos_ends,
        max_step,
        step_limit,
        backslides,
        coverage,
        valid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stage_targets_are_even_monotone_and_end_at_the_cover() {
        let targets = stage_targets(10).unwrap();
        assert_eq!(targets.len(), 10);
        assert_eq!(targets[0], 0.0);
        assert_eq!(targets[9], 1.0);
        assert!(
            targets
                .windows(2)
                .all(|w| w[1] > w[0] && w[1] - w[0] <= step_limit(10).unwrap())
        );
        assert_eq!(step_limit(10).unwrap(), 0.222);
        assert!(stage_targets(2).is_err() && stage_targets(31).is_err());
    }
    fn angle(a: f64) -> Vector {
        vec![a.cos(), a.sin()]
    }
    #[test]
    fn reference_selftest_matches_and_rejects_backslide() {
        let p = [angle(0.0), angle(0.1)];
        let a = [angle(1.47), angle(1.57)];
        assert!(
            project(&[1.0, 0.0], &[1.0, 0.0], &[0.0, 1.0])
                .unwrap()
                .abs()
                < 1e-9
        );
        assert!((project(&[0.5, 0.5], &[1.0, 0.0], &[0.0, 1.0]).unwrap() - 0.5).abs() < 1e-9);
        let mut stages = vec![
            vec![angle(0.05)],
            vec![angle(0.5)],
            vec![angle(1.0)],
            vec![angle(1.5)],
        ];
        let sc = score(&p, &a, &stages, 4).unwrap();
        assert!(sc.valid);
        assert_eq!(sc.coverage, 1.0);
        assert_eq!(sc.backslides, 0);
        assert!(sc.positions[0] < 0.1 && sc.positions[3] > 0.9 && sc.cos_ends < sc.min_cos);
        stages[2] = vec![angle(0.05)];
        let bad = score(&p, &a, &stages, 4).unwrap();
        assert!(!bad.valid);
        assert_eq!(bad.backslides, 1);
    }
    #[test]
    fn malformed_embeddings_do_not_produce_nan_or_valid_plans() {
        assert!(cos(&[1.0], &[1.0, 2.0]).is_err());
        assert!(cos(&[0.0], &[1.0]).is_err());
        assert!(cos(&[f64::NAN], &[1.0]).is_err());
        assert!(Axis::new(&[vec![1.0]], &[vec![1.0]]).is_err());
    }
}
