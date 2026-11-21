//! Reproducible randomness and the hypothesis tests BMRL experiments use.
//!
//! Everything is deterministic and platform independent: the generator is
//! SplitMix64 (fixed algorithm, no OS entropy) and every sample `i` of an
//! experiment draws from its own stream `SplitMix64::stream(seed, i)`, so
//! results do not depend on thread scheduling.

#![forbid(unsafe_code)]

/// z quantile for a two-sided 95% interval.
pub const Z95: f64 = 1.959_963_984_540_054;

/// SplitMix64 (Steele, Lea, Flood 2014).
#[derive(Clone, Debug)]
pub struct SplitMix64(u64);

fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Independent stream for sample `index` of an experiment seeded `seed`.
    pub fn stream(seed: u64, index: u64) -> Self {
        Self(mix64(seed ^ mix64(index.wrapping_add(0x6a09_e667_f3bc_c908))))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        mix64(self.0)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn words<const N: usize>(&mut self) -> [u32; N] {
        std::array::from_fn(|_| self.next_u32())
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| (self.next_u64() >> 56) as u8)
    }
}

/// Complementary error function (Numerical Recipes `erfcc`, relative error < 1.2e-7).
pub fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let poly = -z * z - 1.265_512_23
        + t * (1.000_023_68
            + t * (0.374_091_96
                + t * (0.096_784_18
                    + t * (-0.186_288_06
                        + t * (0.278_868_07 + t * (-1.135_203_98 + t * (1.488_515_87 + t * (-0.822_152_23 + t * 0.170_872_77))))))));
    let ans = t * poly.exp();
    if x >= 0.0 { ans } else { 2.0 - ans }
}

/// Upper tail of the standard normal distribution.
pub fn normal_sf(z: f64) -> f64 {
    0.5 * erfc(z / std::f64::consts::SQRT_2)
}

/// Two-sided p-value of a z statistic.
pub fn two_sided_p(z: f64) -> f64 {
    erfc(z.abs() / std::f64::consts::SQRT_2)
}

/// |z| whose two-sided p-value is `p` (bisection on [`two_sided_p`]).
pub fn z_for_two_sided(p: f64) -> f64 {
    let (mut lo, mut hi) = (0.0f64, 40.0f64);
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if two_sided_p(mid) > p { lo = mid } else { hi = mid }
    }
    0.5 * (lo + hi)
}

/// `ln Γ(x)` (Lanczos approximation, Numerical Recipes `gammln`).
pub fn ln_gamma(x: f64) -> f64 {
    const COF: [f64; 6] = [
        76.180_091_729_471_46,
        -86.505_320_329_416_77,
        24.014_098_240_830_91,
        -1.231_739_572_450_155,
        0.120_865_097_386_617_9e-2,
        -0.539_523_938_495_3e-5,
    ];
    let mut y = x;
    let tmp = x + 5.5;
    let tmp = tmp - (x + 0.5) * tmp.ln();
    let mut ser = 1.000_000_000_190_015;
    for c in COF {
        y += 1.0;
        ser += c / y;
    }
    -tmp + (2.506_628_274_631_000_5 * ser / x).ln()
}

/// Regularized upper incomplete gamma function `Q(a, x)`.
pub fn gamma_q(a: f64, x: f64) -> f64 {
    assert!(a > 0.0 && x >= 0.0, "gamma_q domain: a={a}, x={x}");
    const EPS: f64 = 1e-15;
    const FPMIN: f64 = 1e-300;
    let prefactor = (-x + a * x.ln() - ln_gamma(a)).exp();
    if x == 0.0 {
        return 1.0;
    }
    if x < a + 1.0 {
        let (mut ap, mut del) = (a, 1.0 / a);
        let mut sum = del;
        for _ in 0..10_000 {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if del.abs() < sum.abs() * EPS {
                break;
            }
        }
        (1.0 - sum * prefactor).max(0.0)
    } else {
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / FPMIN;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..10_000 {
            let an = -(i as f64) * (i as f64 - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < FPMIN {
                d = FPMIN;
            }
            c = b + an / c;
            if c.abs() < FPMIN {
                c = FPMIN;
            }
            d = 1.0 / d;
            let del = d * c;
            h *= del;
            if (del - 1.0).abs() < EPS {
                break;
            }
        }
        prefactor * h
    }
}

/// Upper tail of the chi-square distribution with `df` degrees of freedom.
pub fn chi2_sf(x: f64, df: f64) -> f64 {
    gamma_q(df / 2.0, x / 2.0)
}

/// Wilson score interval for a binomial proportion.
pub fn wilson(successes: u64, n: u64, z: f64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let (k, n) = (successes as f64, n as f64);
    let p = k / n;
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denom;
    let half = z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt() / denom;
    ((center - half).max(0.0), (center + half).min(1.0))
}

/// Normal-approximation z statistic of `successes` out of `n` against `p`.
pub fn binomial_z(successes: u64, n: u64, p: f64) -> f64 {
    let n = n as f64;
    (successes as f64 - n * p) / (n * p * (1.0 - p)).sqrt()
}

/// Pooled two-proportion z statistic.
pub fn two_proportion_z(x1: u64, n1: u64, x2: u64, n2: u64) -> f64 {
    let (p1, p2) = (x1 as f64 / n1 as f64, x2 as f64 / n2 as f64);
    let p = (x1 + x2) as f64 / (n1 + n2) as f64;
    let se = (p * (1.0 - p) * (1.0 / n1 as f64 + 1.0 / n2 as f64)).sqrt();
    if se == 0.0 { 0.0 } else { (p1 - p2) / se }
}

/// Chi-square goodness-of-fit result.
#[derive(Clone, Debug, PartialEq)]
pub struct ChiSquare {
    pub statistic: f64,
    pub df: usize,
    pub p_value: f64,
    /// Bins after merging so every expected count is at least 5.
    pub bins: usize,
}

/// Goodness of fit of `observed` counts to bin probabilities `probs`
/// (which must sum to 1). Adjacent bins are merged left to right until each
/// expected count is >= 5; a short remainder joins the last bin.
pub fn chi_square_gof(observed: &[u64], probs: &[f64]) -> ChiSquare {
    assert_eq!(observed.len(), probs.len());
    let n: u64 = observed.iter().sum();
    let mut groups: Vec<(f64, f64)> = Vec::new();
    let (mut o, mut e) = (0.0, 0.0);
    for (&obs, &p) in observed.iter().zip(probs) {
        o += obs as f64;
        e += p * n as f64;
        if e >= 5.0 {
            groups.push((o, e));
            (o, e) = (0.0, 0.0);
        }
    }
    if e > 0.0 || o > 0.0 {
        match groups.last_mut() {
            Some(last) => {
                last.0 += o;
                last.1 += e;
            }
            None => groups.push((o, e)),
        }
    }
    let statistic: f64 = groups.iter().map(|&(o, e)| (o - e) * (o - e) / e).sum();
    let df = groups.len().saturating_sub(1);
    let p_value = if df == 0 { 1.0 } else { chi2_sf(statistic, df as f64) };
    ChiSquare { statistic, df, p_value, bins: groups.len() }
}

/// One-sample Kolmogorov–Smirnov test of `values` against Uniform(0, 1).
/// Returns (D, p-value) with the asymptotic Kolmogorov distribution and the
/// Stephens small-sample correction (Numerical Recipes `ksone`).
pub fn ks_uniform(values: &[f64]) -> (f64, f64) {
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let n = v.len() as f64;
    let d = v
        .iter()
        .enumerate()
        .map(|(i, &x)| ((i + 1) as f64 / n - x).max(x - i as f64 / n))
        .fold(0.0, f64::max);
    let lambda = (n.sqrt() + 0.12 + 0.11 / n.sqrt()) * d;
    (d, kolmogorov_q(lambda))
}

/// Q_KS(λ) = 2 Σ_{j>=1} (-1)^{j-1} exp(-2 j² λ²).
pub fn kolmogorov_q(lambda: f64) -> f64 {
    if lambda < 0.2 {
        return 1.0;
    }
    let mut sum = 0.0;
    let mut sign = 2.0;
    for j in 1..=200 {
        let term = sign * (-2.0 * (j * j) as f64 * lambda * lambda).exp();
        sum += term;
        if term.abs() <= 1e-12 * sum.abs() {
            return sum.clamp(0.0, 1.0);
        }
        sign = -sign;
    }
    1.0
}

/// Ordinary least squares `y = a + b x`: (slope b, intercept a, standard error of b).
pub fn linear_fit(xs: &[f64], ys: &[f64]) -> Option<(f64, f64, f64)> {
    let n = xs.len();
    if n < 2 || n != ys.len() {
        return None;
    }
    let nf = n as f64;
    let (mx, my) = (xs.iter().sum::<f64>() / nf, ys.iter().sum::<f64>() / nf);
    let sxx: f64 = xs.iter().map(|x| (x - mx) * (x - mx)).sum();
    if sxx == 0.0 {
        return None;
    }
    let sxy: f64 = xs.iter().zip(ys).map(|(x, y)| (x - mx) * (y - my)).sum();
    let b = sxy / sxx;
    let a = my - b * mx;
    let se = if n > 2 {
        let rss: f64 = xs.iter().zip(ys).map(|(x, y)| (y - a - b * x).powi(2)).sum();
        (rss / (nf - 2.0) / sxx).sqrt()
    } else {
        f64::NAN
    };
    Some((b, a, se))
}

/// Mean and normal-approximation 95% interval of the mean.
pub fn mean_ci95(xs: &[f64]) -> (f64, (f64, f64)) {
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    if xs.len() < 2 {
        return (mean, (f64::NAN, f64::NAN));
    }
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    let half = Z95 * (var / n).sqrt();
    (mean, (mean - half, mean + half))
}

/// Binomial(n, 1/2) probabilities for 0..=n (n <= 1000), by the exact
/// recurrence `p(k+1) = p(k) (n-k)/(k+1)` from `p(0) = 2^-n`.
pub fn binomial_half_pmf(n: u32) -> Vec<f64> {
    assert!(n <= 1000, "2^-n underflows f64 beyond n = 1074");
    let mut p = Vec::with_capacity(n as usize + 1);
    p.push(0.5f64.powi(n as i32));
    for k in 0..n {
        p.push(p[k as usize] * (n - k) as f64 / (k + 1) as f64);
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, rel: f64) -> bool {
        (a - b).abs() <= rel * b.abs().max(1e-300)
    }

    #[test]
    fn splitmix_reference_output() {
        // First output of SplitMix64 seeded with 0 (reference implementation).
        assert_eq!(SplitMix64::new(0).next_u64(), 0xe220_a839_7b1d_cdaf);
        assert_ne!(SplitMix64::stream(1, 0).next_u64(), SplitMix64::stream(1, 1).next_u64());
    }

    #[test]
    fn normal_tail_values() {
        assert!(close(normal_sf(1.959_963_984_540_054), 0.025, 1e-6));
        assert!(close(normal_sf(0.0), 0.5, 1e-6));
        assert!(close(two_sided_p(3.0), 0.002_699_796_063_260_19, 1e-5));
    }

    #[test]
    fn chi_square_tail_values() {
        // scipy.stats.chi2.sf reference values.
        assert!(close(chi2_sf(3.841_458_820_694_124, 1.0), 0.05, 1e-9));
        assert!(close(chi2_sf(18.307_038_053_275_146, 10.0), 0.05, 1e-9));
        assert!(close(chi2_sf(300.0, 255.0), 0.027_727_522_053_904_83, 1e-6));
        assert!(close(chi2_sf(1.0, 4.0), 0.909_795_989_569_084_7, 1e-9));
    }

    #[test]
    fn ks_and_regression() {
        // Perfectly spread values: tiny D, p near 1.
        let even: Vec<f64> = (0..1000).map(|i| (i as f64 + 0.5) / 1000.0).collect();
        let (d, p) = ks_uniform(&even);
        assert!(d < 0.001 && p > 0.99);
        // All mass below 0.5: strongly rejected.
        let low: Vec<f64> = (0..200).map(|i| i as f64 / 400.0).collect();
        assert!(ks_uniform(&low).1 < 1e-10);
        // scipy.special.kolmogorov(1.0) = 0.26999967167735456
        assert!(close(kolmogorov_q(1.0), 0.269_999_671_677_354_56, 1e-9));
        let (b, a, se) = linear_fit(&[1.0, 2.0, 3.0, 4.0], &[3.0, 5.0, 7.0, 9.0]).unwrap();
        assert!(close(b, 2.0, 1e-12) && close(a, 1.0, 1e-12) && se < 1e-9);
    }

    #[test]
    fn wilson_interval() {
        let (lo, hi) = wilson(50, 100, Z95);
        assert!(close(lo, 0.403_831_7, 1e-5) && close(hi, 0.596_168_3, 1e-5));
        assert_eq!(wilson(0, 0, Z95), (0.0, 1.0));
    }

    #[test]
    fn gof_detects_and_accepts() {
        let probs = binomial_half_pmf(16);
        assert!(close(probs.iter().sum(), 1.0, 1e-12));
        let n = 1_000_000.0;
        let ideal: Vec<u64> = probs.iter().map(|p| (p * n).round() as u64).collect();
        assert!(chi_square_gof(&ideal, &probs).p_value > 0.99);
        let mut skewed = ideal.clone();
        skewed[8] += 5_000;
        assert!(chi_square_gof(&skewed, &probs).p_value < 1e-6);
    }
}
