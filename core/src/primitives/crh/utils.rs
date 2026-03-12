use ark_crypto_primitives::{
    crh::{
        CRHScheme, CRHSchemeGadget,
        poseidon::{CRH, constraints::{CRHGadget, CRHParametersVar}},
    },
    sponge::{
        Absorb,
        poseidon::{PoseidonConfig, PoseidonDefaultConfigEntry, find_poseidon_ark_and_mds},
    },
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sonobe_primitives::transcripts::{
    Absorbable,
    griffin::{
        GriffinParams,
        constraints::crh::GriffinParamsVar,
        sponge::{GriffinSponge, GriffinSpongeVar},
    },
};

pub trait Init: Clone + CanonicalSerialize + CanonicalDeserialize {
    type F: PrimeField + Absorb + Absorbable;
    type H: CRHScheme<Input = [Self::F], Output = Self::F, Parameters = Self>;
    type HGadget: CRHSchemeGadget<
            Self::H,
            Self::F,
            InputVar = [FpVar<Self::F>],
            OutputVar = FpVar<Self::F>,
            ParametersVar = Self::Var,
        >;
    type Var: Clone + AllocVar<Self, Self::F>;

    fn init<const N: usize>() -> Self;
}

impl<F: PrimeField + Absorbable + Absorb> Init for GriffinParams<F> {
    type F = F;
    type H = GriffinSponge<F>;
    type HGadget = GriffinSpongeVar<F>;
    type Var = GriffinParamsVar<F>;

    fn init<const N: usize>() -> Self {
        match N {
            0 | 1 => unimplemented!(),
            2 => GriffinParams::<F>::new(3, 5, 14),
            3 => GriffinParams::<F>::new(4, 5, 11),
            _ => GriffinParams::<F>::new((N + 1).next_multiple_of(4), 5, 9),
        }
    }
}

fn log2<F: PrimeField>() -> f64 {
    let x = F::MODULUS.into();
    let bits = x.bits(); // bit length
    if bits <= 53 {
        // Fits in f64 mantissa exactly
        let val: u64 = x.try_into().unwrap();
        return (val as f64).log2();
    }
    // Shift right so only top ~53 bits remain
    let shift = bits - 53;
    let top = x >> shift;
    let top_u64: u64 = top.try_into().unwrap();
    (top_u64 as f64).log2() + shift as f64
}

fn log_base(x: f64, base: f64) -> f64 {
    x.ln() / base.ln()
}

fn sat_inequiv_alpha<F: PrimeField>(t: usize, r_f: u64, r_p: u64, alpha: u64, m: usize) -> bool {
    let log2_p = log2::<F>();
    let n = log2_p.ceil() as usize;
    let m_f = m as f64;
    let n_f = n as f64;
    let t_f = t as f64;
    let r_p_f = r_p as f64;
    let r_f_f = r_f as f64;
    let alpha_f = alpha as f64;
    let log2_alpha = log_base(2.0, alpha_f);

    let r_f_1: f64 = if m_f <= (log2_p - (alpha_f - 1.0) / 2.0).floor() * (t_f + 1.0) {
        6.0
    } else {
        10.0
    };

    let r_f_2 = 1.0 + log2_alpha * m_f.min(n_f) + log_base(t_f, alpha_f).ceil() - r_p_f;

    let r_f_3 = 1.0 + log2_alpha * (m_f / 3.0).min(log2_p / 2.0) - r_p_f;

    let r_f_4 = t_f - 1.0 + (log2_alpha * m_f / (t_f + 1.0)).min(log2_alpha * log2_p / 2.0) - r_p_f;

    let r_f_max = r_f_1
        .ceil()
        .max(r_f_2.ceil())
        .max(r_f_3.ceil())
        .max(r_f_4.ceil());

    r_f_f >= r_f_max
}

fn get_sbox_cost(r_f: u64, r_p: u64, _n: usize, t: usize) -> usize {
    t * r_f as usize + r_p as usize
}

fn get_size_cost(r_f: u64, r_p: u64, n_total: usize, t: usize) -> usize {
    let n = ((n_total as f64) / (t as f64)).ceil() as usize;
    n_total * r_f as usize + n * r_p as usize
}

fn get_depth_cost(r_f: u64, r_p: u64, _n: usize, _t: usize) -> usize {
    r_f as usize + r_p as usize
}

fn find_fd_round_numbers<F: PrimeField>(
    t: usize,
    alpha: u64,
    m: usize,
    cost_function: fn(u64, u64, usize, usize) -> usize,
    security_margin: bool,
) -> (u64, u64) {
    let n = log2::<F>().ceil() as usize;
    let n_total = n * t;

    let mut r_p: u64 = 0;
    let mut r_f: u64 = 0;
    let mut min_cost = usize::MAX;
    let mut max_cost_rf: u64 = 0;

    for r_p_t in 1u64..500 {
        for r_f_t in (4u64..100).step_by(2) {
            if !sat_inequiv_alpha::<F>(t, r_f_t, r_p_t, alpha, m) {
                continue;
            }

            let (r_f_eff, r_p_eff) = if security_margin {
                (r_f_t + 2, (r_p_t as f64 * 1.075).ceil() as u64)
            } else {
                (r_f_t, r_p_t)
            };

            let cost = cost_function(r_f_eff, r_p_eff, n_total, t);
            if cost < min_cost || (cost == min_cost && r_f_eff < max_cost_rf) {
                r_p = r_p_eff;
                r_f = r_f_eff;
                min_cost = cost;
                max_cost_rf = r_f;
            }
        }
    }

    (r_f, r_p)
}

impl<F: PrimeField + Absorb + Absorbable> Init for PoseidonConfig<F> {
    type F = F;
    type H = CRH<F>;
    type HGadget = CRHGadget<F>;
    type Var = CRHParametersVar<F>;

    fn init<const N: usize>() -> Self {
        let alpha = 5;
        let (full_rounds, partial_rounds) =
            find_fd_round_numbers::<F>(N, alpha, 128, get_sbox_cost, true);
        let (ark, mds) = find_poseidon_ark_and_mds::<F>(
            F::MODULUS_BIT_SIZE as u64,
            N,
            full_rounds,
            partial_rounds,
            0,
        );

        Self {
            full_rounds: full_rounds as usize,
            partial_rounds: partial_rounds as usize,
            alpha,
            ark,
            mds,
            rate: N,
            capacity: 1,
        }
    }
}
