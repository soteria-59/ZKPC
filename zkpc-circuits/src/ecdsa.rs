#![allow(non_snake_case, unused_mut)]

use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use ff::PrimeField;
use ff::PrimeFieldBits;

#[derive(Clone)]
pub struct Point<F: PrimeField> {
    pub x: AllocatedNum<F>,
    pub y: AllocatedNum<F>,
    pub is_inf: Boolean,
}

pub fn alloc_is_zero<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    val: &AllocatedNum<F>,
) -> Result<(Boolean, AllocatedNum<F>), SynthesisError> {
    let val_val = val.get_value();
    let is_zero_val = val_val.map(|v| v.is_zero_vartime());
    let inv_val = val_val.map(|v| {
        if v.is_zero_vartime() {
            F::ZERO
        } else {
            v.invert().unwrap_or(F::ZERO)
        }
    });

    let is_zero_bit = AllocatedBit::alloc(cs.namespace(|| "is_zero_bit"), is_zero_val)?;
    let is_zero = Boolean::Is(is_zero_bit.clone());
    let inv = AllocatedNum::alloc(cs.namespace(|| "inv"), || {
        inv_val.ok_or(SynthesisError::AssignmentMissing)
    })?;

    // is_zero = 1 - val * inv
    // val * inv = 1 - is_zero
    cs.enforce(
        || "val * inv == 1 - is_zero",
        |lc| lc + val.get_variable(),
        |lc| lc + inv.get_variable(),
        |lc| lc + CS::one() - is_zero_bit.get_variable(),
    );

    // is_zero * val == 0
    cs.enforce(
        || "is_zero * val == 0",
        |lc| lc + is_zero_bit.get_variable(),
        |lc| lc + val.get_variable(),
        |lc| lc,
    );

    Ok((is_zero, inv))
}

pub fn add_complete<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    p: &Point<F>,
    q: &Point<F>,
    a_val: F,
) -> Result<Point<F>, SynthesisError> {
    // 1. diff_x = p.x - q.x
    let diff_x = AllocatedNum::alloc(cs.namespace(|| "diff_x"), || {
        let px = p.x.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let qx = q.x.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(px - qx)
    })?;
    cs.enforce(
        || "diff_x eq",
        |lc| lc + p.x.get_variable() - q.x.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + diff_x.get_variable(),
    );

    // 2. Is diff_x == 0?
    let (is_x_eq, inv_diff_x) = alloc_is_zero(cs.namespace(|| "is_x_eq"), &diff_x)?;

    // 3. diff_y = p.y - q.y
    let diff_y = AllocatedNum::alloc(cs.namespace(|| "diff_y"), || {
        let py = p.y.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let qy = q.y.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(py - qy)
    })?;
    cs.enforce(
        || "diff_y eq",
        |lc| lc + p.y.get_variable() - q.y.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + diff_y.get_variable(),
    );

    // 4. two_y = 2 * p.y
    let two_y = AllocatedNum::alloc(cs.namespace(|| "two_y"), || {
        let py = p.y.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(py + py)
    })?;
    cs.enforce(
        || "two_y eq",
        |lc| lc + p.y.get_variable() + p.y.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + two_y.get_variable(),
    );

    // 5. Is two_y == 0?
    let (is_p_y_zero, inv_two_y) = alloc_is_zero(cs.namespace(|| "is_p_y_zero"), &two_y)?;

    // 6. lambda_add = diff_y * inv_diff_x
    let lambda_add = AllocatedNum::alloc(cs.namespace(|| "lambda_add"), || {
        let dy = diff_y
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        let inv_dx = inv_diff_x
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        Ok(dy * inv_dx)
    })?;
    cs.enforce(
        || "lambda_add eq",
        |lc| lc + diff_y.get_variable(),
        |lc| lc + inv_diff_x.get_variable(),
        |lc| lc + lambda_add.get_variable(),
    );

    // 7. lambda_double = (3 * p.x^2 + a) * inv_two_y
    let x_sq = p.x.square(cs.namespace(|| "x_sq"))?;
    let num_double = AllocatedNum::alloc(cs.namespace(|| "num_double"), || {
        let x2 = x_sq.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(x2 + x2 + x2 + a_val)
    })?;
    cs.enforce(
        || "num_double eq",
        |lc| {
            lc + x_sq.get_variable()
                + x_sq.get_variable()
                + x_sq.get_variable()
                + (a_val, CS::one())
        },
        |lc| lc + CS::one(),
        |lc| lc + num_double.get_variable(),
    );

    let lambda_double = AllocatedNum::alloc(cs.namespace(|| "lambda_double"), || {
        let num = num_double
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        let inv = inv_two_y
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        Ok(num * inv)
    })?;
    cs.enforce(
        || "lambda_double eq",
        |lc| lc + num_double.get_variable(),
        |lc| lc + inv_two_y.get_variable(),
        |lc| lc + lambda_double.get_variable(),
    );

    // 8. Select lambda based on is_x_eq
    let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
        if is_x_eq.get_value().unwrap_or(false) {
            lambda_double
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)
        } else {
            lambda_add
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)
        }
    })?;
    cs.enforce(
        || "select lambda",
        |_| is_x_eq.lc(CS::one(), F::ONE),
        |lc| lc + lambda_double.get_variable() - lambda_add.get_variable(),
        |lc| lc + lambda.get_variable() - lambda_add.get_variable(),
    );

    // 9. x_next = lambda^2 - p.x - q.x
    let lambda_sq = lambda.square(cs.namespace(|| "lambda_sq"))?;
    let x_next = AllocatedNum::alloc(cs.namespace(|| "x_next"), || {
        let l_sq = lambda_sq
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        let px = p.x.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let qx = q.x.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(l_sq - px - qx)
    })?;
    cs.enforce(
        || "x_next eq",
        |lc| lc + lambda_sq.get_variable() - p.x.get_variable() - q.x.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + x_next.get_variable(),
    );

    // 10. y_next = lambda * (p.x - x_next) - p.y
    let y_next = AllocatedNum::alloc(cs.namespace(|| "y_next"), || {
        let l = lambda
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        let px = p.x.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let xn = x_next
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        let py = p.y.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(l * (px - xn) - py)
    })?;
    cs.enforce(
        || "y_next eq",
        |lc| lc + lambda.get_variable(),
        |lc| lc + p.x.get_variable() - x_next.get_variable(),
        |lc| lc + y_next.get_variable() + p.y.get_variable(),
    );

    // Now logic for is_inf and selection
    // is_same_point = is_x_eq AND (p.y == q.y) -> wait, if is_x_eq is true, diff_y == 0 means p.y == q.y
    let (is_y_eq, _) = alloc_is_zero(cs.namespace(|| "is_y_eq"), &diff_y)?;
    let is_same_point = Boolean::and(cs.namespace(|| "is_same_point"), &is_x_eq, &is_y_eq)?;

    // if is_x_eq is true but is_same_point is false, they are inverses (p.y = -q.y), so result is inf.
    let is_inverse = Boolean::and(
        cs.namespace(|| "is_inverse"),
        &is_x_eq,
        &is_same_point.not(),
    )?;

    // Also if p.y == 0, then 2*p.y == 0. So if doubling, and p.y == 0, result is inf.
    let is_double_inf = Boolean::and(
        cs.namespace(|| "is_double_inf"),
        &is_same_point,
        &is_p_y_zero,
    )?;

    let is_math_inf = Boolean::or(cs.namespace(|| "is_math_inf"), &is_inverse, &is_double_inf)?;

    // Result logic:
    // If p.is_inf: result = q
    // Else If q.is_inf: result = p
    // Else:
    //    if is_math_inf: result = inf
    //    else: result = (x_next, y_next)

    // Let's build the multiplexers:

    // base_res = if is_math_inf { inf } else { (x_next, y_next) }
    // We don't care about x,y values if it's inf, just pass x_next, y_next!
    let out_x = x_next.clone();
    let out_y = y_next.clone();
    let out_inf = is_math_inf.clone();

    // Select with q: if q.is_inf { p } else { base_res }
    let sel_q = q.is_inf.clone();
    let q_res_x = AllocatedNum::alloc(cs.namespace(|| "q_res_x"), || {
        if sel_q.get_value().unwrap_or(false) {
            p.x.get_value().ok_or(SynthesisError::AssignmentMissing)
        } else {
            out_x.get_value().ok_or(SynthesisError::AssignmentMissing)
        }
    })?;
    cs.enforce(
        || "sel qx",
        |_| sel_q.lc(CS::one(), F::ONE),
        |lc| lc + p.x.get_variable() - out_x.get_variable(),
        |lc| lc + q_res_x.get_variable() - out_x.get_variable(),
    );
    let q_res_y = AllocatedNum::alloc(cs.namespace(|| "q_res_y"), || {
        if sel_q.get_value().unwrap_or(false) {
            p.y.get_value().ok_or(SynthesisError::AssignmentMissing)
        } else {
            out_y.get_value().ok_or(SynthesisError::AssignmentMissing)
        }
    })?;
    cs.enforce(
        || "sel qy",
        |_| sel_q.lc(CS::one(), F::ONE),
        |lc| lc + p.y.get_variable() - out_y.get_variable(),
        |lc| lc + q_res_y.get_variable() - out_y.get_variable(),
    );
    let q_res_inf_val = match sel_q.get_value() {
        Some(true) => p.is_inf.get_value(),
        Some(false) => out_inf.get_value(),
        None => None,
    };
    let q_res_inf = Boolean::Is(bellpepper_core::boolean::AllocatedBit::alloc(
        cs.namespace(|| "q_res_inf"),
        q_res_inf_val,
    )?);
    cs.enforce(
        || "sel qinf",
        |_| sel_q.lc(CS::one(), F::ONE),
        |_| p.is_inf.lc(CS::one(), F::ONE) - &out_inf.lc(CS::one(), F::ONE),
        |_| q_res_inf.lc(CS::one(), F::ONE) - &out_inf.lc(CS::one(), F::ONE),
    );

    // Select with p: if p.is_inf { q } else { q_res }
    let sel_p = p.is_inf.clone();
    let final_x = AllocatedNum::alloc(cs.namespace(|| "final_x"), || {
        if sel_p.get_value().unwrap_or(false) {
            q.x.get_value().ok_or(SynthesisError::AssignmentMissing)
        } else {
            q_res_x.get_value().ok_or(SynthesisError::AssignmentMissing)
        }
    })?;
    cs.enforce(
        || "sel px",
        |_| sel_p.lc(CS::one(), F::ONE),
        |lc| lc + q.x.get_variable() - q_res_x.get_variable(),
        |lc| lc + final_x.get_variable() - q_res_x.get_variable(),
    );
    let final_y = AllocatedNum::alloc(cs.namespace(|| "final_y"), || {
        if sel_p.get_value().unwrap_or(false) {
            q.y.get_value().ok_or(SynthesisError::AssignmentMissing)
        } else {
            q_res_y.get_value().ok_or(SynthesisError::AssignmentMissing)
        }
    })?;
    cs.enforce(
        || "sel py",
        |_| sel_p.lc(CS::one(), F::ONE),
        |lc| lc + q.y.get_variable() - q_res_y.get_variable(),
        |lc| lc + final_y.get_variable() - q_res_y.get_variable(),
    );
    let final_inf_val = match sel_p.get_value() {
        Some(true) => q.is_inf.get_value(),
        Some(false) => q_res_inf.get_value(),
        None => None,
    };
    let final_inf = Boolean::Is(bellpepper_core::boolean::AllocatedBit::alloc(
        cs.namespace(|| "final_inf"),
        final_inf_val,
    )?);
    cs.enforce(
        || "sel pinf",
        |_| sel_p.lc(CS::one(), F::ONE),
        |_| q.is_inf.lc(CS::one(), F::ONE) - &q_res_inf.lc(CS::one(), F::ONE),
        |_| final_inf.lc(CS::one(), F::ONE) - &q_res_inf.lc(CS::one(), F::ONE),
    );

    Ok(Point {
        x: final_x,
        y: final_y,
        is_inf: final_inf,
    })
}

pub fn conditionally_select<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    b: &Boolean,
    p_true: &Point<F>,
    p_false: &Point<F>,
) -> Result<Point<F>, SynthesisError> {
    let r_x = AllocatedNum::alloc(cs.namespace(|| "r_x"), || {
        if b.get_value().unwrap_or(false) {
            p_true
                .x
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)
        } else {
            p_false
                .x
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)
        }
    })?;
    cs.enforce(
        || "select x",
        |_| b.lc(CS::one(), F::ONE),
        |lc| lc + p_true.x.get_variable() - p_false.x.get_variable(),
        |lc| lc + r_x.get_variable() - p_false.x.get_variable(),
    );

    let r_y = AllocatedNum::alloc(cs.namespace(|| "r_y"), || {
        if b.get_value().unwrap_or(false) {
            p_true
                .y
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)
        } else {
            p_false
                .y
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)
        }
    })?;
    cs.enforce(
        || "select y",
        |_| b.lc(CS::one(), F::ONE),
        |lc| lc + p_true.y.get_variable() - p_false.y.get_variable(),
        |lc| lc + r_y.get_variable() - p_false.y.get_variable(),
    );

    let r_inf_val = match b.get_value() {
        Some(true) => p_true.is_inf.get_value(),
        Some(false) => p_false.is_inf.get_value(),
        None => None,
    };
    let r_inf = Boolean::Is(bellpepper_core::boolean::AllocatedBit::alloc(
        cs.namespace(|| "r_inf"),
        r_inf_val,
    )?);
    cs.enforce(
        || "select inf",
        |_| b.lc(CS::one(), F::ONE),
        |_| p_true.is_inf.lc(CS::one(), F::ONE) - &p_false.is_inf.lc(CS::one(), F::ONE),
        |_| r_inf.lc(CS::one(), F::ONE) - &p_false.is_inf.lc(CS::one(), F::ONE),
    );

    Ok(Point {
        x: r_x,
        y: r_y,
        is_inf: r_inf,
    })
}

pub fn scalar_mul<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    Q: &Point<F>,
    bits_le: &[Boolean],
    a_val: F,
) -> Result<Point<F>, SynthesisError> {
    // initialize acc = inf
    let mut acc = Point {
        x: AllocatedNum::alloc(cs.namespace(|| "inf_x"), || Ok(F::ZERO))?,
        y: AllocatedNum::alloc(cs.namespace(|| "inf_y"), || Ok(F::ZERO))?,
        is_inf: Boolean::Constant(true),
    };

    // Instead of double-and-add from highest bit which requires knowing where highest bit is,
    // we can do standard double-and-add over bits:
    // base = Q
    // acc = inf
    // for bit in bits_le:
    //    if bit: acc = add(acc, base)
    //    base = double(base)
    // But since we have complete addition, we can just do:
    // for bit in bits_le (rev):
    //    acc = add(acc, acc)
    //    T = add(acc, Q)
    //    acc = select(bit, T, acc)

    for (i, bit) in bits_le.iter().rev().enumerate() {
        acc = add_complete(cs.namespace(|| format!("double_{}", i)), &acc, &acc, a_val)?;
        let T = add_complete(cs.namespace(|| format!("add_{}", i)), &acc, Q, a_val)?;
        acc = conditionally_select(cs.namespace(|| format!("select_{}", i)), bit, &T, &acc)?;
    }

    Ok(acc)
}

pub fn check_sum_mod_n<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    target: &[Boolean], // 256 bits, e.g. E or R_x
    value: &[Boolean],  // 256 bits, e.g. e or r
    q: &Boolean,        // 1 bit
    n_bits: &[u8],
) -> Result<Boolean, SynthesisError> {
    let mut carry = Boolean::Constant(false);
    for i in 0..256 {
        let n_i_is_one = n_bits[i] == 1;

        let a_val = value[i].get_value();
        let b_val = if n_i_is_one {
            q.get_value()
        } else {
            Some(false)
        };
        let c_val = carry.get_value();

        let a = if a_val.unwrap_or(false) { 1 } else { 0 };
        let b = if b_val.unwrap_or(false) { 1 } else { 0 };
        let c = if c_val.unwrap_or(false) { 1 } else { 0 };
        let c_next = (a + b + c) >= 2;

        let carry_next_bit =
            AllocatedBit::alloc(cs.namespace(|| format!("carry_bit_{}", i)), Some(c_next))?;
        let carry_next_bool = Boolean::Is(carry_next_bit.clone());
        let carry_next_var = carry_next_bit.get_variable();

        let q_lc = if n_i_is_one {
            q.lc(CS::one(), F::ONE)
        } else {
            bellpepper_core::LinearCombination::zero()
        };

        cs.enforce(
            || format!("adder_{}", i),
            |lc| lc + CS::one(),
            |lc| lc + &value[i].lc(CS::one(), F::ONE) + &q_lc + &carry.lc(CS::one(), F::ONE),
            |lc| lc + &target[i].lc(CS::one(), F::ONE) + carry_next_var + carry_next_var,
        );

        carry = carry_next_bool;
    }
    Ok(carry) // Return final carry to ensure no overflow if needed
}

pub fn enforce_less_than_const<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits_le: &[Boolean],
    const_bits: &[u8], // 256 bits
) -> Result<(), SynthesisError> {
    assert_eq!(bits_le.len(), 256);
    let mut is_less = Boolean::Constant(false);
    let mut is_equal = Boolean::Constant(true);
    for i in 0..256 {
        let bit_idx = 255 - i;
        let a_bit = &bits_le[bit_idx];
        let b_bit = const_bits[bit_idx] == 1;

        if b_bit {
            let a_less_b = a_bit.not();
            let eq_and_less = Boolean::and(
                cs.namespace(|| format!("eq_less_{}", i)),
                &is_equal,
                &a_less_b,
            )?;
            is_less = Boolean::or(
                cs.namespace(|| format!("less_{}", i)),
                &is_less,
                &eq_and_less,
            )?;
        }

        let a_eq_b = if b_bit { a_bit.clone() } else { a_bit.not() };
        is_equal = Boolean::and(cs.namespace(|| format!("eq_{}", i)), &is_equal, &a_eq_b)?;
    }
    Boolean::enforce_equal(
        cs.namespace(|| "enforce_less"),
        &is_less,
        &Boolean::Constant(true),
    )?;
    Ok(())
}

pub fn enforce_not_zero<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits_le: &[Boolean],
) -> Result<(), SynthesisError> {
    let mut any_one = Boolean::Constant(false);
    for (i, bit) in bits_le.iter().enumerate() {
        any_one = Boolean::or(cs.namespace(|| format!("any_one_{}", i)), &any_one, bit)?;
    }
    Boolean::enforce_equal(
        cs.namespace(|| "enforce_not_zero"),
        &any_one,
        &Boolean::Constant(true),
    )?;
    Ok(())
}

pub fn reconstruct<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits_le: &[Boolean],
) -> Result<AllocatedNum<F>, SynthesisError> {
    let res = AllocatedNum::alloc(cs.namespace(|| "recon"), || {
        let mut v = F::ZERO;
        let mut base = F::ONE;
        for bit in bits_le {
            if bit.get_value().unwrap() {
                v += base;
            }
            base = base.double();
        }
        Ok(v)
    })?;
    let mut lc = bellpepper_core::LinearCombination::<F>::zero();
    let mut base = F::ONE;
    for bit in bits_le {
        lc = lc + &bit.lc(CS::one(), base);
        base = base.double();
    }
    cs.enforce(
        || "recon_eq",
        |_| lc,
        |lc| lc + CS::one(),
        |lc| lc + res.get_variable(),
    );
    Ok(res)
}

pub const N_BITS_LE: [u8; 256] = [
    1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1,
    0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1,
    0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1,
    1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
];

pub const P_BITS_LE: [u8; 256] = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
];

pub fn verify_ecdsa<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
    mut cs: CS,
    pub_key: &Point<F>,
    m_bits: &[Boolean],
    r_bits: &[Boolean],
    s_bits: &[Boolean],
    e_bits: &[Boolean],
    Rx_bits: &[Boolean],
    q_E: &Boolean,
    q_R: &Boolean,
    R_y: &AllocatedNum<F>,
) -> Result<(), SynthesisError> {
    let n_bits = N_BITS_LE;
    let p_bits = P_BITS_LE;

    let a_val = F::from_str_vartime(
        "115792089210356248762697446949407573530086143415290314195533631308867097853948",
    )
    .unwrap(); // -3 mod p
    let b_val = F::from_str_vartime(
        "41058363725152142129326129780047268409114441015993725554835256314039467401291",
    )
    .unwrap();

    // 0. Ensure pub_key is not infinity
    Boolean::enforce_equal(
        cs.namespace(|| "Q not inf"),
        &pub_key.is_inf,
        &Boolean::Constant(false),
    )?;

    // Verify pub_key is on the curve
    let qy_sq = pub_key.y.square(cs.namespace(|| "Qy^2"))?;
    let qx_sq = pub_key.x.square(cs.namespace(|| "Qx^2"))?;
    let qx_cub = AllocatedNum::alloc(cs.namespace(|| "Qx^3"), || {
        Ok(qx_sq.get_value().unwrap() * pub_key.x.get_value().unwrap())
    })?;
    cs.enforce(
        || "Qx^3 eq",
        |lc| lc + qx_sq.get_variable(),
        |lc| lc + pub_key.x.get_variable(),
        |lc| lc + qx_cub.get_variable(),
    );
    cs.enforce(
        || "Qy^2 == Qx^3 - 3Qx + b",
        |lc| lc + qy_sq.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + qx_cub.get_variable() + (a_val, pub_key.x.get_variable()) + (b_val, CS::one()),
    );

    // 1. Range checks
    enforce_less_than_const(cs.namespace(|| "r < n"), r_bits, &n_bits)?;
    enforce_not_zero(cs.namespace(|| "r != 0"), r_bits)?;
    enforce_less_than_const(cs.namespace(|| "s < n"), s_bits, &n_bits)?;
    enforce_not_zero(cs.namespace(|| "s != 0"), s_bits)?;
    enforce_less_than_const(cs.namespace(|| "e < n"), e_bits, &n_bits)?;
    enforce_less_than_const(cs.namespace(|| "Rx < p"), Rx_bits, &p_bits)?;

    let Qx_bits = pub_key.x.to_bits_le_strict(cs.namespace(|| "Qx_bits"))?;
    enforce_less_than_const(cs.namespace(|| "Qx < p"), &Qx_bits, &p_bits)?;
    let Qy_bits = pub_key.y.to_bits_le_strict(cs.namespace(|| "Qy_bits"))?;
    enforce_less_than_const(cs.namespace(|| "Qy < p"), &Qy_bits, &p_bits)?;

    // 2. Check E = e + q_E * n over integers
    let carry_E = check_sum_mod_n(cs.namespace(|| "E eq"), m_bits, e_bits, q_E, &n_bits)?;
    Boolean::enforce_equal(
        cs.namespace(|| "E no overflow"),
        &carry_E,
        &Boolean::Constant(false),
    )?;

    // 3. Check Rx = r + q_R * n over integers
    let carry_R = check_sum_mod_n(cs.namespace(|| "Rx eq"), Rx_bits, r_bits, q_R, &n_bits)?;
    Boolean::enforce_equal(
        cs.namespace(|| "Rx no overflow"),
        &carry_R,
        &Boolean::Constant(false),
    )?;

    let Rx_num = reconstruct(cs.namespace(|| "Rx_num"), Rx_bits)?;
    let R = Point {
        x: Rx_num,
        y: R_y.clone(),
        is_inf: Boolean::Constant(false),
    };

    // 4. Verify R is on the curve (y^2 = x^3 - 3x + b)
    let y_sq = R.y.square(cs.namespace(|| "Ry^2"))?;
    let x_sq = R.x.square(cs.namespace(|| "Rx^2"))?;
    let x_cub = AllocatedNum::alloc(cs.namespace(|| "Rx^3"), || {
        Ok(x_sq.get_value().unwrap() * R.x.get_value().unwrap())
    })?;
    cs.enforce(
        || "Rx^3 eq",
        |lc| lc + x_sq.get_variable(),
        |lc| lc + R.x.get_variable(),
        |lc| lc + x_cub.get_variable(),
    );
    cs.enforce(
        || "Ry^2 == Rx^3 - 3Rx + b",
        |lc| lc + y_sq.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + x_cub.get_variable() + (a_val, R.x.get_variable()) + (b_val, CS::one()),
    );

    let gx_val = F::from_str_vartime(
        "48439561293906451759052585252797914202762949526041747995844080717082404635286",
    )
    .unwrap();
    let gy_val = F::from_str_vartime(
        "36134250956749795798585127919587881956611106672985015071877198253568414405109",
    )
    .unwrap();
    let G = Point {
        x: AllocatedNum::alloc(cs.namespace(|| "Gx"), || Ok(gx_val))?,
        y: AllocatedNum::alloc(cs.namespace(|| "Gy"), || Ok(gy_val))?,
        is_inf: Boolean::Constant(false),
    };

    // 5. Compute sR, eG, rQ
    let sR = scalar_mul(cs.namespace(|| "sR"), &R, s_bits, a_val)?;
    let eG = scalar_mul(cs.namespace(|| "eG"), &G, e_bits, a_val)?;
    let rQ = scalar_mul(cs.namespace(|| "rQ"), pub_key, r_bits, a_val)?;

    // 6. Check sR = eG + rQ
    let rhs = add_complete(cs.namespace(|| "eG + rQ"), &eG, &rQ, a_val)?;

    cs.enforce(
        || "sR.x == rhs.x",
        |lc| lc + sR.x.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + rhs.x.get_variable(),
    );
    cs.enforce(
        || "sR.y == rhs.y",
        |lc| lc + sR.y.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + rhs.y.get_variable(),
    );
    // Also enforce they have same inf status (which should be false for valid signature, but just in case)
    cs.enforce(
        || "sR.inf == rhs.inf",
        |_| sR.is_inf.lc(CS::one(), F::ONE),
        |lc| lc + CS::one(),
        |_| rhs.is_inf.lc(CS::one(), F::ONE),
    );
    // Enforce that result is NOT infinity!
    Boolean::enforce_equal(
        cs.namespace(|| "sR not inf"),
        &sR.is_inf,
        &Boolean::Constant(false),
    )?;

    Ok(())
}
