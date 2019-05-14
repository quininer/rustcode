//! https://vjudge.net/problem/HDU-1270

extern crate z3_sys;

use std::ffi::CString;
use z3_sys::*;


fn solver(n: usize, result: &[i32]) -> Vec<i32> {
    unsafe {
        let cfg = Z3_mk_config();
        let ctx = Z3_mk_context(cfg);
        let int_sort = Z3_mk_int_sort(ctx);

        let strs = (0..n)
            .map(|i| CString::new(format!("x{}", i)).unwrap())
            .collect::<Vec<_>>();

        let consts = strs.iter()
            .map(|sym| Z3_mk_string_symbol(ctx, sym.as_ptr()))
            .map(|sym| Z3_mk_const(ctx, sym, int_sort))
            .collect::<Vec<_>>();

        let mut sumset = Z3_mk_empty_set(ctx, int_sort);

        for i in 0..n {
            for j in (i + 1)..n {
                let sum = Z3_mk_add(ctx, 2, [consts[i], consts[j]].as_ptr());
                sumset = Z3_mk_set_add(ctx, sumset, sum);
            }
        }

        let solver = Z3_mk_simple_solver(ctx);
        for &val in result {
            let val = Z3_mk_unsigned_int(ctx, val as _, int_sort);
            Z3_solver_assert(ctx, solver, Z3_mk_set_member(ctx, val, sumset));
        }
        assert_eq!(Z3_solver_check(ctx, solver), Z3_L_TRUE);

        let model = Z3_solver_get_model(ctx, solver);
        let interps = consts.into_iter()
            .map(|c| {
                let mut interp: Z3_ast = c;
                assert_eq!(
                    Z3_model_eval(ctx, model, c, Z3_TRUE, &mut interp),
                    Z3_TRUE
                );
                interp
            })
            .collect::<Vec<_>>();

        let output = interps.into_iter()
            .map(|i| {
                let mut val = 0;
                assert_eq!(Z3_get_numeral_int(ctx, i, &mut val), Z3_TRUE);
                val
            })
            .collect::<Vec<_>>();


        Z3_del_context(ctx);
        Z3_del_config(cfg);

        output
    }
}



fn main() {
    let n = 4;
    let results = [4, 5, 7, 10, 12, 13];

    let output = solver(n, &results);

    println!("{:?}", output);
}
