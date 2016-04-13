use num::BigUint;
use implement_diffie_hellman::{ modexp, ONE };
// use bleichenbachers_e_eq_3_rsa_attack::Signer;


#[derive(Clone, PartialEq, Debug)]
pub struct DSA {
    pub x: Option<BigUint>,
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
    pub y: BigUint
}

impl DSA {
    pub fn new(p: &BigUint, q: &BigUint, g: &BigUint) -> DSA {
        DSA::from(&rand_big!(&(q - ONE.clone())), &p, &q, &g)
    }

    pub fn from(x: &BigUint, p: &BigUint, q: &BigUint, g: &BigUint) -> DSA {
        DSA {
            x: Some(x.clone()),
            p: p.clone(),
            q: q.clone(),
            g: g.clone(),
            y: modexp(g, &x, p)
        }
    }

    pub fn public(&self) -> DSA {
        DSA {
            x: None,
            p: self.p.clone(),
            q: self.q.clone(),
            g: self.g.clone(),
            y: self.y.clone()
        }
    }
}

// impl Signer for DSA {
//     fn sign(&self, data: &[u8]) -> Vec<u8> {
//         unimplemented!()
//     }
//     fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
//         unimplemented!()
//     }
// }
