use num::BigUint;
use rmp::Value;
use rmp::encode::value::write_value;
use rmp::decode::read_value;
use implement_a_sha_1_keyed_mac::{ Sha1, Digest };
use implement_diffie_hellman::{ modexp, ONE };
use bleichenbachers_e_eq_3_rsa_attack::Signer;
use implement_rsa::uinvmod;

lazy_static!{
    pub static ref P: BigUint = hex_to_bigint!(u"
800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1");
    pub static ref Q: BigUint = hex_to_bigint!(u"f4f47f05794b256174bba6e9b396a7707e563c5b");
    pub static ref G: BigUint = hex_to_bigint!(u"
5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
0f5b64c36b625a097f1651fe775323556fe00b3608c887892
878480e99041be601a62166ca6894bdd41a7054ec89f756ba
9fc95302291");
}

#[derive(Clone, PartialEq, Debug)]
pub struct DSA {
    pub x: Option<BigUint>,
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
    pub y: BigUint
}

impl Default for DSA {
    fn default() -> DSA {
        DSA::new(&P, &Q, &G)
    }
}

impl DSA {
    pub fn new(p: &BigUint, q: &BigUint, g: &BigUint) -> DSA {
        DSA::from(&rand_big!(&ONE, &(q - ONE.clone())), &p, &q, &g)
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

impl Signer for DSA {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let h = BigUint::from_bytes_be(&Sha1::hash(data));
        let k = rand_big!(&ONE, &(&self.q - ONE.clone()));
        let x = self.clone().x.unwrap();
        let r = modexp(&self.g, &k, &self.p) % &self.q;
        let s = (&x * &r + &h) * uinvmod(&k, &self.q).unwrap() % &self.q;

        let mut out = Vec::new();
        let v = Value::Array(vec![
            Value::Binary(r.to_bytes_be()),
            Value::Binary(s.to_bytes_be())
        ]);
        write_value(&mut out, &v).ok();
        out
    }

    fn verify(&self, data: &[u8], mut signature: &[u8]) -> bool {
        let signature = match read_value(&mut signature) {
            Ok(Value::Array(value)) => value,
            _ => panic!("signature parse error.")
        };
        let (r, s) = match (&signature[0], &signature[1]) {
            (&Value::Binary(ref r), &Value::Binary(ref s)) => (
                BigUint::from_bytes_be(r),
                BigUint::from_bytes_be(s)
            ),
            _ => panic!("signature r/s parse error.")
        };

        let h = BigUint::from_bytes_be(&Sha1::hash(data));
        let w = uinvmod(&s, &self.q).unwrap();
        let u1 = (&h * &w) % &self.q;
        let u2 = (&r * &w) % &self.q;
        let v = (
            (modexp(&self.g, &u1, &self.p) * modexp(&self.y, &u2, &self.p))
                % &self.p
        ) % &self.q;

        v == r
    }
}

#[test]
fn test_sign() {
    let message1 = b"Hello, world";
    let message2 = b"Goodbye, world";

    let dsa = DSA::default();
    let pk = dsa.public();

    let signature1 = dsa.sign(message1);
    let signature2 = dsa.sign(message2);

    assert!(pk.verify(message1, &signature1));
    assert!(pk.verify(message2, &signature2));

    assert!(!pk.verify(message1, &signature2));
    assert!(!pk.verify(message2, &signature1));
}
