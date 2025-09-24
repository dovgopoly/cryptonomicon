use crypto_primes::{Flavor, random_prime};
use crypto_bigint::{U2048};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;

#[derive(Debug)]
pub struct Keypair {
    pub ek: EncryptionKey,
    pub dk: DecryptionKey,
}

#[derive(Debug)]
pub struct Ciphertext(BigUint);

#[derive(Debug)]
pub struct Message(BigUint);

#[derive(Debug)]
pub struct EncryptionKey {
    pub n: BigUint,
    pub g: BigUint,
}

#[derive(Debug)]
pub struct DecryptionKey {
    pub lambda: BigUint,
    pub mu: BigUint,
}

impl Keypair {
    pub fn new() -> Self {
        let mut rng = rand09::rng();

        let p = random_prime::<U2048, _>(&mut rng, Flavor::Any, 1024);
        let q = random_prime::<U2048, _>(&mut rng, Flavor::Any, 1024);
        let p = BigUint::from_bytes_be(&p.to_be_bytes());
        let q = BigUint::from_bytes_be(&q.to_be_bytes());

        let one = BigUint::from(1u8);

        let n = &p * &q;
        let g = &n + &one;

        let lambda = (p - &one) * (q - one);
        let mu = lambda.modinv(&n).unwrap();

        Self {
            ek: EncryptionKey { n, g },
            dk: DecryptionKey { lambda, mu }
        }
    }
}

impl Ciphertext {
    pub fn enc(msg: &Message, ek: &EncryptionKey) -> Self {
        let r = loop {
            let r = rand08::thread_rng().gen_biguint(1024) % &ek.n;
            if r.gcd(&ek.n).eq(&BigUint::from(1u8)) {
                break r;
            };
        };

        let m = &msg.0 % &ek.n;
        let nn = &ek.n * &ek.n;
        let ct = (ek.g.modpow(&m, &nn) * r.modpow(&ek.n, &nn)) % nn;

        Self(ct)
    }

    pub fn dec(&self, kp: &Keypair) -> Message {
        let nn = &kp.ek.n * &kp.ek.n;
        let x = self.0.modpow(&kp.dk.lambda, &nn);
        let lx = (x - BigUint::from(1u8)) / &kp.ek.n;
        let m = (lx * &kp.dk.mu) % &kp.ek.n;

        Message(m)
    }

    pub fn add_assign(&mut self, other: &Self, ek: &EncryptionKey) {
        let nn = &ek.n * &ek.n;

        self.0 = (&self.0 * &other.0) % nn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_flow() {
        let keypair = Keypair::new();

        let msg1 = Message(BigUint::from(1_000u16));
        let msg2 = Message(BigUint::from(2_000u16));

        let mut ct1 = Ciphertext::enc(&msg1, &keypair.ek);
        let ct2 = Ciphertext::enc(&msg2, &keypair.ek);

        for _ in 0..1_000 {
            ct1.add_assign(&ct2, &keypair.ek);
        }

        assert!(ct2.dec(&keypair).0.eq(&msg2.0));
        assert!(ct1.dec(&keypair).0.eq(&(&msg1.0 + BigUint::from(1_000u16) * &msg2.0)));
    }

    #[test]
    fn large_messages_flow() {
        let keypair = Keypair::new();

        let msg = Message(&keypair.ek.n / BigUint::from(10u8));
        let cts = (0..10).into_iter().map(
            |_| Ciphertext::enc(&msg, &keypair.ek)
        ).collect::<Vec<_>>();
        let agg_ct = cts.into_iter().reduce(|mut a, b| {
            a.add_assign(&b, &keypair.ek);
            a
        }).unwrap();
        let dec_msg = agg_ct.dec(&keypair);

        assert!(dec_msg.0.eq(&(&msg.0 * BigUint::from(10u8))))
    }
}
