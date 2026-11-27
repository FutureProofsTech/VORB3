//! VORB3-SP1 signing and verification.

use crate::blake3::{DeriveKeyHasher, Wh512Hasher, derive_key_words};
use crate::field::F288;
use crate::ggm::{hidden_opening, reconstruct_root, tree_root};
use crate::keys::{Error, ExpandedSecretKey, PublicKey};
use crate::rain::{self, RainConstants, RainWitness};
use crate::signature::Signature;
use crate::transcript::Transcript;
use crate::zeroize::wipe_bytes;
use crate::{
    COMMITMENT_LEN, COPATH_LEN, FIELD_BYTES, H2_LEN, PUBLIC_KEY_LEN, ROUNDS, SALT_LEN,
    SIGNATURE_LEN, TREE_COUNT, TREE_DEPTH, WIRE_D_LEN,
};

const SALT_OFF: usize = 0;
const H2_OFF: usize = SALT_LEN;
const WIRE_D_OFF: usize = SALT_LEN + H2_LEN;
const U_OFF: usize = WIRE_D_OFF + WIRE_D_LEN;
const V_OFF: usize = U_OFF + FIELD_BYTES;
const OUT_TAG_OFF: usize = V_OFF + FIELD_BYTES;
const COPATH_OFF: usize = OUT_TAG_OFF + FIELD_BYTES;
const HIDDEN_OFF: usize = COPATH_OFF + COPATH_LEN;
const SECRET_WIRES: usize = 31;
const MASK_TREE: usize = 31;

/// Secret wire values and their MAC tags.
struct Wires {
    values: [F288; SECRET_WIRES],
    tags: [F288; SECRET_WIRES],
}

/// Hidden-leaf shares and verifier MACs for one signature.
struct Openings {
    u: [F288; TREE_COUNT],
    q: [F288; TREE_COUNT],
}

/// Signs `message` with the expanded secret key and 32 bytes of caller entropy.
///
/// # Errors
///
/// Returns [`Error::InvalidSecretKey`] if the expanded key or derived public key
/// is degenerate, and [`Error::InvalidSignature`] if fixed-size assembly fails.
#[inline]
pub fn sign(
    message: &[u8],
    secret: &ExpandedSecretKey,
    entropy: &[u8; 32],
) -> Result<Signature, Error> {
    let mut signature = [0u8; SIGNATURE_LEN];
    sign_into(message, secret, entropy, &mut signature)?;
    Signature::from_bytes(&signature)
}

/// Signs into a caller-provided fixed buffer, avoiding a return copy.
///
/// # Errors
///
/// Returns [`Error::InvalidSecretKey`] for a degenerate key or
/// [`Error::InvalidSignature`] if fixed-size assembly fails.
///
/// Kept out of line so callers do not inherit the full signing temporary set.
#[inline(never)]
pub fn sign_into(
    message: &[u8],
    secret: &ExpandedSecretKey,
    entropy: &[u8; 32],
    signature: &mut [u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    let constants = RainConstants::derive();
    let (ct, witness) = rain::encrypt(secret.sk, secret.pt, &constants);
    let public_key = public_key_from_parts(secret.pt, ct).map_err(|_| Error::InvalidSecretKey)?;
    let pk_hash = public_key_hash(&public_key);
    let mut master = master_seed(secret, &public_key, message, entropy);
    let salt = salt_from_master(&master);
    let mut transcript = Transcript::new();
    transcript.absorb("PK", public_key.as_bytes());
    transcript.absorb("SALT", &salt);
    transcript.absorb("MSG", message);
    {
        let mut roots_bytes = [0u8; TREE_COUNT * COMMITMENT_LEN];
        derive_roots(&master, &salt, &pk_hash, &mut roots_bytes);
        transcript.absorb("ROOTS", &roots_bytes);
    }
    let (delta, chi, h2) = squeeze_challenges(&mut transcript);

    copy_at(signature, SALT_OFF, &salt);
    copy_at(signature, H2_OFF, &h2);
    let mut wires = Wires {
        values: [F288::ZERO; SECRET_WIRES],
        tags: [F288::ZERO; SECRET_WIRES],
    };
    let (mut u_star, q_star) = {
        let mut openings = Openings {
            u: [F288::ZERO; TREE_COUNT],
            q: [F288::ZERO; TREE_COUNT],
        };
        fill_openings(&master, &salt, &pk_hash, &h2, signature, &mut openings);
        fill_wires(secret.sk, &witness, &openings, delta, signature, &mut wires);
        let u_star = openings.u.get(MASK_TREE).copied().unwrap_or(F288::ZERO);
        let q_star = openings.q.get(MASK_TREE).copied().unwrap_or(F288::ZERO);
        for value in &mut openings.u {
            value.wipe();
        }
        for value in &mut openings.q {
            value.wipe();
        }
        (u_star, q_star)
    };
    let (mut a0, mut a1, out_tag) = prove(&witness, &wires.values, &wires.tags, chi, &constants);
    copy_at(signature, OUT_TAG_OFF, &out_tag.to_bytes());

    let mut v_star = q_star.add_value(u_star.mul_value(delta));
    let masked_u = a0.add_value(v_star);
    let masked_v = a1.add_value(u_star);
    copy_at(signature, U_OFF, &masked_u.to_bytes());
    copy_at(signature, V_OFF, &masked_v.to_bytes());

    a0.wipe();
    a1.wipe();
    u_star.wipe();
    v_star.wipe();
    for value in &mut wires.values {
        value.wipe();
    }
    for value in &mut wires.tags {
        value.wipe();
    }
    wipe_bytes(&mut master);
    Ok(())
}

/// Verifies a signature. All signature-content failures return
/// [`Error::InvalidSignature`].
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] for a malformed or invalid signature.
#[inline]
pub fn verify(message: &[u8], public_key: &PublicKey, signature: &Signature) -> Result<(), Error> {
    verify_bytes(message, public_key, signature.as_bytes())
}

/// Verifies a raw fixed-size signature buffer.
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] for any signature-content failure.
///
/// Kept out of line so callers do not inherit the verification temporary set.
#[inline(never)]
pub fn verify_bytes(
    message: &[u8],
    public_key: &PublicKey,
    bytes: &[u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    let constants = RainConstants::derive();
    let salt = read::<SALT_LEN>(bytes, SALT_OFF).unwrap_or([0u8; SALT_LEN]);
    let h2 = read::<H2_LEN>(bytes, H2_OFF).unwrap_or([0u8; H2_LEN]);
    let pk_hash = public_key_hash(public_key);

    let mut transcript = Transcript::new();
    transcript.absorb("PK", public_key.as_bytes());
    transcript.absorb("SALT", &salt);
    transcript.absorb("MSG", message);
    {
        let mut roots_bytes = [0u8; TREE_COUNT * COMMITMENT_LEN];
        reconstruct_roots(bytes, &salt, &pk_hash, &h2, &mut roots_bytes);
        transcript.absorb("ROOTS", &roots_bytes);
    }
    let (delta, chi, h2_check) = squeeze_challenges(&mut transcript);
    let h2_ok = h2_check == h2;
    let mut q_open = [F288::ZERO; SECRET_WIRES];
    opened_wires(bytes, delta, &mut q_open);
    let proof_ok = check_proof(public_key, bytes, delta, chi, &q_open, &constants);
    if h2_ok && proof_ok {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

#[inline]
fn public_key_from_parts(pt: F288, ct: F288) -> Result<PublicKey, Error> {
    let mut bytes = [0u8; PUBLIC_KEY_LEN];
    write_field(&mut bytes, 0, pt);
    write_field(&mut bytes, FIELD_BYTES, ct);
    PublicKey::from_bytes(bytes)
}

#[inline]
fn public_key_hash(public_key: &PublicKey) -> [u8; COMMITMENT_LEN] {
    let mut hasher = Wh512Hasher::new();
    hasher.update(b"VORB3-PK-HASH-V1");
    hasher.update(public_key.as_bytes());
    hasher.finalize()
}

#[inline(never)]
fn master_seed(
    secret: &ExpandedSecretKey,
    public_key: &PublicKey,
    message: &[u8],
    entropy: &[u8; 32],
) -> [u8; FIELD_BYTES] {
    let mut hasher = DeriveKeyHasher::new("VORB3-HEDGED-V1");
    hasher.update(&secret.sk.to_bytes());
    hasher.update(public_key.as_bytes());
    hasher.update(
        &u64::try_from(message.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(message);
    hasher.update(entropy);
    let mut master = [0u8; FIELD_BYTES];
    hasher.finalize(&mut master);
    master
}

#[inline]
fn salt_from_master(master: &[u8; FIELD_BYTES]) -> [u8; SALT_LEN] {
    let mut hasher = Wh512Hasher::new();
    hasher.update(b"VORB3-SALT-V1");
    hasher.update(master);
    hasher.finalize()
}

fn derive_roots(
    master: &[u8; FIELD_BYTES],
    salt: &[u8; SALT_LEN],
    pk_hash: &[u8; COMMITMENT_LEN],
    roots: &mut [u8; TREE_COUNT * COMMITMENT_LEN],
) {
    for index in 0..TREE_COUNT {
        let tree_index = u16::try_from(index).unwrap_or(0);
        let root = tree_root(
            tree_root_seed(master, tree_index),
            tree_index,
            salt,
            pk_hash,
        );
        copy_at(roots, index.wrapping_mul(COMMITMENT_LEN), &root);
    }
}

fn fill_openings(
    master: &[u8; FIELD_BYTES],
    salt: &[u8; SALT_LEN],
    pk_hash: &[u8; COMMITMENT_LEN],
    h2: &[u8; H2_LEN],
    signature: &mut [u8; SIGNATURE_LEN],
    openings: &mut Openings,
) {
    for index in 0..TREE_COUNT {
        let tree_index = u16::try_from(index).unwrap_or(0);
        let alpha = h2.get(index).copied().unwrap_or(0);
        let mut root_seed = tree_root_seed(master, tree_index);
        let (share, commitment, copath) =
            hidden_opening(root_seed, tree_index, alpha, salt, pk_hash);
        wipe_bytes(&mut root_seed);
        for level in 0..TREE_DEPTH {
            let offset = COPATH_OFF
                .wrapping_add(index.wrapping_mul(TREE_DEPTH * FIELD_BYTES))
                .wrapping_add(level.wrapping_mul(FIELD_BYTES));
            if let Some(seed) = copath.get(level) {
                copy_at(signature, offset, seed);
            }
        }
        copy_at(
            signature,
            HIDDEN_OFF.wrapping_add(index.wrapping_mul(COMMITMENT_LEN)),
            &commitment,
        );
        if let Some(slot) = openings.u.get_mut(index) {
            *slot = share;
        }
        if let Some(slot) = openings.q.get_mut(index) {
            *slot = field_from_commitment(&commitment);
        }
    }
}

fn fill_wires(
    sk: F288,
    witness: &RainWitness,
    openings: &Openings,
    delta: F288,
    signature: &mut [u8; SIGNATURE_LEN],
    wires: &mut Wires,
) {
    if let Some(slot) = wires.values.get_mut(0) {
        *slot = sk;
    }
    for round in 0..ROUNDS {
        if let Some(value) = witness.y.get(round).copied()
            && let Some(slot) = wires.values.get_mut(1usize.wrapping_add(round))
        {
            *slot = value;
        }
        if let Some(value) = witness.b.get(round).copied()
            && let Some(slot) = wires
                .values
                .get_mut(1usize.wrapping_add(ROUNDS).wrapping_add(round))
        {
            *slot = value;
        }
    }

    for index in 0..SECRET_WIRES {
        let u = openings.u.get(index).copied().unwrap_or(F288::ZERO);
        let q = openings.q.get(index).copied().unwrap_or(F288::ZERO);
        let w = wires.values.get(index).copied().unwrap_or(F288::ZERO);
        let mut d = u.add_value(w);
        let tag = q.add_value(u.mul_value(delta));
        if let Some(slot) = wires.tags.get_mut(index) {
            *slot = tag;
        }
        copy_at(
            signature,
            WIRE_D_OFF.wrapping_add(index.wrapping_mul(FIELD_BYTES)),
            &d.to_bytes(),
        );
        d.wipe();
    }
}

fn prove(
    witness: &RainWitness,
    wire_w: &[F288; SECRET_WIRES],
    tags: &[F288; SECRET_WIRES],
    chi: F288,
    constants: &RainConstants,
) -> (F288, F288, F288) {
    let v_sk = tags.first().copied().unwrap_or(F288::ZERO);
    let mut v_s = F288::ZERO;
    let mut a0 = F288::ZERO;
    let mut a1 = F288::ZERO;
    let mut power = F288::ONE;
    let mut last_diffusion = F288::ZERO;
    let mut last_v_y = F288::ZERO;

    for round in 0..ROUNDS {
        let v_y = tags
            .get(1usize.wrapping_add(round))
            .copied()
            .unwrap_or(F288::ZERO);
        let v_b = tags
            .get(1usize.wrapping_add(ROUNDS).wrapping_add(round))
            .copied()
            .unwrap_or(F288::ZERO);
        let w_b = wire_w
            .get(1usize.wrapping_add(ROUNDS).wrapping_add(round))
            .copied()
            .unwrap_or(F288::ZERO);
        let w_x = witness.x.get(round).copied().unwrap_or(F288::ZERO);
        let w_y = witness.y.get(round).copied().unwrap_or(F288::ZERO);
        let diffusion = constants
            .diffusion
            .get(round)
            .copied()
            .unwrap_or(F288::ZERO);
        let v_x = v_s.add_value(v_sk);
        let v_s_next = diffusion.mul_value(v_y);

        let (g0a, g0b) = gate(w_b, v_b, w_b, v_b, v_b);
        a0 = a0.add_value(g0a.mul_value(power));
        a1 = a1.add_value(g0b.mul_value(power));
        power = power.mul_value(chi);

        let (g1a, g1b) = gate(w_b, v_b, w_x, v_x, F288::ZERO);
        a0 = a0.add_value(g1a.mul_value(power));
        a1 = a1.add_value(g1b.mul_value(power));
        power = power.mul_value(chi);

        let (g2a, g2b) = gate(w_b, v_b, w_y, v_y, F288::ZERO);
        a0 = a0.add_value(g2a.mul_value(power));
        a1 = a1.add_value(g2b.mul_value(power));
        power = power.mul_value(chi);

        let (g3a, g3b) = gate(w_x, v_x, w_y, v_y, v_b);
        a0 = a0.add_value(g3a.mul_value(power));
        a1 = a1.add_value(g3b.mul_value(power));
        power = power.mul_value(chi);

        v_s = v_s_next;
        last_diffusion = diffusion;
        last_v_y = v_y;
    }
    let out_tag = last_diffusion.mul_value(last_v_y).add_value(v_sk);
    (a0, a1, out_tag)
}

fn reconstruct_roots(
    bytes: &[u8; SIGNATURE_LEN],
    salt: &[u8; SALT_LEN],
    pk_hash: &[u8; COMMITMENT_LEN],
    h2: &[u8; H2_LEN],
    roots: &mut [u8; TREE_COUNT * COMMITMENT_LEN],
) {
    for tree_index in 0..TREE_COUNT {
        let hidden = read::<COMMITMENT_LEN>(
            bytes,
            HIDDEN_OFF.wrapping_add(tree_index.wrapping_mul(COMMITMENT_LEN)),
        )
        .unwrap_or([0u8; COMMITMENT_LEN]);
        let mut copath = [[0u8; FIELD_BYTES]; TREE_DEPTH];
        for level in 0..TREE_DEPTH {
            let seed = read::<FIELD_BYTES>(
                bytes,
                COPATH_OFF
                    .wrapping_add(tree_index.wrapping_mul(TREE_DEPTH * FIELD_BYTES))
                    .wrapping_add(level.wrapping_mul(FIELD_BYTES)),
            )
            .unwrap_or([0u8; FIELD_BYTES]);
            if let Some(slot) = copath.get_mut(level) {
                *slot = seed;
            }
        }
        let alpha = h2.get(tree_index).copied().unwrap_or(0);
        let root = reconstruct_root(
            hidden,
            &copath,
            u16::try_from(tree_index).unwrap_or(0),
            alpha,
            salt,
            pk_hash,
        );
        copy_at(roots, tree_index.wrapping_mul(COMMITMENT_LEN), &root);
    }
}

fn squeeze_challenges(transcript: &mut Transcript) -> (F288, F288, [u8; H2_LEN]) {
    let mut delta_bytes = [0u8; FIELD_BYTES];
    let mut chi_bytes = [0u8; FIELD_BYTES];
    let mut h2 = [0u8; H2_LEN];
    transcript.squeeze("DELTA", &mut delta_bytes);
    transcript.squeeze("CHI", &mut chi_bytes);
    transcript.squeeze("H2", &mut h2);
    (
        nonzero(F288::from_bytes(delta_bytes)),
        nonzero(F288::from_bytes(chi_bytes)),
        h2,
    )
}

fn opened_wires(bytes: &[u8; SIGNATURE_LEN], delta: F288, q_open: &mut [F288; SECRET_WIRES]) {
    for index in 0..SECRET_WIRES {
        let commitment = read::<COMMITMENT_LEN>(
            bytes,
            HIDDEN_OFF.wrapping_add(index.wrapping_mul(COMMITMENT_LEN)),
        )
        .unwrap_or([0u8; COMMITMENT_LEN]);
        let opening = read::<FIELD_BYTES>(
            bytes,
            WIRE_D_OFF.wrapping_add(index.wrapping_mul(FIELD_BYTES)),
        )
        .unwrap_or([0u8; FIELD_BYTES]);
        let q = field_from_commitment(&commitment);
        let d = F288::from_bytes(opening);
        if let Some(slot) = q_open.get_mut(index) {
            *slot = q.add_value(d.mul_value(delta));
        }
    }
}

fn check_proof(
    public_key: &PublicKey,
    bytes: &[u8; SIGNATURE_LEN],
    delta: F288,
    chi: F288,
    q_open: &[F288; SECRET_WIRES],
    constants: &RainConstants,
) -> bool {
    let hidden_mask = read::<COMMITMENT_LEN>(
        bytes,
        HIDDEN_OFF.wrapping_add(MASK_TREE.wrapping_mul(COMMITMENT_LEN)),
    )
    .unwrap_or([0u8; COMMITMENT_LEN]);
    let q_star = field_from_commitment(&hidden_mask);
    let u_field = read::<FIELD_BYTES>(bytes, U_OFF).unwrap_or([0u8; FIELD_BYTES]);
    let v_field = read::<FIELD_BYTES>(bytes, V_OFF).unwrap_or([0u8; FIELD_BYTES]);
    let out_tag_bytes = read::<FIELD_BYTES>(bytes, OUT_TAG_OFF).unwrap_or([0u8; FIELD_BYTES]);
    let masked_u = F288::from_bytes(u_field);
    let masked_v = F288::from_bytes(v_field);
    let out_tag = F288::from_bytes(out_tag_bytes);

    let q_sk = q_open.first().copied().unwrap_or(F288::ZERO);
    let mut q_s = public_key.pt().mul_value(delta);
    let mut batch = F288::ZERO;
    let mut power = F288::ONE;
    let mut last_diffusion = F288::ZERO;
    let mut last_q_y = F288::ZERO;
    for round in 0..ROUNDS {
        let q_y = q_open
            .get(1usize.wrapping_add(round))
            .copied()
            .unwrap_or(F288::ZERO);
        let q_b = q_open
            .get(1usize.wrapping_add(ROUNDS).wrapping_add(round))
            .copied()
            .unwrap_or(F288::ZERO);
        let diffusion = constants
            .diffusion
            .get(round)
            .copied()
            .unwrap_or(F288::ZERO);
        let round_constant = constants.round.get(round).copied().unwrap_or(F288::ZERO);
        let q_x = q_s
            .add_value(q_sk)
            .add_value(round_constant.mul_value(delta));
        let q_s_next = diffusion.mul_value(q_y);

        let b0 = q_b.mul_value(q_b).add_value(q_b.mul_value(delta));
        batch = batch.add_value(b0.mul_value(power));
        power = power.mul_value(chi);
        let b1 = q_b.mul_value(q_x);
        batch = batch.add_value(b1.mul_value(power));
        power = power.mul_value(chi);
        let b2 = q_b.mul_value(q_y);
        batch = batch.add_value(b2.mul_value(power));
        power = power.mul_value(chi);
        let q_c = delta.add_value(q_b);
        let b3 = q_x.mul_value(q_y).add_value(q_c.mul_value(delta));
        batch = batch.add_value(b3.mul_value(power));
        power = power.mul_value(chi);

        q_s = q_s_next;
        last_diffusion = diffusion;
        last_q_y = q_y;
    }

    let q_ct = last_diffusion.mul_value(last_q_y).add_value(q_sk);
    let output_ok = q_ct == out_tag.add_value(public_key.ct().mul_value(delta));
    let mask_ok = batch.add_value(q_star) == masked_u.add_value(masked_v.mul_value(delta));
    output_ok && mask_ok
}

#[inline]
fn gate(a_w: F288, a_v: F288, b_w: F288, b_v: F288, c_v: F288) -> (F288, F288) {
    let a0 = a_v.mul_value(b_v);
    let a1 = a_w
        .mul_value(b_v)
        .add_value(b_w.mul_value(a_v))
        .add_value(c_v);
    (a0, a1)
}

#[inline]
fn tree_root_seed(master: &[u8; FIELD_BYTES], tree_index: u16) -> [u8; FIELD_BYTES] {
    let mut data = [0u8; FIELD_BYTES + 2];
    let (master_slot, index_slot) = data.split_at_mut(FIELD_BYTES);
    master_slot.copy_from_slice(master);
    index_slot.copy_from_slice(&tree_index.to_le_bytes());
    let mut seed = [0u8; FIELD_BYTES];
    derive_key_words(crate::ggm::TREE_ROOT_KEY, &data, &mut seed);
    wipe_bytes(&mut data);
    seed
}

#[inline]
fn field_from_commitment(commitment: &[u8; COMMITMENT_LEN]) -> F288 {
    let (source, _rest) = commitment.split_at(FIELD_BYTES);
    let mut array = [0u8; FIELD_BYTES];
    array.copy_from_slice(source);
    F288::from_bytes(array)
}

#[inline]
fn nonzero(value: F288) -> F288 {
    let zero = value.ct_is_zero();
    F288::ct_select(zero, value, F288::ONE)
}

#[inline]
fn copy_at(destination: &mut [u8], offset: usize, source: &[u8]) {
    let Some(end) = offset.checked_add(source.len()) else {
        return;
    };
    if let Some(slot) = destination.get_mut(offset..end) {
        slot.copy_from_slice(source);
    }
}

#[inline]
fn read<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let source = bytes.get(offset..end)?;
    let mut array = [0u8; N];
    array.copy_from_slice(source);
    Some(array)
}

#[inline]
fn write_field(bytes: &mut [u8; PUBLIC_KEY_LEN], offset: usize, value: F288) {
    let Some(end) = offset.checked_add(FIELD_BYTES) else {
        return;
    };
    if let Some(slot) = bytes.get_mut(offset..end) {
        slot.copy_from_slice(&value.to_bytes());
    }
}

#[cfg(all(test, not(any(feature = "nist1", feature = "nist3"))))]
mod tests {
    use super::{copy_at, read, write_field};
    use crate::field::F288;

    #[test]
    fn bounds_helpers_fail_closed() {
        let mut buffer = [0u8; 4];
        copy_at(&mut buffer, usize::MAX, &[1]);
        copy_at(&mut buffer, 3, &[1, 2]);
        assert_eq!(read::<4>(&[0u8; 4], usize::MAX), None);
        assert_eq!(read::<4>(&[0u8; 4], 3), None);
        let mut field_bytes = [0u8; 72];
        write_field(&mut field_bytes, usize::MAX, F288::ONE);
        write_field(&mut field_bytes, 70, F288::ONE);
        write_field(&mut field_bytes, 0, F288::ONE);
        assert_eq!(read::<36>(&field_bytes, 0), Some(F288::ONE.to_bytes()));
    }
}

#[cfg(feature = "bench-api")]
pub(crate) mod bench {
    use super::{
        COMMITMENT_LEN, ExpandedSecretKey, F288, FIELD_BYTES, H2_LEN, Openings, PublicKey,
        RainConstants, RainWitness, SALT_LEN, SECRET_WIRES, SIGNATURE_LEN, TREE_COUNT, Wires,
        check_proof, derive_roots, fill_openings, fill_wires, master_seed, opened_wires, prove,
        public_key_hash, reconstruct_roots, salt_from_master,
    };

    pub fn master_seed_bench(
        secret: &ExpandedSecretKey,
        public_key: &PublicKey,
        message: &[u8],
        entropy: &[u8; 32],
    ) -> [u8; FIELD_BYTES] {
        master_seed(secret, public_key, message, entropy)
    }

    pub fn salt_bench(master: &[u8; FIELD_BYTES]) -> [u8; SALT_LEN] {
        salt_from_master(master)
    }

    pub fn pk_hash_bench(public_key: &PublicKey) -> [u8; COMMITMENT_LEN] {
        public_key_hash(public_key)
    }

    pub fn roots_bench(
        master: &[u8; FIELD_BYTES],
        salt: &[u8; SALT_LEN],
        pk_hash: &[u8; COMMITMENT_LEN],
    ) -> [u8; TREE_COUNT * COMMITMENT_LEN] {
        let mut roots = [0u8; TREE_COUNT * COMMITMENT_LEN];
        derive_roots(master, salt, pk_hash, &mut roots);
        roots
    }

    pub fn openings_bench(
        master: &[u8; FIELD_BYTES],
        salt: &[u8; SALT_LEN],
        pk_hash: &[u8; COMMITMENT_LEN],
        h2: &[u8; H2_LEN],
        signature: &mut [u8; SIGNATURE_LEN],
    ) -> ([F288; TREE_COUNT], [F288; TREE_COUNT]) {
        let mut openings = Openings {
            u: [F288::ZERO; TREE_COUNT],
            q: [F288::ZERO; TREE_COUNT],
        };
        fill_openings(master, salt, pk_hash, h2, signature, &mut openings);
        (openings.u, openings.q)
    }

    pub fn wires_bench(
        sk: F288,
        witness: &RainWitness,
        u_values: &[F288; TREE_COUNT],
        q_values: &[F288; TREE_COUNT],
        delta: F288,
        signature: &mut [u8; SIGNATURE_LEN],
    ) -> ([F288; SECRET_WIRES], [F288; SECRET_WIRES]) {
        let openings = Openings {
            u: *u_values,
            q: *q_values,
        };
        let mut wires = Wires {
            values: [F288::ZERO; SECRET_WIRES],
            tags: [F288::ZERO; SECRET_WIRES],
        };
        fill_wires(sk, witness, &openings, delta, signature, &mut wires);
        (wires.values, wires.tags)
    }

    pub fn prove_bench(
        witness: &RainWitness,
        wire_w: &[F288; SECRET_WIRES],
        tags: &[F288; SECRET_WIRES],
        chi: F288,
        constants: &RainConstants,
    ) -> (F288, F288, F288) {
        prove(witness, wire_w, tags, chi, constants)
    }

    pub fn opened_wires_bench(bytes: &[u8; SIGNATURE_LEN], delta: F288) -> [F288; SECRET_WIRES] {
        let mut q_open = [F288::ZERO; SECRET_WIRES];
        opened_wires(bytes, delta, &mut q_open);
        q_open
    }

    pub fn check_proof_bench(
        public_key: &PublicKey,
        bytes: &[u8; SIGNATURE_LEN],
        delta: F288,
        chi: F288,
        q_open: &[F288; SECRET_WIRES],
        constants: &RainConstants,
    ) -> bool {
        check_proof(public_key, bytes, delta, chi, q_open, constants)
    }

    pub fn reconstruct_roots_bench(
        bytes: &[u8; SIGNATURE_LEN],
        salt: &[u8; SALT_LEN],
        pk_hash: &[u8; COMMITMENT_LEN],
        h2: &[u8; H2_LEN],
    ) -> [u8; TREE_COUNT * COMMITMENT_LEN] {
        let mut roots = [0u8; TREE_COUNT * COMMITMENT_LEN];
        reconstruct_roots(bytes, salt, pk_hash, h2, &mut roots);
        roots
    }
}

#[cfg(all(test, any(feature = "nist1", feature = "nist3")))]
mod profile_tests {
    use super::{copy_at, read, write_field};
    use crate::PUBLIC_KEY_LEN;
    use crate::field::F288;

    #[test]
    fn profile_bounds_helpers_fail_closed() {
        let mut buffer = [0u8; 4];
        copy_at(&mut buffer, usize::MAX, &[1]);
        copy_at(&mut buffer, 3, &[1, 2]);
        assert!(read::<4>(&[0u8; 4], usize::MAX).is_none());
        assert!(read::<4>(&[0u8; 4], 3).is_none());
        let mut field_bytes = [0u8; PUBLIC_KEY_LEN];
        write_field(&mut field_bytes, usize::MAX, F288::ONE);
        write_field(&mut field_bytes, PUBLIC_KEY_LEN, F288::ONE);
        write_field(&mut field_bytes, 0, F288::ONE);
    }
}
