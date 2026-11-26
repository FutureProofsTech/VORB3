//! Exercise the non-default benchmark API wrappers.

use vorb3::bench_api::{
    ggm_hidden_opening, ggm_reconstruct_root, ggm_tree_root, secret_parts, sign_check_proof,
    sign_master_seed, sign_opened_wires, sign_openings, sign_prove, sign_public_key_hash,
    sign_reconstruct_roots, sign_roots, sign_salt, sign_wires, transcript_challenges,
};
use vorb3::keys::{ExpandedSecretKey, SecretKey};
use vorb3::rain::{self, RainConstants};
use vorb3::sign::sign_into;
use vorb3::{COMMITMENT_LEN, FIELD_BYTES, SIGNATURE_LEN, TREE_COUNT};

const SEED: &[u8; 36] = include_bytes!("../../kat/seed_sp288_35.bin");
const EXPECTED_PK: &[u8; 72] = include_bytes!("../../kat/pk_sp288_35.bin");
const EXPECTED_SIG: &[u8; SIGNATURE_LEN] = include_bytes!("../../kat/sign_sp288_35.bin");
const MESSAGE: &[u8] = b"VORB3 phase-0 SP288_35";

#[test]
fn bench_api_phases_execute() {
    let compact = SecretKey::from_seed(*SEED);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    let Ok(public) = expanded.public_key() else {
        return;
    };
    assert_eq!(public.as_bytes(), EXPECTED_PK);
    let (sk, pt) = secret_parts(&expanded);
    let constants = RainConstants::derive();
    let (_ct, witness) = rain::encrypt(sk, pt, &constants);

    let master = sign_master_seed(&expanded, &public, MESSAGE, &[0u8; 32]);
    let salt = sign_salt(master);
    let pk_hash = sign_public_key_hash(&public);
    let roots = sign_roots(master, salt, pk_hash);
    let (delta, chi, h2) = transcript_challenges(public.as_bytes(), &salt, MESSAGE, &roots);

    let mut signature = [0u8; SIGNATURE_LEN];
    assert!(sign_into(MESSAGE, &expanded, &[0u8; 32], &mut signature).is_ok());
    let (u_values, q_values) = sign_openings(master, salt, pk_hash, h2, &mut signature);
    let (wire_values, tags) = sign_wires(sk, &witness, &u_values, &q_values, delta, &mut signature);
    let _proof = sign_prove(&witness, &wire_values, &tags, chi, &constants);
    let q_open = sign_opened_wires(EXPECTED_SIG, delta);
    assert!(sign_check_proof(
        &public,
        EXPECTED_SIG,
        delta,
        chi,
        &q_open,
        &constants
    ));
    let reconstructed = sign_reconstruct_roots(EXPECTED_SIG, salt, pk_hash, h2);
    assert_eq!(reconstructed.len(), TREE_COUNT * COMMITMENT_LEN);

    let ggm_seed = [0x42u8; FIELD_BYTES];
    let root = ggm_tree_root(ggm_seed, 0, salt, pk_hash);
    let (hidden, commitment, copath) = ggm_hidden_opening(ggm_seed, 0, 42, salt, pk_hash);
    let _ = hidden;
    assert_eq!(
        ggm_reconstruct_root(commitment, copath, 0, 42, salt, pk_hash),
        root
    );
}
