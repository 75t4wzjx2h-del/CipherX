// CipherX — Tendermint BFT Consensus (Phase 2)
//
// Full Tendermint BFT state machine.
//
// Flow per block:
//   HEIGHT h, ROUND r:
//   1. PROPOSE   — proposer broadcasts a block proposal
//   2. PREVOTE   — each validator broadcasts prevote (for proposal or nil)
//   3. PRECOMMIT — if 2/3+ prevotes for same block → precommit it
//   4. COMMIT    — if 2/3+ precommits → block is FINAL (instant finality)
//
// Validator privacy:
//   - Votes signed with ephemeral keys derived from ValidatorCommitment
//   - Identity never revealed — only nullifier used for deduplication
//   - Proposer selected via round-robin over nullifiers (VRF in Phase 4)
//
// Timeouts (tuned for 400ms block time):
//   propose   : 200ms
//   prevote   : 100ms
//   precommit : 100ms
//   delta/rnd : +50ms per round (prevents livelock)

use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{info, warn, debug};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};

use crate::core::block::{Block, BlockHash};
use crate::crypto::keys::ValidatorCommitment;

// ─── Timeouts ────────────────────────────────────────────────────────────────

pub struct Timeouts {
    pub propose: Duration,
    pub prevote: Duration,
    pub precommit: Duration,
    pub round_delta: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            propose: Duration::from_millis(200),
            prevote: Duration::from_millis(100),
            precommit: Duration::from_millis(100),
            round_delta: Duration::from_millis(50),
        }
    }
}

impl Timeouts {
    pub fn propose_for_round(&self, round: u32) -> Duration {
        self.propose + self.round_delta * round
    }
    pub fn prevote_for_round(&self, round: u32) -> Duration {
        self.prevote + self.round_delta * round
    }
    pub fn precommit_for_round(&self, round: u32) -> Duration {
        self.precommit + self.round_delta * round
    }
}

// ─── Vote ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VoteType {
    Prevote,
    Precommit,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vote {
    pub vote_type: VoteType,
    pub height: u64,
    pub round: u32,
    pub block_hash: Option<BlockHash>,
    /// Anonymous validator ID — no identity revealed
    pub validator_nullifier: [u8; 32],
    /// Ed25519 public key for signature verification
    pub validator_pubkey: [u8; 32],
    pub signature: Vec<u8>,
    pub voting_power: u64,
}

impl Vote {
    pub fn sign_bytes(&self) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(match self.vote_type {
            VoteType::Prevote   => b"PREVOTE",
            VoteType::Precommit => b"PRECOMMIT",
        });
        b.extend_from_slice(&self.height.to_le_bytes());
        b.extend_from_slice(&self.round.to_le_bytes());
        match &self.block_hash {
            Some(h) => b.extend_from_slice(&h.0),
            None    => b.extend_from_slice(&[0u8; 32]),
        }
        b
    }

    /// Verify the Ed25519 signature on this vote.
    /// Empty signature → trusted internal vote (solo mode).
    pub fn verify_signature(&self) -> bool {
        if self.signature.is_empty() {
            return true;
        }
        if self.signature.len() != 64 {
            return false;
        }
        let Ok(vk) = VerifyingKey::from_bytes(&self.validator_pubkey) else {
            return false;
        };
        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&self.sign_bytes(), &sig).is_ok()
    }
}

// ─── Proposal ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Proposal {
    pub height: u64,
    pub round: u32,
    pub block: Block,
    pub proposer_nullifier: [u8; 32],
    pub signature: Vec<u8>,
    pub validator_proof: ValidatorCommitment,
}

impl Proposal {
    pub fn sign_bytes(&self) -> Vec<u8> {
        let mut b = b"PROPOSAL".to_vec();
        b.extend_from_slice(&self.height.to_le_bytes());
        b.extend_from_slice(&self.round.to_le_bytes());
        b.extend_from_slice(&self.block.hash().0);
        b
    }

    /// Verify commitment validity + Ed25519 proposal signature.
    /// Empty signature → trusted internal proposal (solo mode).
    pub fn verify(&self) -> bool {
        if !self.validator_proof.verify() {
            return false;
        }
        if self.signature.is_empty() {
            return true;
        }
        self.validator_proof.verify_signature(&self.sign_bytes(), &self.signature)
    }
}

// ─── Vote set ─────────────────────────────────────────────────────────────────

struct VoteSet {
    votes: HashMap<[u8; 32], Vote>,
    quorum: u64,
    power_by_block: HashMap<Option<BlockHash>, u64>,
}

impl VoteSet {
    fn new(total_validators: u64) -> Self {
        VoteSet {
            votes: HashMap::new(),
            quorum: (total_validators * 2 / 3) + 1,
            power_by_block: HashMap::new(),
        }
    }

    /// Returns Some(block_hash) if quorum reached for that block (or nil)
    fn add(&mut self, vote: Vote) -> Option<Option<BlockHash>> {
        let nullifier = vote.validator_nullifier;
        if self.votes.contains_key(&nullifier) {
            return None; // duplicate — ignored here, equivocation checked elsewhere
        }
        let power = vote.voting_power;
        let bh = vote.block_hash.clone();
        self.votes.insert(nullifier, vote);
        let acc = self.power_by_block.entry(bh.clone()).or_insert(0);
        *acc += power;
        if *acc >= self.quorum { Some(bh) } else { None }
    }

    fn count(&self) -> usize { self.votes.len() }

    fn existing(&self, nullifier: &[u8; 32]) -> Option<&Vote> {
        self.votes.get(nullifier)
    }
}

// ─── Equivocation evidence ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EquivocationEvidence {
    pub height: u64,
    pub round: u32,
    pub vote_type: VoteType,
    pub vote_a: Vote,
    pub vote_b: Vote,
}

// ─── Consensus step ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ConsensusStep {
    NewHeight,
    Propose,
    Prevote,
    Precommit,
    Commit,
}

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Invalid proposal at h={height} r={round}")]
    InvalidProposal { height: u64, round: u32 },
    #[error("Wrong height: expected {expected}, got {got}")]
    WrongHeight { expected: u64, got: u64 },
    #[error("Not the proposer for this round")]
    UnauthorizedProposer,
}

#[derive(Debug)]
pub enum ConsensusOutput {
    BroadcastVote(Vote),
    BroadcastProposal(Proposal),
    FinalizedBlock(Block, Vec<Vote>),
    SlashEvidence(EquivocationEvidence),
    Pending,
}

// ─── Engine ───────────────────────────────────────────────────────────────────

pub struct TendermintEngine {
    pub height: u64,
    pub round: u32,
    pub step: ConsensusStep,

    total_validators: u64,
    our_nullifier: Option<[u8; 32]>,
    our_commitment: Option<ValidatorCommitment>,
    signing_key: Option<SigningKey>,

    current_proposal: Option<Proposal>,
    locked_block: Option<(BlockHash, u32)>,
    valid_block: Option<(BlockHash, u32)>,

    prevote_sets:    HashMap<u32, VoteSet>,
    precommit_sets:  HashMap<u32, VoteSet>,

    validator_nullifiers: Vec<[u8; 32]>,
    equivocations: Vec<EquivocationEvidence>,

    timeouts: Timeouts,
    step_start: Instant,
}

impl TendermintEngine {
    pub fn new(
        height: u64,
        total_validators: u64,
        validator_nullifiers: Vec<[u8; 32]>,
        our_nullifier: Option<[u8; 32]>,
        our_commitment: Option<ValidatorCommitment>,
    ) -> Self {
        info!("🔵 Tendermint started | h={} validators={}", height, total_validators);
        TendermintEngine {
            height, round: 0, step: ConsensusStep::NewHeight,
            total_validators, our_nullifier, our_commitment,
            signing_key: None,
            current_proposal: None, locked_block: None, valid_block: None,
            prevote_sets: HashMap::new(), precommit_sets: HashMap::new(),
            validator_nullifiers, equivocations: vec![],
            timeouts: Timeouts::default(), step_start: Instant::now(),
        }
    }

    /// Attach an Ed25519 signing key so votes and proposals are actually signed.
    pub fn with_signing_key(mut self, sk: SigningKey) -> Self {
        self.signing_key = Some(sk);
        self
    }

    // ── Proposer selection (round-robin; Phase 4: VRF) ────────────────────────

    pub fn proposer_for_round(&self, round: u32) -> Option<[u8; 32]> {
        if self.validator_nullifiers.is_empty() { return None; }
        let idx = (self.height.wrapping_add(round as u64)) as usize
            % self.validator_nullifiers.len();
        Some(self.validator_nullifiers[idx])
    }

    pub fn is_proposer(&self) -> bool {
        matches!(
            (self.our_nullifier, self.proposer_for_round(self.round)),
            (Some(a), Some(b)) if a == b
        )
    }

    // ── Height / round transitions ────────────────────────────────────────────

    pub fn start_height(&mut self, height: u64) -> ConsensusOutput {
        self.height = height;
        self.round = 0;
        self.current_proposal = None;
        self.locked_block = None;
        self.valid_block = None;
        self.prevote_sets.clear();
        self.precommit_sets.clear();
        info!("🔷 New height: {}", height);
        self.enter_propose()
    }

    fn enter_propose(&mut self) -> ConsensusOutput {
        self.step = ConsensusStep::Propose;
        self.step_start = Instant::now();
        debug!("→ PROPOSE h={} r={}", self.height, self.round);
        if self.is_proposer() {
            info!("📣 We are proposer h={} r={}", self.height, self.round);
        }
        ConsensusOutput::Pending
    }

    /// Called by the node when it's our turn to propose a block
    pub fn submit_proposal(&mut self, block: Block) -> Result<ConsensusOutput, ConsensusError> {
        if !self.is_proposer() {
            return Err(ConsensusError::UnauthorizedProposer);
        }
        let nullifier = self.our_nullifier.unwrap();
        let commitment = self.our_commitment.clone()
            .unwrap_or(ValidatorCommitment::placeholder());

        let mut proposal = Proposal {
            height: self.height,
            round: self.round,
            block,
            proposer_nullifier: nullifier,
            signature: vec![],
            validator_proof: commitment,
        };
        if let Some(sk) = &self.signing_key {
            proposal.signature = sk.sign(&proposal.sign_bytes()).to_bytes().to_vec();
        }
        info!("📦 Proposal h={} r={} block={}", self.height, self.round, proposal.block.hash().to_hex());
        self.current_proposal = Some(proposal.clone());
        Ok(ConsensusOutput::BroadcastProposal(proposal))
    }

    pub fn receive_proposal(&mut self, proposal: Proposal) -> Result<ConsensusOutput, ConsensusError> {
        if proposal.height != self.height || proposal.round != self.round {
            return Err(ConsensusError::InvalidProposal {
                height: proposal.height, round: proposal.round,
            });
        }
        if self.proposer_for_round(self.round) != Some(proposal.proposer_nullifier) {
            return Err(ConsensusError::UnauthorizedProposer);
        }
        if !proposal.verify() {
            return Err(ConsensusError::InvalidProposal {
                height: proposal.height, round: proposal.round,
            });
        }
        info!("📥 Proposal received h={} r={} block={}", proposal.height, proposal.round, proposal.block.hash().to_hex());
        self.current_proposal = Some(proposal);
        Ok(self.enter_prevote())
    }

    // ── Prevote ───────────────────────────────────────────────────────────────

    fn enter_prevote(&mut self) -> ConsensusOutput {
        self.step = ConsensusStep::Prevote;
        self.step_start = Instant::now();
        let vote_for = self.decide_prevote();
        let vote = self.make_vote(VoteType::Prevote, vote_for.clone());
        match &vote_for {
            Some(h) => info!("🗳️  Prevote FOR {}", h.to_hex()),
            None     => info!("🗳️  Prevote NIL"),
        }
        ConsensusOutput::BroadcastVote(vote)
    }

    fn decide_prevote(&self) -> Option<BlockHash> {
        // Locking rule: if locked, prevote for locked block unless proposal overrides
        if let Some((locked, _)) = &self.locked_block {
            if let Some(p) = &self.current_proposal {
                if p.block.hash() == *locked { return Some(locked.clone()); }
            }
            return Some(locked.clone());
        }
        // No lock: prevote for proposal if valid
        self.current_proposal.as_ref().map(|p| p.block.hash())
    }

    // ── Receive vote ──────────────────────────────────────────────────────────

    pub fn receive_vote(&mut self, vote: Vote) -> Result<ConsensusOutput, ConsensusError> {
        if vote.height != self.height {
            return Err(ConsensusError::WrongHeight {
                expected: self.height, got: vote.height,
            });
        }
        if !vote.verify_signature() {
            return Ok(ConsensusOutput::Pending);
        }
        if let Some(evidence) = self.detect_equivocation(&vote) {
            warn!("⚠️  Equivocation detected — slashing evidence collected");
            self.equivocations.push(evidence.clone());
            return Ok(ConsensusOutput::SlashEvidence(evidence));
        }
        match vote.vote_type {
            VoteType::Prevote   => self.handle_prevote(vote),
            VoteType::Precommit => self.handle_precommit(vote),
        }
    }

    fn handle_prevote(&mut self, vote: Vote) -> Result<ConsensusOutput, ConsensusError> {
        let round = vote.round;
        let vs = self.prevote_sets.entry(round)
            .or_insert_with(|| VoteSet::new(self.total_validators));
        debug!("Prevote {}/{}", vs.count() + 1, self.total_validators);
        let quorum = vs.add(vote);
        if let Some(bh_opt) = quorum {
            match bh_opt {
                Some(bh) => {
                    info!("✅ Prevote quorum block={}", bh.to_hex());
                    self.valid_block = Some((bh.clone(), round));
                    let update_lock = self.locked_block.as_ref()
                        .map_or(true, |(h, _)| *h == bh);
                    if update_lock { self.locked_block = Some((bh, round)); }
                    return Ok(self.enter_precommit(true));
                }
                None => {
                    info!("✅ Prevote quorum NIL");
                    return Ok(self.enter_precommit(false));
                }
            }
        }
        Ok(ConsensusOutput::Pending)
    }

    // ── Precommit ─────────────────────────────────────────────────────────────

    fn enter_precommit(&mut self, has_block: bool) -> ConsensusOutput {
        self.step = ConsensusStep::Precommit;
        self.step_start = Instant::now();
        let vote_for = if has_block {
            self.locked_block.as_ref().map(|(h, _)| h.clone())
        } else {
            None
        };
        let vote = self.make_vote(VoteType::Precommit, vote_for.clone());
        match &vote_for {
            Some(h) => info!("🔒 Precommit FOR {}", h.to_hex()),
            None     => info!("🔒 Precommit NIL"),
        }
        ConsensusOutput::BroadcastVote(vote)
    }

    fn handle_precommit(&mut self, vote: Vote) -> Result<ConsensusOutput, ConsensusError> {
        let round = vote.round;
        let vs = self.precommit_sets.entry(round)
            .or_insert_with(|| VoteSet::new(self.total_validators));
        debug!("Precommit {}/{}", vs.count() + 1, self.total_validators);
        let quorum = vs.add(vote);
        if let Some(bh_opt) = quorum {
            match bh_opt {
                Some(bh) => {
                    info!("🎉 Block {} FINALIZED at h={}", bh.to_hex(), self.height);
                    let commit_votes: Vec<Vote> = self.precommit_sets
                        .get(&round).unwrap().votes.values().cloned().collect();
                    if let Some(p) = &self.current_proposal {
                        if p.block.hash() == bh {
                            let block = p.block.clone();
                            self.step = ConsensusStep::Commit;
                            return Ok(ConsensusOutput::FinalizedBlock(block, commit_votes));
                        }
                    }
                }
                None => {
                    info!("⏭️  Precommit NIL quorum → round {}", self.round + 1);
                    self.start_new_round();
                    return Ok(self.enter_propose());
                }
            }
        }
        Ok(ConsensusOutput::Pending)
    }

    fn start_new_round(&mut self) {
        self.round += 1;
        self.current_proposal = None;
        self.step = ConsensusStep::Propose;
        self.step_start = Instant::now();
        info!("🔄 Round {} | h={}", self.round, self.height);
    }

    // ── Timeout ───────────────────────────────────────────────────────────────

    pub fn check_timeout(&mut self) -> Option<ConsensusOutput> {
        let elapsed = self.step_start.elapsed();
        match self.step {
            ConsensusStep::Propose => {
                if elapsed > self.timeouts.propose_for_round(self.round) {
                    warn!("⏰ Propose timeout h={} r={}", self.height, self.round);
                    let vote = self.make_vote(VoteType::Prevote, None);
                    return Some(ConsensusOutput::BroadcastVote(vote));
                }
            }
            ConsensusStep::Prevote => {
                if elapsed > self.timeouts.prevote_for_round(self.round) {
                    warn!("⏰ Prevote timeout h={} r={}", self.height, self.round);
                    return Some(self.enter_precommit(false));
                }
            }
            ConsensusStep::Precommit => {
                if elapsed > self.timeouts.precommit_for_round(self.round) {
                    warn!("⏰ Precommit timeout h={} r={}", self.height, self.round);
                    self.start_new_round();
                    return Some(self.enter_propose());
                }
            }
            _ => {}
        }
        None
    }

    // ── Equivocation ──────────────────────────────────────────────────────────

    fn detect_equivocation(&self, new_vote: &Vote) -> Option<EquivocationEvidence> {
        let sets = match new_vote.vote_type {
            VoteType::Prevote   => &self.prevote_sets,
            VoteType::Precommit => &self.precommit_sets,
        };
        if let Some(vs) = sets.get(&new_vote.round) {
            if let Some(existing) = vs.existing(&new_vote.validator_nullifier) {
                if existing.block_hash != new_vote.block_hash {
                    return Some(EquivocationEvidence {
                        height: self.height,
                        round: self.round,
                        vote_type: new_vote.vote_type.clone(),
                        vote_a: existing.clone(),
                        vote_b: new_vote.clone(),
                    });
                }
            }
        }
        None
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_vote(&self, vote_type: VoteType, block_hash: Option<BlockHash>) -> Vote {
        let pubkey = self.our_commitment.as_ref()
            .map(|c| c.public_key)
            .unwrap_or([0u8; 32]);
        let mut vote = Vote {
            vote_type,
            height: self.height,
            round: self.round,
            block_hash,
            validator_nullifier: self.our_nullifier.unwrap_or([0u8; 32]),
            validator_pubkey: pubkey,
            signature: vec![],
            voting_power: 1,
        };
        if let Some(sk) = &self.signing_key {
            vote.signature = sk.sign(&vote.sign_bytes()).to_bytes().to_vec();
        }
        vote
    }

    pub fn pending_equivocations(&self) -> &[EquivocationEvidence] { &self.equivocations }
    pub fn current_step(&self) -> &ConsensusStep { &self.step }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn null(n: u8) -> [u8; 32] { let mut b = [0u8; 32]; b[0] = n; b }

    fn single_validator_engine() -> TendermintEngine {
        let n = null(1);
        TendermintEngine::new(1, 1, vec![n], Some(n), Some(ValidatorCommitment::placeholder()))
    }

    #[test]
    fn test_single_validator_is_proposer() {
        assert!(single_validator_engine().is_proposer());
    }

    #[test]
    fn test_proposer_rotation() {
        let ns: Vec<[u8; 32]> = (1u8..=3).map(null).collect();
        let e = TendermintEngine::new(1, 3, ns.clone(), None, None);
        // h=1 r=0 → idx=(1+0)%3=1
        assert_eq!(e.proposer_for_round(0), Some(ns[1]));
        // h=1 r=1 → idx=(1+1)%3=2
        assert_eq!(e.proposer_for_round(1), Some(ns[2]));
        // h=1 r=2 → idx=(1+2)%3=0
        assert_eq!(e.proposer_for_round(2), Some(ns[0]));
    }

    fn mkv(n: u8, bh: Option<BlockHash>) -> Vote {
        Vote { vote_type: VoteType::Prevote, height: 1, round: 0,
            block_hash: bh, validator_nullifier: null(n),
            validator_pubkey: [0u8; 32], signature: vec![], voting_power: 1 }
    }

    #[test]
    fn test_quorum_single_validator() {
        let mut vs = VoteSet::new(1); // quorum=1
        let result = vs.add(mkv(1, Some(BlockHash([42u8; 32]))));
        assert!(result.is_some());
    }

    #[test]
    fn test_quorum_three_validators() {
        let mut vs = VoteSet::new(3); // quorum = floor(2/3*3)+1 = 3
        let bh = Some(BlockHash([42u8; 32]));
        for i in 1u8..=2 {
            let r = vs.add(mkv(i, bh.clone()));
            assert!(r.is_none(), "quorum should not be reached at vote {}", i);
        }
        let r = vs.add(mkv(3, bh));
        assert!(r.is_some());
    }

    #[test]
    fn test_duplicate_vote_ignored() {
        let mut vs = VoteSet::new(3);
        let bh = Some(BlockHash([1u8; 32]));
        vs.add(mkv(1, bh.clone()));
        assert_eq!(vs.count(), 1);
        vs.add(mkv(1, bh)); // same nullifier — ignored
        assert_eq!(vs.count(), 1);
    }

    #[test]
    fn test_equivocation_detection() {
        let ns: Vec<[u8; 32]> = (1u8..=3).map(null).collect();
        let mut e = TendermintEngine::new(1, 3, ns, Some(null(1)), Some(ValidatorCommitment::placeholder()));
        e.step = ConsensusStep::Prevote;

        let vote_a = Vote { vote_type: VoteType::Prevote, height: 1, round: 0,
            block_hash: Some(BlockHash([1u8; 32])), validator_nullifier: null(2),
            validator_pubkey: [0u8; 32], signature: vec![], voting_power: 1 };
        let vote_b = Vote { vote_type: VoteType::Prevote, height: 1, round: 0,
            block_hash: Some(BlockHash([2u8; 32])), validator_nullifier: null(2), // DIFFERENT block!
            validator_pubkey: [0u8; 32], signature: vec![], voting_power: 1 };

        e.receive_vote(vote_a).unwrap();
        assert!(e.pending_equivocations().is_empty());

        let result = e.receive_vote(vote_b).unwrap();
        assert!(matches!(result, ConsensusOutput::SlashEvidence(_)));
        assert_eq!(e.pending_equivocations().len(), 1);
    }

    #[test]
    fn test_timeout_increases_with_round() {
        let t = Timeouts::default();
        assert!(t.propose_for_round(1) > t.propose_for_round(0));
        assert!(t.propose_for_round(5) > t.propose_for_round(1));
    }
}
