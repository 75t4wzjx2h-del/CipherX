// CipherX — RocksDB Persistence
//
// Column families:
//   blocks_by_hash   — hash   → bincode(Block)
//   blocks_by_height — height → hash(32 bytes)
//   key_images       — [u8;32] → b"1" (presence = spent)
//   chain_state      — "height" / "tip" → values
//   validators       — nullifier → bincode(validator data)

use rocksdb::{DB, Options, ColumnFamilyDescriptor, WriteBatch};

use crate::core::block::{Block, BlockHash};

const CF_BLOCKS_BY_HASH:   &str = "blocks_by_hash";
const CF_BLOCKS_BY_HEIGHT: &str = "blocks_by_height";
const CF_KEY_IMAGES:       &str = "key_images";
const CF_CHAIN_STATE:      &str = "chain_state";
const CF_VALIDATORS:       &str = "validators";

const KEY_HEIGHT: &[u8] = b"height";
const KEY_TIP:    &[u8] = b"tip";

pub struct CipherXDb {
    db: DB,
}

impl CipherXDb {
    pub fn open(path: &str) -> Result<Self, String> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS_BY_HASH,   Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCKS_BY_HEIGHT, Options::default()),
            ColumnFamilyDescriptor::new(CF_KEY_IMAGES,       Options::default()),
            ColumnFamilyDescriptor::new(CF_CHAIN_STATE,      Options::default()),
            ColumnFamilyDescriptor::new(CF_VALIDATORS,       Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| format!("RocksDB open: {}", e))?;

        Ok(CipherXDb { db })
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn cf(&self, name: &str) -> &rocksdb::ColumnFamily {
        self.db.cf_handle(name).expect("column family must exist")
    }

    // ── Blocks ────────────────────────────────────────────────────────────────

    pub fn put_block(&self, block: &Block) -> Result<(), String> {
        let hash = block.hash();
        let height = block.header.height;
        let encoded = bincode::serialize(block)
            .map_err(|e| format!("block serialize: {}", e))?;

        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf(CF_BLOCKS_BY_HASH),   &hash.0,              &encoded);
        batch.put_cf(self.cf(CF_BLOCKS_BY_HEIGHT), &height.to_le_bytes(), &hash.0);

        self.db.write(batch)
            .map_err(|e| format!("DB write block: {}", e))
    }

    pub fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Option<Block>, String> {
        match self.db.get_cf(self.cf(CF_BLOCKS_BY_HASH), &hash.0)
            .map_err(|e| format!("DB get block: {}", e))?
        {
            None => Ok(None),
            Some(b) => {
                let block = bincode::deserialize(&b)
                    .map_err(|e| format!("block deserialize: {}", e))?;
                Ok(Some(block))
            }
        }
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, String> {
        let hash_bytes = match self.db.get_cf(self.cf(CF_BLOCKS_BY_HEIGHT), &height.to_le_bytes())
            .map_err(|e| format!("DB get height index: {}", e))?
        {
            None => return Ok(None),
            Some(b) => b,
        };
        if hash_bytes.len() < 32 {
            return Err("corrupt height index".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash_bytes[..32]);
        self.get_block_by_hash(&BlockHash(arr))
    }

    // ── Key images (double-spend prevention) ─────────────────────────────────

    pub fn put_key_image(&self, ki: &[u8; 32]) -> Result<(), String> {
        self.db.put_cf(self.cf(CF_KEY_IMAGES), ki, b"1")
            .map_err(|e| format!("DB put key image: {}", e))
    }

    pub fn has_key_image(&self, ki: &[u8; 32]) -> Result<bool, String> {
        Ok(self.db.get_cf(self.cf(CF_KEY_IMAGES), ki)
            .map_err(|e| format!("DB get key image: {}", e))?
            .is_some())
    }

    // ── Chain state ───────────────────────────────────────────────────────────

    pub fn save_chain_state(&self, height: u64, tip: &BlockHash) -> Result<(), String> {
        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf(CF_CHAIN_STATE), KEY_HEIGHT, &height.to_le_bytes());
        batch.put_cf(self.cf(CF_CHAIN_STATE), KEY_TIP,    &tip.0);
        self.db.write(batch)
            .map_err(|e| format!("DB write chain state: {}", e))
    }

    pub fn load_chain_state(&self) -> Result<Option<(u64, BlockHash)>, String> {
        let h = match self.db.get_cf(self.cf(CF_CHAIN_STATE), KEY_HEIGHT)
            .map_err(|e| format!("DB load height: {}", e))? { None => return Ok(None), Some(b) => b };
        let t = match self.db.get_cf(self.cf(CF_CHAIN_STATE), KEY_TIP)
            .map_err(|e| format!("DB load tip: {}", e))? { None => return Ok(None), Some(b) => b };

        if h.len() < 8 || t.len() < 32 {
            return Err("corrupt chain state".to_string());
        }
        let mut height_bytes = [0u8; 8];
        height_bytes.copy_from_slice(&h[..8]);
        let mut tip_bytes = [0u8; 32];
        tip_bytes.copy_from_slice(&t[..32]);

        Ok(Some((u64::from_le_bytes(height_bytes), BlockHash(tip_bytes))))
    }

    // ── Validators ────────────────────────────────────────────────────────────

    pub fn put_validator(&self, nullifier: &[u8; 32], data: &[u8]) -> Result<(), String> {
        self.db.put_cf(self.cf(CF_VALIDATORS), nullifier, data)
            .map_err(|e| format!("DB put validator: {}", e))
    }

    pub fn get_validator(&self, nullifier: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
        self.db.get_cf(self.cf(CF_VALIDATORS), nullifier)
            .map_err(|e| format!("DB get validator: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::Block;
    use std::env;

    fn tmp_db() -> (CipherXDb, String) {
        let path = format!("{}/cipherx_test_{}", env::temp_dir().display(), rand::random::<u64>());
        (CipherXDb::open(&path).unwrap(), path)
    }

    #[test]
    fn test_block_roundtrip() {
        let (db, _path) = tmp_db();
        let block = Block::genesis();
        let hash = block.hash();
        db.put_block(&block).unwrap();
        let loaded = db.get_block_by_hash(&hash).unwrap().unwrap();
        assert_eq!(loaded.header.height, block.header.height);
    }

    #[test]
    fn test_block_by_height() {
        let (db, _path) = tmp_db();
        let block = Block::genesis();
        db.put_block(&block).unwrap();
        let loaded = db.get_block_by_height(0).unwrap().unwrap();
        assert_eq!(loaded.header.height, 0);
    }

    #[test]
    fn test_key_image() {
        let (db, _path) = tmp_db();
        let ki = [7u8; 32];
        assert!(!db.has_key_image(&ki).unwrap());
        db.put_key_image(&ki).unwrap();
        assert!(db.has_key_image(&ki).unwrap());
    }

    #[test]
    fn test_chain_state_roundtrip() {
        let (db, _path) = tmp_db();
        let tip = BlockHash([0xABu8; 32]);
        db.save_chain_state(42, &tip).unwrap();
        let (h, t) = db.load_chain_state().unwrap().unwrap();
        assert_eq!(h, 42);
        assert_eq!(t, tip);
    }

    #[test]
    fn test_empty_chain_state() {
        let (db, _path) = tmp_db();
        assert!(db.load_chain_state().unwrap().is_none());
    }
}
