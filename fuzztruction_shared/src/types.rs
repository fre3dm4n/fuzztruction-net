use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct MutationSiteID(pub u64);

static MUTATION_SITE_ID_INVALID: u64 = 0;
lazy_static! {
    static ref MUTATION_SITE_ID_CTR: Mutex<u64> = Mutex::new(MUTATION_SITE_ID_INVALID + 1);
    static ref MUTATION_SITE_ID_MAP: Mutex<HashMap<(usize, usize, usize), MutationSiteID>> =
        Mutex::new(HashMap::new());
}

impl MutationSiteID {
    pub fn get(base_offset: usize, inode: usize, section_file_offset: usize) -> MutationSiteID {
        let mut ctr = MUTATION_SITE_ID_CTR.lock().unwrap();
        let mut map = MUTATION_SITE_ID_MAP.lock().unwrap();

        let key = (base_offset, inode, section_file_offset);
        if let Some(id) = map.get(&key) {
            id.clone()
        } else {
            let val = MutationSiteID(*ctr);
            let had_val = map.insert(key, val.clone());
            assert!(
                had_val.is_none(),
                "There was already an entry for the given key!"
            );

            *ctr = *ctr + 1;
            val
        }
    }

    pub fn invalid() -> MutationSiteID {
        MutationSiteID(MUTATION_SITE_ID_INVALID)
    }
}

impl ToString for MutationSiteID {
    fn to_string(&self) -> String {
        format!("PatchPointID({})", self.0)
    }
}

impl From<MutationSiteID> for u64 {
    fn from(pp: MutationSiteID) -> Self {
        pp.0
    }
}

impl From<u64> for MutationSiteID {
    fn from(v: u64) -> Self {
        MutationSiteID(v)
    }
}

impl From<usize> for MutationSiteID {
    fn from(v: usize) -> Self {
        MutationSiteID(v as u64)
    }
}

impl From<&MutationSiteID> for usize {
    fn from(pp: &MutationSiteID) -> Self {
        pp.0 as usize
    }
}

impl From<MutationSiteID> for usize {
    fn from(pp: MutationSiteID) -> Self {
        pp.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VAddr(pub u64);

macro_rules! implement_from_for_multiple {
    ($t:ty) => {
        impl From<$t> for VAddr {
            fn from(v: $t) -> Self {
                VAddr(v as u64)
            }
        }
    };
    ($t:ty, $($tt:ty),+) => {
        impl From<$t> for VAddr {
            fn from(v: $t) -> Self {
                VAddr(v as u64)
            }
        }
        implement_from_for_multiple!($($tt),+);
    };
}

implement_from_for_multiple!(u8, u16, u32, u64, usize);
