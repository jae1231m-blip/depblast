use std::path::PathBuf;
use std::time::{SystemTime, Duration};
use serde_json::Value;

pub const CACHE_DIR_NAME: &str = "depblast";
pub const CACHE_TTL_DAYS: u64 = 30;

pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    pub fn new() -> Result<Self, anyhow::Error> {
        let dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(CACHE_DIR_NAME);
        if !dir.exists() {
            std::fs::create_dir_all(&dir)?;
        }
        Ok(Cache { dir })
    }

    pub fn get(&self, package: &str, version: &str) -> Result<Option<Value>, anyhow::Error> {
        let file = self.dir.join(cache_key(package, version));
        if !file.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&file)?;
        let entry: CacheEntry = serde_json::from_str(&data)?;
        if entry.expires_at > SystemTime::now() {
            Ok(Some(entry.data))
        } else {
            // Expired; drop it so the directory stays tidy.
            let _ = std::fs::remove_file(&file);
            Ok(None)
        }
    }

    pub fn set(&self, package: &str, version: &str, data: Value) -> Result<(), anyhow::Error> {
        let file = self.dir.join(cache_key(package, version));
        let entry = CacheEntry {
            data: data.clone(),
            fetched_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(CACHE_TTL_DAYS * 86_400),
        };
        std::fs::write(&file, serde_json::to_string_pretty(&entry)?)?;
        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheEntry {
    data: Value,
    fetched_at: SystemTime,
    expires_at: SystemTime,
}

fn cache_key(package: &str, version: &str) -> String {
    let mut k = format!("{package}-{version}");
    k = k.replace(['/', '\\', ':', ' '], "_");
    k
}
