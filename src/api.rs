use serde_json::Value;

pub struct OsvClient {
    base: url::Url,
}

impl OsvClient {
    pub fn new() -> Result<Self, anyhow::Error> {
        let base = url::Url::parse("https://api.osv.dev")?;
        Ok(OsvClient { base })
    }

    pub fn query(&self, package: &str, ecosystem: &str, version: &str) -> Result<Value, anyhow::Error> {
        let endpoint = self.base.join("/v1/query")?;
        let response = ureq::post(endpoint.as_str())
            .set("content-type", "application/json")
            .send_json(&serde_json::json!({
                "package": { "name": package, "ecosystem": ecosystem },
                "version": version,
            }))?;

        let status = response.status();
        if status != 200 {
            let body = response.into_string().unwrap_or_default();
            return Err(anyhow::anyhow!("OSV query failed: HTTP {} body={}", status, body));
        }
        let text = response.into_string()?;
        Ok(serde_json::from_str(&text)?)
    }
}
