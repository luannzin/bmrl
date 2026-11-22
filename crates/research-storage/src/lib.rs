//! Experiment registry.
//!
//! Every experiment, benchmark and reproduction attempt is stored twice:
//! as a row in `<data>/bmrl.sqlite` (indexed columns plus the full JSON
//! record) and, for experiments, as `<data>/results/<id>.json` so results are
//! diffable and readable without tooling. Failed and negative runs are kept.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Repository root: `$BMR_ROOT`, else the checkout this binary was built from.
pub fn workspace_root() -> PathBuf {
    std::env::var_os("BMR_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            crate_dir.parent().and_then(Path::parent).unwrap_or(crate_dir).to_path_buf()
        })
}

/// Data directory: `$BMR_DATA_DIR`, else `<root>/experiments`.
pub fn data_dir() -> PathBuf {
    std::env::var_os("BMR_DATA_DIR").map(PathBuf::from).unwrap_or_else(|| workspace_root().join("experiments"))
}

/// UTC timestamp, ISO 8601.
pub fn now_iso() -> String {
    iso8601(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()))
}

/// Unix seconds to `YYYY-MM-DDTHH:MM:SSZ` (Hinnant's civil-from-days).
pub fn iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem / 60 % 60, rem % 60)
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS experiments (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    definition_version INTEGER NOT NULL,
    status TEXT NOT NULL,
    result TEXT,
    candidate_anomaly INTEGER NOT NULL DEFAULT 0,
    seed TEXT,
    samples INTEGER,
    reproduced INTEGER,
    verified INTEGER,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    record TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS experiments_kind ON experiments(kind);
CREATE TABLE IF NOT EXISTS benchmarks (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    created_at TEXT NOT NULL,
    record TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    primitive TEXT NOT NULL,
    statement TEXT NOT NULL,
    null_hypothesis TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hypothesis_id TEXT NOT NULL REFERENCES hypotheses(id),
    experiment_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    scope TEXT NOT NULL,
    seed TEXT,
    summary TEXT NOT NULL,
    counterexamples TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_hypothesis ON evidence(hypothesis_id);
CREATE TABLE IF NOT EXISTS reproductions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id TEXT NOT NULL REFERENCES experiments(id),
    created_at TEXT NOT NULL,
    matched INTEGER NOT NULL,
    record TEXT NOT NULL
);
";

pub struct Store {
    conn: Connection,
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir.join("results")).with_context(|| format!("creating {}", dir.display()))?;
        let conn = Connection::open(dir.join("bmrl.sqlite"))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn, dir: dir.to_path_buf() })
    }

    pub fn open_default() -> Result<Self> {
        Self::open(&data_dir())
    }

    /// Next id `<prefix>-NNNN` for `table`. Only ids of exactly that shape
    /// count: `smt-%` also matches `smt-scaling-0002`, which once made the
    /// next smt id skip a number and could have reused an existing id.
    fn next_id(&self, table: &str, prefix: &str) -> Result<String> {
        let mut stmt = self.conn.prepare(&format!("SELECT id FROM {table} WHERE id LIKE ?1"))?;
        let ids = stmt.query_map(params![format!("{prefix}-%")], |r| r.get::<_, String>(0))?;
        let mut n = 0u32;
        for id in ids {
            let id = id?;
            let rest = &id[prefix.len() + 1..];
            if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                n = n.max(rest.parse().unwrap_or(0));
            }
        }
        Ok(format!("{prefix}-{:04}", n + 1))
    }

    pub fn next_experiment_id(&self, kind: &str) -> Result<String> {
        self.next_id("experiments", kind)
    }

    /// Insert an experiment record, or update the same run's record (same id
    /// and start time), and rewrite its JSON file. A different run with the
    /// same id is refused: history is append-only.
    pub fn save_experiment(&self, record: &Value) -> Result<PathBuf> {
        let id = record["id"].as_str().context("record without id")?;
        let changed = self.conn.execute(
            "INSERT INTO experiments (id, kind, name, definition_version, status, result, candidate_anomaly, seed, samples,
                                      reproduced, verified, started_at, finished_at, record)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(id) DO UPDATE SET status = excluded.status, result = excluded.result,
                 candidate_anomaly = excluded.candidate_anomaly, reproduced = excluded.reproduced,
                 verified = excluded.verified, finished_at = excluded.finished_at, record = excluded.record
             WHERE experiments.started_at = excluded.started_at",
            params![
                id,
                record["kind"].as_str(),
                record["name"].as_str(),
                record["definition_version"].as_i64(),
                record["status"].as_str(),
                record["result"].as_str(),
                record["candidate_anomaly"].as_bool().unwrap_or(false),
                record["seed"].as_u64().map(|s| s.to_string()),
                record["samples"].as_i64(),
                record["reproduction"]["matched"].as_bool(),
                record["verification"]["passed"].as_bool(),
                record["started_at"].as_str(),
                record["finished_at"].as_str(),
                serde_json::to_string(record)?,
            ],
        )?;
        anyhow::ensure!(changed == 1, "experiment id {id} already belongs to another run; refusing to overwrite it");
        let path = self.dir.join("results").join(format!("{id}.json"));
        std::fs::write(&path, serde_json::to_string_pretty(record)?)?;
        Ok(path)
    }

    pub fn get_experiment(&self, id: &str) -> Result<Option<Value>> {
        let text: Option<String> =
            self.conn.query_row("SELECT record FROM experiments WHERE id = ?1", params![id], |r| r.get(0)).optional()?;
        text.map(|t| serde_json::from_str(&t).map_err(Into::into)).transpose()
    }

    /// Newest first: id, kind, status, result, anomaly flag, reproduced, verified, finished_at.
    pub fn list_experiments(&self, kind: Option<&str>, limit: usize) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, name, status, result, candidate_anomaly, reproduced, verified, started_at, finished_at
             FROM experiments WHERE (?1 IS NULL OR kind = ?1) ORDER BY started_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![kind, limit as i64], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, String>(0)?,
                "kind": r.get::<_, String>(1)?,
                "name": r.get::<_, String>(2)?,
                "status": r.get::<_, String>(3)?,
                "result": r.get::<_, Option<String>>(4)?,
                "candidate_anomaly": r.get::<_, bool>(5)?,
                "reproduced": r.get::<_, Option<bool>>(6)?,
                "verified": r.get::<_, Option<bool>>(7)?,
                "started_at": r.get::<_, String>(8)?,
                "finished_at": r.get::<_, Option<String>>(9)?,
            }))
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Every experiment record, oldest first.
    pub fn all_experiments(&self) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare("SELECT record FROM experiments ORDER BY started_at, id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|t| Ok(serde_json::from_str(&t?)?)).collect()
    }

    /// Every benchmark record with its kind, oldest first.
    pub fn all_benchmarks(&self) -> Result<Vec<(String, Value)>> {
        let mut stmt = self.conn.prepare("SELECT kind, record FROM benchmarks ORDER BY created_at, id")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        rows.map(|row| {
            let (kind, text) = row?;
            Ok((kind, serde_json::from_str(&text)?))
        })
        .collect()
    }

    /// Store a benchmark in SQLite and as `<data>/benchmarks/<id>.json`.
    pub fn save_benchmark(&self, kind: &str, record: &mut Value) -> Result<String> {
        let id = self.next_id("benchmarks", &format!("bench-{kind}"))?;
        record["id"] = Value::String(id.clone());
        record["kind"] = Value::String(kind.to_string());
        let dir = self.dir.join("benchmarks");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("{id}.json")), serde_json::to_string_pretty(record)?)?;
        self.conn.execute(
            "INSERT INTO benchmarks (id, kind, created_at, record) VALUES (?1, ?2, ?3, ?4)",
            params![id, kind, now_iso(), serde_json::to_string(record)?],
        )?;
        Ok(id)
    }

    pub fn list_benchmarks(&self, limit: usize) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare("SELECT record FROM benchmarks ORDER BY created_at DESC, id DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
        rows.map(|t| Ok(serde_json::from_str(&t?)?)).collect()
    }

    /// Append an erratum to a stored experiment. Records are never edited
    /// otherwise; the original observations stay as they were.
    pub fn add_erratum(&self, id: &str, note: &str) -> Result<Value> {
        let mut rec = self.get_experiment(id)?.with_context(|| format!("no experiment {id}"))?;
        if !rec["errata"].is_array() {
            rec["errata"] = Value::Array(vec![]);
        }
        rec["errata"].as_array_mut().expect("array").push(serde_json::json!({ "note": note, "created_at": now_iso() }));
        self.save_experiment(&rec)?;
        self.conn.execute(
            "UPDATE evidence SET summary = summary || ?2 WHERE experiment_id = ?1",
            params![id, format!(" [ERRATUM: {note}]")],
        )?;
        Ok(rec)
    }

    /// Register a hypothesis (statement text is refreshed, status kept).
    pub fn upsert_hypothesis(&self, id: &str, kind: &str, primitive: &str, statement: &str, null_hypothesis: &str) -> Result<()> {
        let now = now_iso();
        self.conn.execute(
            "INSERT INTO hypotheses (id, kind, primitive, statement, null_hypothesis, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'open', ?6, ?6)
             ON CONFLICT(id) DO UPDATE SET statement = excluded.statement, null_hypothesis = excluded.null_hypothesis,
                 primitive = excluded.primitive",
            params![id, kind, primitive, statement, null_hypothesis, now],
        )?;
        Ok(())
    }

    /// Attach evidence and recompute the hypothesis status from all evidence.
    ///
    /// Status rules (data-derived, never set by hand):
    /// * any `candidate-anomaly` verdict  -> `candidate-unconfirmed`
    /// * else any `reduced-round-only`    -> `supported-reduced-round-only`
    /// * else `negative` from >= 2 seeds  -> `not-supported`
    /// * else one `negative`              -> `not-supported-single-seed`
    /// * else `model-estimate`            -> `modelled`
    /// * else `exact-analysis`            -> `analysed`
    /// * otherwise                        -> `open`
    #[allow(clippy::too_many_arguments)]
    pub fn add_evidence(
        &self,
        hypothesis_id: &str,
        experiment_id: &str,
        verdict: &str,
        scope: &str,
        seed: Option<u64>,
        summary: &str,
        counterexamples: &Value,
    ) -> Result<String> {
        self.conn.execute(
            "INSERT INTO evidence (hypothesis_id, experiment_id, verdict, scope, seed, summary, counterexamples, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![hypothesis_id, experiment_id, verdict, scope, seed.map(|s| s.to_string()), summary, serde_json::to_string(counterexamples)?, now_iso()],
        )?;
        let count = |v: &str| -> Result<i64> {
            Ok(self.conn.query_row(
                "SELECT COUNT(DISTINCT COALESCE(seed, experiment_id)) FROM evidence WHERE hypothesis_id = ?1 AND verdict = ?2",
                params![hypothesis_id, v],
                |r| r.get(0),
            )?)
        };
        let status = if count("candidate-anomaly")? > 0 {
            "candidate-unconfirmed"
        } else if count("reduced-round-only")? > 0 {
            "supported-reduced-round-only"
        } else if count("negative")? >= 2 {
            "not-supported"
        } else if count("negative")? == 1 {
            "not-supported-single-seed"
        } else if count("model-estimate")? > 0 {
            "modelled"
        } else if count("exact-analysis")? > 0 {
            "analysed"
        } else {
            "open"
        };
        self.conn.execute("UPDATE hypotheses SET status = ?2, updated_at = ?3 WHERE id = ?1", params![hypothesis_id, status, now_iso()])?;
        Ok(status.to_string())
    }

    pub fn list_hypotheses(&self) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT h.id, h.kind, h.primitive, h.status, h.statement, h.updated_at,
                    (SELECT COUNT(*) FROM evidence e WHERE e.hypothesis_id = h.id)
             FROM hypotheses h ORDER BY h.id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, String>(0)?, "kind": r.get::<_, String>(1)?, "primitive": r.get::<_, String>(2)?,
                "status": r.get::<_, String>(3)?, "statement": r.get::<_, String>(4)?, "updated_at": r.get::<_, String>(5)?,
                "evidence_count": r.get::<_, i64>(6)?,
            }))
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn hypothesis_evidence(&self, id: &str) -> Result<Vec<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT experiment_id, verdict, scope, seed, summary, counterexamples, created_at FROM evidence
             WHERE hypothesis_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?, r.get::<_, String>(6)?))
        })?;
        rows.map(|row| {
            let (exp, verdict, scope, seed, summary, cx, at) = row?;
            Ok(serde_json::json!({
                "experiment_id": exp, "verdict": verdict, "scope": scope, "seed": seed, "summary": summary,
                "counterexamples": serde_json::from_str::<Value>(&cx)?, "created_at": at,
            }))
        })
        .collect()
    }

    pub fn save_reproduction(&self, experiment_id: &str, matched: bool, record: &Value) -> Result<()> {
        self.conn.execute(
            "INSERT INTO reproductions (experiment_id, created_at, matched, record) VALUES (?1, ?2, ?3, ?4)",
            params![experiment_id, now_iso(), matched, serde_json::to_string(record)?],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn iso_dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_231_006_505), "2009-01-03T18:15:05Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn experiment_roundtrip_and_ids() {
        let dir = std::env::temp_dir().join(format!("bmrl-store-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        assert_eq!(store.next_experiment_id("smt").unwrap(), "smt-0001");
        let mut rec = json!({
            "id": "smt-0001", "kind": "smt", "name": "n", "definition_version": 1, "status": "running",
            "seed": u64::MAX, "samples": 5, "started_at": now_iso(),
        });
        store.save_experiment(&rec).unwrap();
        rec["status"] = json!("completed");
        rec["reproduction"] = json!({ "matched": true });
        store.save_experiment(&rec).unwrap();
        assert_eq!(store.get_experiment("smt-0001").unwrap().unwrap()["status"], "completed");
        assert_eq!(store.next_experiment_id("smt").unwrap(), "smt-0002");
        let list = store.list_experiments(Some("smt"), 10).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["reproduced"], true);
        // A kind whose name extends another's must not shift or reuse its ids.
        let other = json!({ "id": "smt-scaling-0007", "kind": "smt-scaling", "name": "n", "definition_version": 1, "status": "completed", "started_at": "2026-01-01T00:00:00Z" });
        store.save_experiment(&other).unwrap();
        assert_eq!(store.next_experiment_id("smt").unwrap(), "smt-0002");
        // Same id, different run: refused, original kept.
        let mut clash = rec.clone();
        clash["started_at"] = json!("2030-01-01T00:00:00Z");
        assert!(store.save_experiment(&clash).is_err());
        assert_eq!(store.get_experiment("smt-0001").unwrap().unwrap()["started_at"], rec["started_at"]);
        let mut b = json!({ "x": 1 });
        assert_eq!(store.save_benchmark("cpu", &mut b).unwrap(), "bench-cpu-0001");
        assert!(dir.join("results").join("smt-0001.json").exists());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
