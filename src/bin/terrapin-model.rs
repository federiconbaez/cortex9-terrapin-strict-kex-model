use cortex9_terrapin_strict_kex_model::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

fn usage() -> ! {
    eprintln!(
        "usage:\n  terrapin-model run <scenario.json>\n  terrapin-model matrix <scenarios_dir> <sweep_dir> <out_dir>"
    );
    std::process::exit(2)
}

fn load(p: &Path) -> Scenario {
    let s = fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {}: {e}", p.display()))
}

fn term_str(o: &Outcome) -> String {
    o.termination
        .as_ref()
        .map(|t| format!("{t:?}"))
        .unwrap_or_else(|| "none".into())
}

fn verdict_str(v: Verdict) -> String {
    serde_json::to_value(v)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn sha256_file(p: &Path) -> String {
    let b = fs::read(p).unwrap();
    let d = Sha256::digest(&b);
    d.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("run") if a.len() == 3 => {
            let o = run(&load(Path::new(&a[2])));
            println!("{}", serde_json::to_string_pretty(&o).unwrap());
        }
        Some("matrix") if a.len() == 5 => {
            matrix(Path::new(&a[2]), Path::new(&a[3]), Path::new(&a[4]))
        }
        _ => usage(),
    }
}

fn matrix(dir: &Path, sweep_dir: &Path, out: &Path) {
    fs::create_dir_all(out).unwrap();
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    files.sort();

    let mut csv = String::from(
        "scenario,direction,binding,sender_strict,receiver_strict,verdict,termination,terminated_at_wire_index,lost_honest_indices\n",
    );
    let mut outcomes = Vec::new();
    for f in &files {
        let sc = load(f);
        let o = run(&sc);
        csv.push_str(&format!(
            "{},{:?},{:?},{},{},{},{},{},{}\n",
            o.scenario,
            sc.direction,
            sc.binding,
            o.sender_strict,
            o.receiver_strict,
            verdict_str(o.verdict),
            term_str(&o),
            o.terminated_at_wire_index
                .map(|i| i.to_string())
                .unwrap_or_default(),
            o.lost_honest_indices
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(";")
        ));
        outcomes.push(o);
    }
    fs::write(out.join("scenarios.csv"), &csv).unwrap();
    fs::write(
        out.join("scenarios.json"),
        serde_json::to_string_pretty(&outcomes).unwrap(),
    )
    .unwrap();

    // Counterfactual sweep over endpoint support / defense / binding for
    // every base scenario in sweep_dir (attack bases and benign bases).
    let mut bases: Vec<PathBuf> = fs::read_dir(sweep_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    bases.sort();
    let variants: Vec<(&str, EndpointCfg)> = vec![
        ("legacy", EndpointCfg::legacy()),
        ("strict_full", EndpointCfg::strict()),
        (
            "strict_a_only",
            EndpointCfg {
                reset_seq: false,
                ..EndpointCfg::strict()
            },
        ),
        (
            "strict_b_only",
            EndpointCfg {
                reject_unexpected: false,
                ..EndpointCfg::strict()
            },
        ),
        (
            "strict_no_defense",
            EndpointCfg {
                reject_unexpected: false,
                reset_seq: false,
                ..EndpointCfg::strict()
            },
        ),
    ];
    let mut sw = String::from(
        "base,client,server,binding,sender_strict,receiver_strict,verdict,termination\n",
    );
    let mut rows = 0usize;
    for bp in &bases {
        let base = load(bp);
        for (cn, c) in &variants {
            for (sn, s) in &variants {
                for b in [CipherBinding::SeqBound, CipherBinding::InvocationCounter] {
                    let mut sc = base.clone();
                    sc.client = *c;
                    sc.server = *s;
                    sc.binding = b;
                    let o = run(&sc);
                    sw.push_str(&format!(
                        "{},{cn},{sn},{b:?},{},{},{},{}\n",
                        base.name,
                        o.sender_strict,
                        o.receiver_strict,
                        verdict_str(o.verdict),
                        term_str(&o)
                    ));
                    rows += 1;
                }
            }
        }
    }
    fs::write(out.join("sweep.csv"), &sw).unwrap();

    let mut sums = String::new();
    for n in ["scenarios.csv", "scenarios.json", "sweep.csv"] {
        sums.push_str(&format!("{}  {}\n", sha256_file(&out.join(n)), n));
    }
    fs::write(out.join("SHA256SUMS"), sums).unwrap();
    eprintln!(
        "wrote {} scenarios and {rows} sweep rows to {}",
        outcomes.len(),
        out.display()
    );
}
