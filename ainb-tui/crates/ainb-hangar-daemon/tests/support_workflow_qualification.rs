//! Disposable support workflow, not model-quality or production-autonomy proof.
//! Process isolation/authentication helpers adapt the MIT DevOS portfolio fixture
//! originally based on agents-in-a-box 269324bdccac0429b224eb975a8425d9ff3d4a65.
//! Run on Linux inside owned PID AND network namespaces. Missing prerequisites fail.
//! Expected incident facts below are independent of worker-produced reports.

#![cfg(unix)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ainb_hangar_core::clock::{HangarClock, SystemClock};
use ainb_hangar_daemon::runner::{ProviderInvocation, RunOutcome, Runner, RunnerConfig};
use ainb_hangar_store::Store;
use ainb_hangar_store::repo::task::{NewTask, Task, TaskRepo};
use ainb_hangar_store::service::claim::ClaimTaskService;
use ainb_hangar_store::service::complete::{CompleteParams, CompleteTaskService};
use ainb_hangar_store::service::finalize::FinalizeOutcome;
use ainb_hangar_store::service::retry::{RetryDecision, RetryService};
use ainb_hangar_store::service::start::StartTaskService;
use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::Pid;
use serde_json::{Value, json};
use sqlx::Row;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const TASK: &str = "support-task";
const RUNTIME: &str = "runtime-1";
const AGENT: &str = "agent-1";
const DEADLINE_MS: u64 = 15_000;
const SENTINEL: &[u8] = b"owned synthetic controller sentinel\n";

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn until(mut condition: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(30);
    while Instant::now() < end {
        if condition() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("bounded support condition never became true");
}

fn sha(path: &Path) -> String {
    let output = Command::new("/usr/bin/sha256sum")
        .env_clear()
        .arg("--")
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn preflight() -> (PathBuf, String, PathBuf) {
    assert_eq!(
        std::env::consts::OS,
        "linux",
        "Linux execution is mandatory"
    );
    let host = std::env::var("QUALIFICATION_HOST_PID_NAMESPACE").expect("original PID namespace");
    assert_ne!(
        fs::read_link("/proc/self/ns/pid").unwrap().to_string_lossy(),
        host
    );
    let host_network =
        std::env::var("QUALIFICATION_HOST_NET_NAMESPACE").expect("original network namespace");
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap().to_string_lossy(),
        host_network
    );
    let interfaces = fs::read_to_string("/proc/net/dev").unwrap();
    assert_eq!(
        interfaces
            .lines()
            .filter_map(|l| l.split_once(':').map(|v| v.0.trim()))
            .collect::<Vec<_>>(),
        ["lo"]
    );
    for path in ["/usr/bin/python3", "/usr/bin/sha256sum", "/bin/sh"] {
        let metadata = fs::metadata(path).expect("mandatory local executable missing");
        assert!(metadata.is_file() && metadata.permissions().mode() & 0o111 != 0);
    }
    let daemon =
        fs::canonicalize(std::env::var_os("QUALIFICATION_DAEMON_BIN").expect("explicit daemon"))
            .unwrap();
    let compiled = fs::canonicalize(env!("CARGO_BIN_EXE_ainb-hangar-daemon"))
        .expect("Cargo-associated test daemon must exist");
    assert_eq!(
        compiled.file_name().and_then(|name| name.to_str()),
        Some("ainb-hangar-daemon"),
        "Cargo-associated test daemon must have the expected binary name"
    );
    let debug = compiled.parent().expect("Cargo test binary debug directory");
    assert_eq!(
        debug.file_name().and_then(|name| name.to_str()),
        Some("debug"),
        "Cargo test binary must be built in target/debug"
    );
    let target = debug.parent().expect("Cargo test target directory");
    assert_eq!(
        target.file_name().and_then(|name| name.to_str()),
        Some("target"),
        "Cargo test target must be OUTPUT/target"
    );
    let output = target.parent().expect("qualification OUTPUT parent");
    let runtime_path = output.join("daemon-target/debug/ainb-hangar-daemon");
    let runtime = fs::canonicalize(&runtime_path)
        .expect("separately built ordinary daemon must exist under the same OUTPUT");
    assert_eq!(
        runtime, runtime_path,
        "ordinary daemon path must not resolve through a linked fallback"
    );
    assert_ne!(
        daemon, compiled,
        "runtime daemon must not be Cargo's test-feature binary"
    );
    assert_eq!(
        daemon, runtime,
        "runtime daemon must be the separate OUTPUT/daemon-target/debug build"
    );
    let digest = std::env::var("QUALIFICATION_DAEMON_SHA256").expect("recorded daemon digest");
    assert_eq!(sha(&daemon), digest);
    let evidence = fs::canonicalize(
        std::env::var_os("QUALIFICATION_WORKFLOW_EVIDENCE_DIR")
            .expect("owned retained evidence root"),
    )
    .unwrap();
    assert!(
        evidence.is_dir() && !evidence.starts_with("/tmp") && !evidence.starts_with("/dev/shm")
    );
    (daemon, digest, evidence)
}

fn expected(kind: &str) -> Value {
    match kind {
        "opaque" => {
            json!({"incident":"opaque-17","diagnosis":"unknown","disposition":"escalate","next_action":"collect logs for human investigation"})
        }
        _ => {
            json!({"incident":"transient-42","diagnosis":"temporary dependency timeout","disposition":"retry_once","next_action":"retry once after 30 seconds"})
        }
    }
}

fn process_identity(pid: i32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
    if fields.first().copied() == Some("Z") {
        return None;
    }
    fields.get(19).map(|s| (*s).to_owned())
}

struct OwnedControlProcess(Child);
impl Drop for OwnedControlProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child_receipt(root: &Path) -> Value {
    until(|| root.join("child.json").is_file());
    serde_json::from_slice(&fs::read(root.join("child.json")).unwrap()).unwrap()
}

fn stopped_within(pids: &[i32], since: Instant, limit_ms: u64) -> u128 {
    while since.elapsed() < Duration::from_millis(limit_ms) {
        if pids.iter().all(|pid| process_identity(*pid).is_none()) {
            return since.elapsed().as_millis();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "owned process outlived its original deadline and bounded observation tolerance: {pids:?}"
    );
}

struct Fixture {
    case: &'static str,
    home: TempDir,
    evidence: PathBuf,
    daemon_bin: PathBuf,
    daemon_hash: String,
    daemons: Vec<Child>,
    workers: Vec<(i32, String)>,
    supervisors: Vec<(i32, String)>,
    events: Vec<Value>,
    controls: Value,
    kind: &'static str,
    limit: i64,
    started: Instant,
    retained: bool,
}

impl Fixture {
    fn new(case: &'static str, kind: &'static str, limit: i64) -> Self {
        let (daemon_bin, daemon_hash, evidence) = preflight();
        let home = tempfile::Builder::new().prefix("sw-").tempdir_in("/tmp").unwrap();
        let mut fixture = Self {
            case,
            home,
            evidence,
            daemon_bin,
            daemon_hash,
            daemons: vec![],
            workers: vec![],
            supervisors: vec![],
            events: vec![],
            controls: json!({}),
            kind,
            limit,
            started: Instant::now(),
            retained: false,
        };
        fs::create_dir(fixture.hangar()).unwrap();
        rt().block_on(async {
            let store = Store::open_in(&fixture.hangar()).await.unwrap();
            ainb_hangar_daemon::seed::seed_p4_fixture(store.pool()).await.unwrap();
            sqlx::query("UPDATE agent_task_queue SET status='done',finished_at=created_at WHERE id='task-1'").execute(store.pool()).await.unwrap();
            sqlx::query("UPDATE agent SET instructions=? WHERE id=?").bind(fixture.brief()).bind(AGENT).execute(store.pool()).await.unwrap();
            store.pool().close().await;
        });
        fixture.enqueue(TASK, limit);
        fixture.events.push(json!({"event":"intake","task":TASK,"owner":"fixture operator","incident":fixture.incident(),
            "acceptance_reference":"frozen support workflow expected facts v1","permitted_effect":"task.result","execution_allowance":limit,"deadline_ms":DEADLINE_MS}));
        fixture
    }

    fn hangar(&self) -> PathBuf {
        self.home.path().join(".agents-in-a-box")
    }
    fn incident(&self) -> Value {
        if self.kind == "opaque" {
            json!({"id":"opaque-17","observed":"unclassified symptom; no diagnostics"})
        } else {
            json!({"id":"transient-42","observed":"dependency timeout; transient flag true"})
        }
    }
    fn brief(&self) -> String {
        format!("SUPPORT_INCIDENT {}", self.incident())
    }
    fn task(&self, id: &str) -> Task {
        rt().block_on(async {
            let s = Store::open_in(&self.hangar()).await.unwrap();
            let t = TaskRepo::get_by_id(s.pool(), id).await.unwrap().expect("durable task");
            s.pool().close().await;
            t
        })
    }
    fn enqueue(&self, id: &str, limit: i64) {
        rt().block_on(async {
            let s = Store::open_in(&self.hangar()).await.unwrap();
            TaskRepo::insert(
                s.pool(),
                &NewTask {
                    id: id.into(),
                    workspace_id: ainb_hangar_daemon::seed::WS_ID.into(),
                    runtime_id: RUNTIME.into(),
                    agent_id: AGENT.into(),
                    issue_id: None,
                    work_dir: None,
                    priority: 0,
                    created_at: SystemClock.now_ms(),
                    autopilot_run_id: None,
                    generation: 0,
                },
            )
            .await
            .unwrap();
            assert!(TaskRepo::configure_execution_limit(s.pool(), id, limit).await.unwrap());
            s.pool().close().await;
        });
    }
    fn roots(&self) -> Vec<PathBuf> {
        self.roots_for(TASK)
    }
    fn roots_for(&self, id: &str) -> Vec<PathBuf> {
        let base = ainb_hangar_daemon::execenv::task_root(
            self.home.path(),
            ainb_hangar_daemon::seed::WS_SLUG,
            id,
        )
        .join("executions");
        let mut roots = fs::read_dir(base)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.path())
            .collect::<Vec<_>>();
        roots.sort();
        roots
    }
    fn worker(&mut self, excluded: &[PathBuf]) -> PathBuf {
        self.worker_for(TASK, excluded)
    }
    fn worker_for(&mut self, id: &str, excluded: &[PathBuf]) -> PathBuf {
        let mut found = None;
        until(|| {
            found = self
                .roots_for(id)
                .into_iter()
                .find(|p| !excluded.contains(p) && p.join("started.json").is_file());
            found.is_some()
        });
        let root = found.unwrap();
        let start: Value =
            serde_json::from_slice(&fs::read(root.join("started.json")).unwrap()).unwrap();
        let pid = i32::try_from(start["pid"].as_i64().unwrap()).unwrap();
        let identity = process_identity(pid).expect("positive actual worker liveness");
        self.workers.push((pid, identity));
        let supervisor = i32::try_from(start["parent_pid"].as_i64().unwrap()).unwrap();
        assert_eq!(start["process_group"], supervisor);
        self.supervisors.push((
            supervisor,
            process_identity(supervisor).expect("actual live supervisor"),
        ));
        self.events.push(json!({"event":"worker_alive","root":root,"pid":pid,"epoch":root.file_name().unwrap().to_string_lossy(),"start":start}));
        root
    }
    fn script(&self, mode: &str, extra: Value) -> PathBuf {
        let script = self.home.path().join(format!("worker-{mode}.py"));
        let config = json!({"mode":mode,"extra":extra});
        let encoded = serde_json::to_string(&config.to_string()).unwrap();
        fs::write(&script, format!("#!/usr/bin/python3\nimport json,os,sys,time,socket,sqlite3,errno\nCONFIG=json.loads({encoded})\n{WORKER}")).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }
    fn spawn(&mut self, mode: &str, extra: Value, deadline: u64, missing_enforcement: bool) {
        let script = self.script(mode, extra);
        let log = File::create(self.home.path().join(format!("daemon-{}.log", self.daemons.len())))
            .unwrap();
        let mut command = if missing_enforcement {
            let wrapper = self.home.path().join("deny-landlock.py");
            fs::write(&wrapper, DENY_LANDLOCK).unwrap();
            let mut c = Command::new("/usr/bin/python3");
            c.arg(wrapper).arg(&self.daemon_bin);
            c
        } else {
            Command::new(&self.daemon_bin)
        };
        command.env_clear();
        if mode == "malicious" {
            // Synthetic values only. Neither worker nor parent receipts retain values.
            for key in [
                "ANTHROPIC_API_KEY",
                "CLAUDE_CODE_OAUTH_TOKEN",
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "HANGAR_SECRET_TOKEN",
            ] {
                command.env(key, "synthetic-qualification-credential");
            }
        }
        let child = command
            .env("HOME", self.home.path())
            .env("PATH", "/usr/bin:/bin")
            .env("HANGAR_DAEMON_RUNTIME_ID", RUNTIME)
            .env("HANGAR_CLAUDE_PATH", &script)
            .env("HANGAR_CODEX_PATH", &script)
            .env("HANGAR_COPILOT_PATH", &script)
            .env("HANGAR_ANTIGRAVITY_PATH", &script)
            .env("HANGAR_DAEMON_POLL_MS", "50")
            .env("HANGAR_SWEEP_INTERVAL_MS", "100")
            .env("HANGAR_PROVIDER_MAX_RUNTIME_MS", deadline.to_string())
            .env(
                "HANGAR_DAEMON_DISABLE_SANDBOX",
                if mode == "network" { "1" } else { "0" },
            )
            .current_dir(self.home.path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .process_group(0)
            .spawn()
            .unwrap();
        self.events.push(json!({"event":"daemon_started","pid":child.id(),"missing_enforcement_injected":missing_enforcement,"legacy_sandbox_disabled":mode=="network","deadline_ms":deadline}));
        self.daemons.push(child);
    }
    fn crash_last(&mut self) {
        let d = self.daemons.last_mut().unwrap();
        let pid = d.id();
        d.kill().unwrap();
        d.wait().unwrap();
        self.events
            .push(json!({"event":"daemon_sigkill","pid":pid,"task_status":self.task(TASK).status}));
    }
    fn stop_daemons(&mut self) {
        for child in &mut self.daemons {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    fn settle(&self) {
        until(|| {
            matches!(
                self.task(TASK).status.as_str(),
                "done" | "failed" | "cancelled"
            )
        });
    }
    fn units(&self) -> i64 {
        rt().block_on(async {
            let s = Store::open_in(&self.hangar()).await.unwrap();
            let n = sqlx::query_scalar("SELECT execution_units FROM agent_task_queue WHERE id=?")
                .bind(TASK)
                .fetch_one(s.pool())
                .await
                .unwrap();
            s.pool().close().await;
            n
        })
    }
    fn snapshot(&self) -> Value {
        rt().block_on(async {
        let s=Store::open_in(&self.hangar()).await.unwrap();
        let rows=sqlx::query("SELECT id,status,result,execution_epoch,execution_root_id,execution_limit,execution_units,execution_owner_task_id,execution_owner_epoch,execution_published_task_id,execution_cancelled,parent_task_id,failure_reason FROM agent_task_queue WHERE id <> 'task-1' ORDER BY id").fetch_all(s.pool()).await.unwrap();
        let result=Value::Array(rows.into_iter().map(|r| json!({"id":r.get::<String,_>("id"),"status":r.get::<String,_>("status"),
            "result":r.get::<Option<String>,_>("result"),"execution_epoch":r.get::<i64,_>("execution_epoch"),
            "execution_root_id":r.get::<Option<String>,_>("execution_root_id"),"execution_limit":r.get::<Option<i64>,_>("execution_limit"),
            "execution_units":r.get::<i64,_>("execution_units"),"parent_task_id":r.get::<Option<String>,_>("parent_task_id"),
            "execution_owner_task_id":r.get::<Option<String>,_>("execution_owner_task_id"),"execution_owner_epoch":r.get::<Option<i64>,_>("execution_owner_epoch"),
            "execution_published_task_id":r.get::<Option<String>,_>("execution_published_task_id"),"execution_cancelled":r.get::<i64,_>("execution_cancelled"),
            "failure_reason":r.get::<Option<String>,_>("failure_reason")})).collect()); s.pool().close().await; result
    })
    }
    fn acceptance(&self) -> Value {
        let task = self.task(TASK);
        let mut reports = vec![];
        if let Some(raw) = task.result.as_deref() {
            let payload: Value = serde_json::from_str(raw).unwrap();
            for line in payload["content"].as_str().unwrap_or("").lines() {
                if let Ok(event) = serde_json::from_str::<Value>(line) {
                    if event["type"] == "result" && event["subtype"] == "success" {
                        if let Some(text) = event["result"].as_str() {
                            if let Ok(report) = serde_json::from_str::<Value>(text) {
                                reports.push(report);
                            }
                        }
                    }
                }
            }
        }
        let accepted =
            task.status == "done" && reports.len() == 1 && reports[0] == expected(self.kind);
        json!({"accepted":accepted,"reports":reports,"expected":expected(self.kind),
            "disposition":if accepted {"accepted"} else if task.status=="done" {"rejected"} else {"unresolved"},
            "next_action":if accepted {expected(self.kind)["next_action"].as_str().unwrap().to_owned()} else {"investigate and rework before any further execution".into()}})
    }
    fn finish(&mut self, expected_disposition: &str) {
        self.stop_daemons();
        let acceptance = self.acceptance();
        assert_eq!(acceptance["disposition"], expected_disposition);
        assert_eq!(sha(&self.daemon_bin), self.daemon_hash);
        assert!(self.units() <= self.limit);
        let workers = self.worker_records();
        let observer_uid = fs::metadata("/proc/self").unwrap().uid();
        for record in workers.as_array().unwrap() {
            if !record["started"].is_null() {
                assert_eq!(record["started"]["uid"], observer_uid);
            }
        }
        let record = json!({"schema_version":1,"case_id":self.case,"status":"passed","daemon_sha256":self.daemon_hash,
            "intake":{"owner":"fixture operator","incident":self.incident(),"execution_allowance":self.limit,"deadline_ms":DEADLINE_MS,"permitted_effect":"task.result"},
            "acceptance":acceptance,"task_rows":self.snapshot(),"execution_directories":self.roots().len(),
            "executions":self.roots().iter().filter(|p|p.join("started.json").is_file()).count(),
            "worker_records":workers,"observer_uid":observer_uid,"events":self.events,"controls":self.controls,
            "namespace":{"platform":std::env::consts::OS,
                "host_pid":std::env::var("QUALIFICATION_HOST_PID_NAMESPACE").unwrap(),
                "host_net":std::env::var("QUALIFICATION_HOST_NET_NAMESPACE").unwrap(),
                "current_pid":fs::read_link("/proc/self/ns/pid").unwrap().to_string_lossy(),
                "current_net":fs::read_link("/proc/self/ns/net").unwrap().to_string_lossy(),
                "interfaces":["lo"]},
            "elapsed_ms":self.started.elapsed().as_millis(),"model_calls":0,"currency_cost_known":false,"harness_network_is_worker_enforcement":false});
        self.retain(&record);
        println!("QUALIFICATION_WORKFLOW_RESULT {record}");
    }
    fn retain(&mut self, record: &Value) {
        let prefix = format!("support-workflow-{}", self.case);
        write_new(
            &self.evidence.join(format!("{prefix}.json")),
            serde_json::to_string_pretty(record).unwrap().as_bytes(),
        );
        write_new(
            &self.evidence.join(format!("{prefix}-result.txt")),
            self.task(TASK).result.unwrap_or_default().as_bytes(),
        );
        for entry in fs::read_dir(self.home.path()).unwrap().flatten() {
            if entry.file_type().unwrap().is_file()
                && entry.file_name().to_string_lossy().ends_with(".log")
            {
                write_new(
                    &self
                        .evidence
                        .join(format!("{prefix}-{}", entry.file_name().to_string_lossy())),
                    &fs::read(entry.path()).unwrap(),
                );
            }
        }
        for task in self.snapshot().as_array().unwrap() {
            let id = task["id"].as_str().unwrap();
            for root in self.roots_for(id) {
                let epoch = root.file_name().unwrap().to_string_lossy();
                for entry in fs::read_dir(root.join("logs")).into_iter().flatten().flatten() {
                    if entry.file_type().unwrap().is_file() {
                        write_new(
                            &self.evidence.join(format!(
                                "{prefix}-{id}-{epoch}-{}.txt",
                                entry.file_name().to_string_lossy()
                            )),
                            &fs::read(entry.path()).unwrap(),
                        );
                    }
                }
            }
        }
        self.retained = true;
    }
    fn worker_records(&self) -> Value {
        let mut records = vec![];
        for task in self.snapshot().as_array().unwrap() {
            let id = task["id"].as_str().unwrap();
            for root in self.roots_for(id) {
                let mut record = json!({"task_id":id,"root":root});
                for name in ["started", "child", "checks", "report"] {
                    let path = root.join(format!("{name}.json"));
                    if path.exists() {
                        record[name] = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                    }
                }
                records.push(record);
            }
        }
        json!(records)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop_daemons();
        // Only fixture-owned process identities; never kill before stale probes.
        for (pid, start) in &self.workers {
            if process_identity(*pid).as_deref() == Some(start.as_str()) {
                let _ = killpg(Pid::from_raw(*pid), Signal::SIGKILL);
                let _ = kill(Pid::from_raw(*pid), Signal::SIGKILL);
            }
        }
        for (pid, start) in &self.supervisors {
            if process_identity(*pid).as_deref() == Some(start.as_str()) {
                let _ = killpg(Pid::from_raw(*pid), Signal::SIGKILL);
                let _ = kill(Pid::from_raw(*pid), Signal::SIGKILL);
            }
        }
        if !self.retained {
            // Failure evidence is best effort during unwinding; never replace a pass.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let record = json!({"schema_version":1,"case_id":self.case,"status":"failed","events":self.events,"controls":self.controls,"task_rows":self.snapshot()});
                self.retain(&record);
            }));
        }
    }
}

const WORKER: &str = r#"
root=os.path.dirname(os.getcwd())
def save(name,value):
    path=os.path.join(root,name)
    with open(path+'.pending','w') as f:
        json.dump(value,f,sort_keys=True); f.flush(); os.fsync(f.fileno())
    os.replace(path+'.pending',path)
brief=sys.argv[-1]
assert 'SUPPORT_INCIDENT ' in brief, 'real intake brief did not reach worker'
incident=json.JSONDecoder().raw_decode(brief.split('SUPPORT_INCIDENT ',1)[1])[0]
save('started.json',{'pid':os.getpid(),'parent_pid':os.getppid(),'process_group':os.getpgrp(),'uid':os.getuid(),'incident':incident,'root':root,
    'environment_keys':sorted(os.environ),'home':os.environ.get('HOME'),'tmpdir':os.environ.get('TMPDIR')})
print(json.dumps({'type':'system','session_id':'synthetic-support'}),flush=True)
mode=CONFIG['mode']; extra=CONFIG['extra']
if mode=='descendant':
    child=os.fork()
    if child: os._exit(0)
    save('child.json',{'pid':os.getpid(),'parent_pid':os.getppid(),'process_group':os.getpgrp(),'uid':os.getuid(),'parent_exited':True})
    while True: time.sleep(.025)
if mode=='cancel_tree':
    child=os.fork()
    if child==0:
        save('child.json',{'pid':os.getpid(),'parent_pid':os.getppid(),'process_group':os.getpgrp(),'uid':os.getuid()})
        while True: time.sleep(.025)
if mode in ('barrier','stale','hang','cancel_tree'):
    while not os.path.exists(os.path.join(root,'release')): time.sleep(.025)
checks=[]
def denied(label,operation):
    try:
        operation()
    except OSError as error:
        assert error.errno in (errno.EACCES,errno.EPERM), (label,str(error))
        checks.append({'operation':label,'errno':error.errno})
    else: raise AssertionError(label+' unexpectedly permitted')
if mode=='malicious':
    forbidden=('ANTHROPIC_API_KEY','CLAUDE_CODE_OAUTH_TOKEN','GH_TOKEN','GITHUB_TOKEN','HANGAR_SECRET_TOKEN')
    assert all(key not in os.environ for key in forbidden)
    for key in ('HOME','TMPDIR'):
        assert key in os.environ and os.path.commonpath([root,os.environ[key]])==root
    denied('external_read',lambda:open(extra['sentinel'],'rb').read())
    denied('external_write',lambda:open(extra['sentinel'],'wb').write(b'CORRUPTED'))
if mode=='network':
    denied('network_connect',lambda:socket.create_connection(('127.0.0.1',extra['port']),1))
    denied('controller_db_open',lambda:open(extra['db'],'r+b'))
    try:
        db=sqlite3.connect('file:'+extra['db']+'?mode=rw',uri=True)
        db.execute("UPDATE agent_task_queue SET result='BYPASS',status='done' WHERE id='support-task'")
        db.commit()
    except sqlite3.OperationalError as error:
        assert 'unable to open database' in str(error) or 'not authorized' in str(error), str(error)
        checks.append({'operation':'controller_db_mutation','error':str(error)})
    else: raise AssertionError('controller mutation unexpectedly permitted')
if mode=='stale':
    with open(os.path.join(root,'successor-path')) as f: successor=f.read()
    denied('successor_overwrite',lambda:open(successor,'wb').write(b'STALE'))
save('checks.json',checks)
if incident['id']=='opaque-17':
    report={'incident':'opaque-17','diagnosis':'unknown','disposition':'escalate','next_action':'collect logs for human investigation'}
else:
    report={'incident':'transient-42','diagnosis':'temporary dependency timeout','disposition':'retry_once','next_action':'retry once after 30 seconds'}
if mode=='incorrect': report['diagnosis']='invented disk failure'
save('report.json',report)
print(json.dumps({'type':'result','subtype':'success','result':json.dumps(report,sort_keys=True),'total_cost_usd':0,'usage':{'input_tokens':0,'output_tokens':0}}),flush=True)
"#;

// A more restrictive ancestor filter simulates unavailable Landlock for the
// actual daemon. No provider-side bypass flag or mock enforcement result exists.
const DENY_LANDLOCK: &str = r#"import ctypes,os,sys
class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,444),Filter(0x06,0,0,0x50000|38),Filter(0x06,0,0,0x7fff0000))
libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(38,1,0,0,0)==0
program=Program(4,filters)
assert libc.prctl(22,2,ctypes.byref(program),0,0)==0
assert libc.syscall(444,0,0,1)==-1 and ctypes.get_errno()==38
print('QUALIFICATION_FAULT landlock_create_ruleset=ENOSYS',flush=True)
os.execve(sys.argv[1],[sys.argv[1]],dict(os.environ))
"#;

#[test]
fn support_workflow_recognised_transient() {
    let mut f = Fixture::new("recognised_transient", "transient", 1);
    f.spawn("normal", json!({}), DEADLINE_MS, false);
    f.settle();
    assert_eq!(f.units(), 1);
    f.finish("accepted");
}

#[test]
fn support_workflow_opaque_incident() {
    let mut f = Fixture::new("opaque_incident", "opaque", 1);
    f.spawn("normal", json!({}), DEADLINE_MS, false);
    f.settle();
    assert_eq!(f.units(), 1);
    f.finish("accepted");
}

#[test]
fn support_workflow_malicious_input() {
    let mut f = Fixture::new("malicious_input", "transient", 1);
    let sentinel = f.home.path().join("sentinel");
    fs::write(&sentinel, SENTINEL).unwrap();
    assert_eq!(fs::read(&sentinel).unwrap(), SENTINEL);
    fs::write(&sentinel, b"control").unwrap();
    fs::write(&sentinel, SENTINEL).unwrap();
    f.spawn(
        "malicious",
        json!({"sentinel":sentinel}),
        DEADLINE_MS,
        false,
    );
    f.settle();
    assert_eq!(fs::read(&sentinel).unwrap(), SENTINEL);
    let daemon_pid = f.daemons.last().unwrap().id();
    let daemon_environment = fs::read(format!("/proc/{daemon_pid}/environ")).unwrap();
    let mut daemon_environment_keys = daemon_environment
        .split(|b| *b == 0)
        .filter_map(|entry| entry.split(|b| *b == b'=').next())
        .filter(|key| !key.is_empty())
        .map(|key| String::from_utf8(key.to_vec()).unwrap())
        .collect::<Vec<_>>();
    daemon_environment_keys.sort();
    for key in [
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "HANGAR_SECRET_TOKEN",
    ] {
        assert!(daemon_environment_keys.iter().any(|value| value == key));
    }
    let root = f.roots().pop().unwrap();
    let started: Value =
        serde_json::from_slice(&fs::read(root.join("started.json")).unwrap()).unwrap();
    let environment_keys = started["environment_keys"].as_array().unwrap();
    for key in [
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "HANGAR_SECRET_TOKEN",
    ] {
        assert!(!environment_keys.iter().any(|value| value == key));
    }
    let private_home = Path::new(started["home"].as_str().unwrap());
    let private_tmpdir = Path::new(started["tmpdir"].as_str().unwrap());
    assert!(private_home.starts_with(&root));
    assert!(private_tmpdir.starts_with(&root));
    let checks: Value =
        serde_json::from_slice(&fs::read(root.join("checks.json")).unwrap()).unwrap();
    assert_eq!(checks.as_array().unwrap().len(), 2);
    f.controls = json!({"same_uid_positive_control":true,"sentinel_before":String::from_utf8_lossy(SENTINEL),"sentinel_after":String::from_utf8_lossy(&fs::read(sentinel).unwrap()),"denials":checks,
        "synthetic_credentials_injected":true,"credential_keys_absent":true,"daemon_environment_keys":daemon_environment_keys,
        "worker_environment_keys":environment_keys,"private_home":private_home,"private_tmpdir":private_tmpdir});
    f.finish("accepted");
}

#[test]
fn support_workflow_network_state_bypass() {
    let mut f = Fixture::new("network_state_bypass", "transient", 1);
    let ip = ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .expect("owned namespace loopback configuration prerequisite");
    assert!(Command::new(ip).args(["link", "set", "lo", "up"]).status().unwrap().success());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let control = TcpStream::connect(address).unwrap();
    let (_accepted, _) = listener.accept().unwrap();
    drop(control);
    listener.set_nonblocking(true).unwrap();
    let db = f.hangar().join("hangar.db");
    assert!(OpenOptions::new().read(true).write(true).open(&db).is_ok());
    f.spawn(
        "network",
        json!({"port":address.port(),"db":db}),
        DEADLINE_MS,
        false,
    );
    f.settle();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let root = f.roots().pop().unwrap();
    let checks: Value =
        serde_json::from_slice(&fs::read(root.join("checks.json")).unwrap()).unwrap();
    assert_eq!(checks.as_array().unwrap().len(), 3);
    f.controls = json!({"loopback_positive_connection":true,"controller_db_positive_open":true,"legacy_sandbox_disabled":true,"unexpected_connections":0,"denials":checks});
    f.finish("accepted");
}

#[test]
fn support_workflow_incorrect_report() {
    let mut f = Fixture::new("incorrect_report", "transient", 1);
    f.spawn("incorrect", json!({}), DEADLINE_MS, false);
    f.settle();
    assert_eq!(f.task(TASK).status, "done");
    assert_eq!(f.units(), 1);
    f.controls = json!({"process_exit_zero_is_not_acceptance":true});
    f.finish("rejected");
}

// These two cases deliberately assemble the public claim/start/Runner/complete
// services. They prove the linked service boundary, not unattended handoff.
fn execute_claimed(f: &Fixture, epoch: i64) -> CompleteParams {
    let task = f.task(TASK);
    let env = ainb_hangar_daemon::execenv::prepare_env_for_execution(
        &task,
        ainb_hangar_daemon::seed::WS_SLUG,
        f.home.path(),
        epoch,
        &SystemClock,
    )
    .unwrap();
    let script = f.script("normal", json!({}));
    rt().block_on(async {
        let store = Store::open_in(&f.hangar()).await.unwrap();
        assert_eq!(
            StartTaskService::start_owned(store.pool(), TASK, epoch, &SystemClock)
                .await
                .unwrap(),
            FinalizeOutcome::Transitioned
        );
        let runner = Runner::new(RunnerConfig {
            claude_path: script.clone(),
            codex_path: script.clone(),
            copilot_path: script.clone(),
            antigravity_path: script,
            max_runtime: Duration::from_millis(DEADLINE_MS),
            tail_lines: 100,
            sandbox: true,
        })
        .with_strict_support()
        .with_support_supervisor(&f.daemon_bin);
        let invocation = ProviderInvocation {
            prompt: f.brief(),
            model: None,
            cli_args: vec![],
        };
        let result = runner
            .run_claude(
                &env,
                vec![
                    ("HOME".into(), f.home.path().to_string_lossy().into_owned()),
                    ("PATH".into(), "/usr/bin:/bin".into()),
                ],
                &invocation,
            )
            .await
            .unwrap();
        let RunOutcome::Success(result) = result else {
            panic!("strict synthetic worker did not succeed: {result:?}")
        };
        assert_eq!(result.exit_code, Some(0));
        store.pool().close().await;
        CompleteParams {
            result: serde_json::to_value(ainb_hangar_core::result::TaskResult::new(
                result.stdout_tail,
                result.exit_code,
                result.pr_url,
            ))
            .unwrap(),
            session_id: result.session_id,
            work_dir: Some(env.workdir.to_string_lossy().into_owned()),
        }
    })
}

fn stale_complete(f: &Fixture, epoch: i64) -> String {
    let before = f.task(TASK).result;
    let error = rt().block_on(async {
        let store = Store::open_in(&f.hangar()).await.unwrap();
        let result = CompleteTaskService::complete_owned(
            store.pool(),
            TASK,
            epoch,
            CompleteParams {
                result: json!({"content":"STALE"}),
                session_id: None,
                work_dir: None,
            },
            &SystemClock,
        )
        .await;
        store.pool().close().await;
        result.expect_err("stale completion was accepted")
    });
    assert!(
        matches!(
            error,
            ainb_hangar_store::service::finalize::FinalizeError::StaleExecution { .. }
                | ainb_hangar_store::service::finalize::FinalizeError::TerminalMismatch { .. }
                | ainb_hangar_store::service::finalize::FinalizeError::OwnershipRevoked { .. }
        ),
        "{error}"
    );
    assert_eq!(f.task(TASK).result, before);
    error.to_string()
}

#[test]
fn support_workflow_concurrent_owners() {
    let mut f = Fixture::new("concurrent_owners", "transient", 1);
    let claims = rt().block_on(async {
        let first = Store::open_in(&f.hangar()).await.unwrap();
        let second = Store::open_in(&f.hangar()).await.unwrap();
        let (a, b) = tokio::join!(
            ClaimTaskService::claim_for_runtime(first.pool(), RUNTIME, &SystemClock),
            ClaimTaskService::claim_for_runtime(second.pool(), RUNTIME, &SystemClock)
        );
        let claims = vec![a.unwrap(), b.unwrap()];
        first.pool().close().await;
        second.pool().close().await;
        claims
    });
    assert_eq!(claims.iter().filter(|c| c.is_some()).count(), 1);
    let winner = claims.iter().flatten().next().unwrap();
    assert_eq!(winner.id, TASK);
    assert_eq!(f.units(), 1);
    let params = execute_claimed(&f, winner.execution_epoch);
    rt().block_on(async {
        let s = Store::open_in(&f.hangar()).await.unwrap();
        assert_eq!(
            CompleteTaskService::complete_owned(
                s.pool(),
                TASK,
                winner.execution_epoch,
                params,
                &SystemClock
            )
            .await
            .unwrap(),
            FinalizeOutcome::Transitioned
        );
        s.pool().close().await;
    });
    f.controls = json!({"claimants":claims.iter().map(|c|c.as_ref().map(|c|json!({"task_id":c.id,"epoch":c.execution_epoch}))).collect::<Vec<_>>(),
        "admitted_claimants":1,"public_service_handoff":true,"unattended_handoff_proved":false});
    f.finish("accepted");
}

#[test]
fn support_workflow_crash_before_publication() {
    let mut f = Fixture::new("crash_before_publication", "transient", 2);
    let original_deadline_ms = 2_000;
    f.spawn("barrier", json!({}), original_deadline_ms, false);
    let old = f.worker(&[]);
    let observed = Instant::now();
    let old_pid = f.workers[0].0;
    let supervisor = f.supervisors[0].0;
    let epoch = f.task(TASK).execution_epoch;
    assert!(f.task(TASK).result.is_none());
    f.crash_last();
    assert!(
        process_identity(f.workers[0].0).is_some(),
        "worker must survive controller crash"
    );
    f.spawn("normal", json!({}), DEADLINE_MS, false);
    f.settle();
    assert_eq!(f.units(), 2);
    assert!(f.task(TASK).execution_epoch > epoch);
    let stopped_elapsed_ms = stopped_within(
        &[old_pid, supervisor],
        observed,
        original_deadline_ms + 2_000 + 500,
    );
    f.controls = json!({"old_epoch":epoch,"successor_epoch":f.task(TASK).execution_epoch,"old_root":old,"result_before_crash":null,
        "worker_alive_after_daemon_crash":true,"same_database":true,"execution_units":f.units(),
        "original_deadline_ms":original_deadline_ms,"supervisor_grace_ms":2000,"observation_tolerance_ms":500,
        "old_worker_pid":old_pid,"supervisor_pid":supervisor,"stopped_elapsed_ms":stopped_elapsed_ms,
        "old_worker_stopped_before_fixture_cleanup":true,"supervisor_stopped_before_fixture_cleanup":true});
    f.finish("accepted");
}

#[test]
fn support_workflow_stale_worker_takeover() {
    let mut f = Fixture::new("stale_worker_takeover", "transient", 2);
    f.spawn("stale", json!({}), DEADLINE_MS, false);
    let old = f.worker(&[]);
    let old_epoch = f.task(TASK).execution_epoch;
    f.crash_last();
    assert!(process_identity(f.workers[0].0).is_some());
    f.spawn("barrier", json!({}), DEADLINE_MS, false);
    let new = f.worker(std::slice::from_ref(&old));
    let epoch = f.task(TASK).execution_epoch;
    assert!(epoch > old_epoch);
    assert_ne!(old, new);
    assert_eq!(f.task(TASK).status, "running");
    let sentinel = new.join("successor.txt");
    write_new(&sentinel, SENTINEL);
    write_new(
        &old.join("successor-path"),
        sentinel.to_str().unwrap().as_bytes(),
    );
    // Old process has not been cleaned up. It attempts the real forbidden write
    // while the successor is alive and owns the running row.
    assert!(process_identity(f.workers[0].0).is_some());
    write_new(&old.join("release"), b"release");
    until(|| old.join("checks.json").is_file());
    let checks: Value =
        serde_json::from_slice(&fs::read(old.join("checks.json")).unwrap()).unwrap();
    assert_eq!(checks.as_array().unwrap().len(), 1);
    assert_eq!(checks[0]["operation"], "successor_overwrite");
    assert_eq!(fs::read(&sentinel).unwrap(), SENTINEL);
    let denial_running = stale_complete(&f, old_epoch);
    assert_eq!(f.task(TASK).status, "running");
    assert!(f.task(TASK).result.is_none());
    write_new(&new.join("release"), b"release");
    f.settle();
    let committed = f.task(TASK).result;
    let denial_committed = stale_complete(&f, old_epoch);
    assert_eq!(f.task(TASK).result, committed);
    assert_eq!(fs::read(&sentinel).unwrap(), SENTINEL);
    assert_eq!(f.units(), 2);
    f.controls = json!({"old_epoch":old_epoch,"successor_epoch":epoch,"old_root":old,"successor_root":new,
        "old_worker_released_before_cleanup":true,"successor_alive_during_probe":true,"denials":checks,
        "stale_completion_running":denial_running,"stale_completion_committed":denial_committed,
        "sentinel_before":String::from_utf8_lossy(SENTINEL),"sentinel_after":String::from_utf8_lossy(&fs::read(sentinel).unwrap()),"accepted_result_unchanged":true});
    f.finish("accepted");
}

#[test]
fn support_workflow_commit_lost_ack() {
    let mut f = Fixture::new("commit_lost_ack", "transient", 1);
    let claim = rt().block_on(async {
        let s = Store::open_in(&f.hangar()).await.unwrap();
        let claim = ClaimTaskService::claim_for_runtime(s.pool(), RUNTIME, &SystemClock)
            .await
            .unwrap()
            .unwrap();
        s.pool().close().await;
        claim
    });
    let params = execute_claimed(&f, claim.execution_epoch);
    // The actual completion service response is deliberately discarded. The
    // observer only learns the outcome from durable state after this boundary.
    rt().block_on(async {
        let s = Store::open_in(&f.hangar()).await.unwrap();
        drop(
            CompleteTaskService::complete_owned(
                s.pool(),
                TASK,
                claim.execution_epoch,
                params,
                &SystemClock,
            )
            .await,
        );
        s.pool().close().await;
    });
    let committed = f.task(TASK).result.expect("commit exists despite discarded acknowledgement");
    f.spawn("normal", json!({}), DEADLINE_MS, false);
    std::thread::sleep(Duration::from_millis(600));
    f.crash_last();
    f.spawn("normal", json!({}), DEADLINE_MS, false);
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(f.task(TASK).result.as_deref(), Some(committed.as_str()));
    assert_eq!(f.units(), 1);
    assert_eq!(f.roots().len(), 1);
    f.controls = json!({"acknowledgement":"actual CompleteOwned response discarded","service_handoff":true,
        "transport_response_loss_proved":false,"committed_before_restart":committed,"committed_after_restart":f.task(TASK).result,"execution_units":f.units()});
    f.finish("accepted");
}

async fn call(stream: &mut BufReader<UnixStream>, id: u64, method: &str, params: Value) -> Value {
    let body =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .unwrap();
    stream
        .get_mut()
        .write_all(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes())
        .await
        .unwrap();
    stream.get_mut().write_all(&body).await.unwrap();
    stream.get_mut().flush().await.unwrap();
    loop {
        let mut length = None;
        loop {
            let mut line = String::new();
            assert!(stream.read_line(&mut line).await.unwrap() > 0);
            assert!(line.len() <= 1024);
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("Content-Length") {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
            }
        }
        let length = length.unwrap();
        assert!(length <= 1024 * 1024);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        let response: Value = serde_json::from_slice(&body).unwrap();
        if response["id"] == id {
            return response;
        }
    }
}

fn cancel_rpc(f: &Fixture, workspace: &str, authenticated: bool) -> Value {
    rt().block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let socket = ainb_hangar_daemon::rpc::socket_path_in(&f.hangar());
            assert!(socket.as_os_str().len() < 108, "bounded UDS address");
            let stream = loop {
                match UnixStream::connect(&socket).await {
                    Ok(s) => break s,
                    Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
                }
            };
            let mut stream = BufReader::new(stream);
            if authenticated {
                let token = fs::read_to_string(ainb_hangar_proto::auth::token_file_in(&f.hangar()))
                    .unwrap();
                let auth = call(
                    &mut stream,
                    1,
                    ainb_hangar_proto::methods::AUTH_HELLO,
                    json!({"token":token.trim()}),
                )
                .await;
                assert!(auth["error"].is_null(), "{auth}");
            }
            call(
                &mut stream,
                2,
                "hangar/task_cancel",
                json!({"workspace_id":workspace,"task_id":TASK}),
            )
            .await
        })
        .await
        .expect("bounded cancel RPC")
    })
}

#[test]
fn support_workflow_cancel_before_publication() {
    let mut f = Fixture::new("cancel_before_publication", "transient", 2);
    let (foreign_workspace_id, foreign_workspace_resolved_id) = rt().block_on(async {
        use ainb_hangar_store::repo::workspace::WorkspaceRepo;
        let store = Store::open_in(&f.hangar()).await.unwrap();
        let workspace = WorkspaceRepo::create(
            store.pool(),
            "foreign-workspace",
            "Synthetic foreign workspace",
            None,
        )
        .await
        .unwrap();
        let typed = ainb_hangar_core::ids::WorkspaceId::from_str(workspace.id.clone()).unwrap();
        assert!(WorkspaceRepo::get_config(store.pool(), &typed).await.unwrap().is_some());
        let resolved: String =
            sqlx::query_scalar("SELECT id FROM workspace WHERE id = ?1 OR slug = ?1 LIMIT 1")
                .bind("foreign-workspace")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(resolved, workspace.id);
        assert_ne!(resolved, ainb_hangar_daemon::seed::WS_ID);
        store.pool().close().await;
        (workspace.id, resolved)
    });
    let mut unrelated = OwnedControlProcess(
        Command::new("/bin/sleep")
            .arg("60")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    let unrelated_pid = i32::try_from(unrelated.0.id()).unwrap();
    let unrelated_identity = process_identity(unrelated_pid).unwrap();
    f.spawn("cancel_tree", json!({}), DEADLINE_MS, false);
    let old = f.worker(&[]);
    let supervisor = f.supervisors[0].0;
    let child = child_receipt(&old);
    let child_pid = i32::try_from(child["pid"].as_i64().unwrap()).unwrap();
    assert_eq!(child["process_group"], supervisor);
    f.workers.push((
        child_pid,
        process_identity(child_pid).expect("actual live descendant"),
    ));
    let epoch = f.task(TASK).execution_epoch;
    let pid = f.workers[0].0;
    let unauth = cancel_rpc(&f, ainb_hangar_daemon::seed::WS_SLUG, false);
    assert!(!unauth["error"].is_null());
    let foreign = cancel_rpc(&f, "foreign-workspace", true);
    assert_eq!(foreign["error"]["code"], -32602);
    assert_eq!(
        foreign["error"]["message"],
        "task does not belong to that workspace"
    );
    assert_eq!(f.task(TASK).status, "running");
    assert!(process_identity(pid).is_some());
    let cancelled = cancel_rpc(&f, ainb_hangar_daemon::seed::WS_SLUG, true);
    assert!(cancelled["error"].is_null(), "{cancelled}");
    assert_eq!(cancelled["result"]["cancelled"], true);
    assert_eq!(cancelled["result"]["signalled"], true);
    let stopped_elapsed_ms = stopped_within(&[pid, child_pid, supervisor], Instant::now(), 3_000);
    assert_eq!(
        process_identity(unrelated_pid).as_deref(),
        Some(unrelated_identity.as_str())
    );
    assert!(unrelated.0.try_wait().unwrap().is_none());
    f.settle();
    assert_eq!(f.task(TASK).status, "cancelled");
    let denial = stale_complete(&f, epoch);
    f.crash_last();
    let child_id = "support-after-cancel";
    rt().block_on(async {
        let s = Store::open_in(&f.hangar()).await.unwrap();
        let task = TaskRepo::get_by_id(s.pool(), TASK).await.unwrap().unwrap();
        assert!(matches!(
            RetryService::force_requeue(s.pool(), &task, child_id, &SystemClock)
                .await
                .unwrap(),
            RetryDecision::Spawned { .. }
        ));
        assert!(
            ClaimTaskService::claim_for_runtime(s.pool(), RUNTIME, &SystemClock)
                .await
                .unwrap()
                .is_none()
        );
        s.pool().close().await;
    });
    f.spawn("normal", json!({}), DEADLINE_MS, false);
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(f.task(TASK).status, "cancelled");
    assert!(f.task(TASK).result.is_none());
    assert_eq!(f.units(), 1);
    assert_eq!(f.roots().len(), 1);
    assert!(f.roots_for(child_id).is_empty());
    assert_eq!(f.task(child_id).execution_epoch, 0);
    f.controls = json!({"unauthenticated_response":unauth,"foreign_workspace_response":foreign,"operator_response":cancelled,
        "foreign_workspace_exists":true,"foreign_workspace_slug":"foreign-workspace",
        "foreign_workspace_id":foreign_workspace_id,"foreign_workspace_resolved_id":foreign_workspace_resolved_id,
        "task_workspace_id":f.task(TASK).workspace_id,
        "worker_pid":pid,"worker_stopped_before_fixture_cleanup":true,"old_root":old,"delayed_completion":denial,"cancelled_after_restart":true,
        "remaining_allowance":1,"forced_retry_child":child_id,"forced_retry_after_cancel_denied":true,
        "supervisor_pid":supervisor,"descendant_pid":child_pid,"supervisor_stopped_before_fixture_cleanup":true,
        "descendant_stopped_before_fixture_cleanup":true,"stopped_elapsed_ms":stopped_elapsed_ms,
        "unrelated_process_pid":unrelated_pid,"unrelated_process_alive_after_cancel":true});
    f.finish("unresolved");
}

#[test]
fn support_workflow_execution_allowance_exhausted() {
    let mut f = Fixture::new("execution_allowance_exhausted", "transient", 2);
    f.spawn("barrier", json!({}), DEADLINE_MS, false);
    let first = f.worker(&[]);
    f.crash_last();
    f.spawn("barrier", json!({}), DEADLINE_MS, false);
    let second = f.worker(std::slice::from_ref(&first));
    f.crash_last();
    assert_ne!(first, second);
    assert_eq!(f.units(), 2);
    f.spawn("normal", json!({}), DEADLINE_MS, false);
    until(|| f.task(TASK).status == "queued");
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(f.roots().len(), 2);
    assert_eq!(f.units(), 2);
    assert!(f.task(TASK).result.is_none());
    f.stop_daemons();
    let child_id = "support-retry-child";
    rt().block_on(async {
        let s = Store::open_in(&f.hangar()).await.unwrap();
        assert_eq!(
            ainb_hangar_store::service::fail::FailTaskService::fail(
                s.pool(),
                TASK,
                ainb_hangar_store::service::fail::FailureReason::RuntimeRecovery,
                &SystemClock
            )
            .await
            .unwrap(),
            FinalizeOutcome::Transitioned
        );
        let parent = TaskRepo::get_by_id(s.pool(), TASK).await.unwrap().unwrap();
        assert!(matches!(
            RetryService::force_requeue(s.pool(), &parent, child_id, &SystemClock)
                .await
                .unwrap(),
            RetryDecision::Spawned { .. }
        ));
        assert!(
            ClaimTaskService::claim_for_runtime(s.pool(), RUNTIME, &SystemClock)
                .await
                .unwrap()
                .is_none()
        );
        s.pool().close().await;
    });
    assert_eq!(f.task(child_id).execution_limit, Some(2));
    f.spawn("normal", json!({}), DEADLINE_MS, false);
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(f.task(child_id).status, "queued");
    assert_eq!(f.task(child_id).execution_epoch, 0);
    assert!(f.roots_for(child_id).is_empty());
    assert_eq!(f.units(), 2);
    let row = f
        .snapshot()
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == child_id)
        .unwrap()
        .clone();
    assert_eq!(row["execution_root_id"], TASK);
    let root_snapshot = f.snapshot();
    let root_row = root_snapshot.as_array().unwrap().iter().find(|r| r["id"] == TASK).unwrap();
    assert_eq!(root_row["execution_cancelled"], 0);
    assert!(root_row["execution_published_task_id"].is_null());
    f.controls = json!({"root_allowance":2,"execution_units":2,"recovery_next_claim_denied":true,"manual_retry_claim_denied":true,"retry_child":row,"worker_roots":[first,second]});
    f.finish("unresolved");
}

#[test]
fn support_workflow_missing_enforcement_deadline() {
    let mut f = Fixture::new("missing_enforcement_deadline", "transient", 1);
    f.spawn("normal", json!({}), DEADLINE_MS, true);
    f.settle();
    assert_eq!(f.task(TASK).status, "failed");
    assert_eq!(f.task(TASK).failure_reason.as_deref(), Some("spawn_error"));
    assert!(
        fs::read_to_string(f.home.path().join("daemon-0.log"))
            .unwrap()
            .contains("QUALIFICATION_FAULT landlock_create_ruleset=ENOSYS")
    );
    assert!(f.roots().iter().all(|p| !p.join("started.json").exists()));
    assert_eq!(f.units(), 1);
    f.stop_daemons();
    let missing = f.snapshot();
    let deadline_id = "support-deadline-task";
    f.enqueue(deadline_id, 1);
    f.spawn("hang", json!({}), 700, false);
    let root = f.worker_for(deadline_id, &[]);
    let pid = f.workers.last().unwrap().0;
    until(|| f.task(deadline_id).status == "failed");
    until(|| process_identity(pid).is_none());
    let task = f.task(deadline_id);
    assert_eq!(task.failure_reason.as_deref(), Some("timeout"));
    assert!(task.result.is_some(), "failure diagnostic must be retained");
    assert_eq!(f.roots_for(deadline_id).len(), 1);
    f.stop_daemons();
    let descendant_id = "support-descendant-deadline";
    f.enqueue(descendant_id, 1);
    f.spawn("descendant", json!({}), 1_200, false);
    let mut descendant_root = None;
    until(|| {
        descendant_root =
            f.roots_for(descendant_id).into_iter().find(|r| r.join("child.json").is_file());
        descendant_root.is_some()
    });
    let descendant_root = descendant_root.unwrap();
    let child: Value =
        serde_json::from_slice(&fs::read(descendant_root.join("child.json")).unwrap()).unwrap();
    let child_pid = i32::try_from(child["pid"].as_i64().unwrap()).unwrap();
    f.workers.push((
        child_pid,
        process_identity(child_pid).expect("positive inherited-pipe descendant liveness"),
    ));
    let parent: Value =
        serde_json::from_slice(&fs::read(descendant_root.join("started.json")).unwrap()).unwrap();
    let parent_pid = i32::try_from(parent["pid"].as_i64().unwrap()).unwrap();
    let supervisor_pid = i32::try_from(parent["parent_pid"].as_i64().unwrap()).unwrap();
    assert_eq!(parent["process_group"], supervisor_pid);
    assert_eq!(child["process_group"], supervisor_pid);
    f.supervisors.push((
        supervisor_pid,
        process_identity(supervisor_pid).expect("actual live supervisor"),
    ));
    until(|| process_identity(parent_pid).is_none());
    assert!(
        process_identity(child_pid).is_some(),
        "parent exits before live descendant"
    );
    until(|| f.task(descendant_id).status == "failed");
    until(|| process_identity(child_pid).is_none());
    until(|| process_identity(supervisor_pid).is_none());
    let descendant = f.task(descendant_id);
    assert_eq!(descendant.failure_reason.as_deref(), Some("timeout"));
    assert!(descendant.result.is_some());
    f.stop_daemons();
    let orphan_id = "support-descendant-daemon-crash";
    f.enqueue(orphan_id, 1);
    f.spawn("descendant", json!({}), 2_000, false);
    let mut orphan_root = None;
    until(|| {
        orphan_root = f.roots_for(orphan_id).into_iter().find(|r| r.join("child.json").is_file());
        orphan_root.is_some()
    });
    let orphan_root = orphan_root.unwrap();
    let orphan_child = child_receipt(&orphan_root);
    let orphan_pid = i32::try_from(orphan_child["pid"].as_i64().unwrap()).unwrap();
    let orphan_parent: Value =
        serde_json::from_slice(&fs::read(orphan_root.join("started.json")).unwrap()).unwrap();
    let orphan_parent_pid = i32::try_from(orphan_parent["pid"].as_i64().unwrap()).unwrap();
    let orphan_supervisor = i32::try_from(orphan_parent["parent_pid"].as_i64().unwrap()).unwrap();
    assert_eq!(orphan_child["process_group"], orphan_supervisor);
    assert_eq!(orphan_parent["process_group"], orphan_supervisor);
    f.workers.push((
        orphan_pid,
        process_identity(orphan_pid).expect("live descendant before daemon crash"),
    ));
    f.supervisors.push((
        orphan_supervisor,
        process_identity(orphan_supervisor).expect("live supervisor before daemon crash"),
    ));
    let orphan_observed = Instant::now();
    until(|| process_identity(orphan_parent_pid).is_none());
    f.crash_last();
    assert!(process_identity(orphan_pid).is_some());
    assert!(process_identity(orphan_supervisor).is_some());
    let orphan_stopped_elapsed_ms =
        stopped_within(&[orphan_pid, orphan_supervisor], orphan_observed, 4_500);
    let orphan_before_restart = f.task(orphan_id);
    assert_eq!(orphan_before_restart.status, "running");
    assert!(orphan_before_restart.result.is_none());
    f.spawn("normal", json!({}), DEADLINE_MS, false);
    until(|| f.task(orphan_id).status == "queued");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(f.task(orphan_id).status, "queued");
    assert_eq!(f.roots_for(orphan_id).len(), 1);
    assert!(f.task(orphan_id).result.is_none());
    let snapshots = f.snapshot();
    for id in [TASK, deadline_id, descendant_id, orphan_id] {
        let row = snapshots.as_array().unwrap().iter().find(|r| r["id"] == id).unwrap();
        assert!(row["execution_published_task_id"].is_null());
        assert_eq!(row["execution_units"], 1);
    }
    f.controls = json!({"missing_enforcement":{"injected_syscall":444,"errno":38,"provider_started":false,"task_rows":missing},
        "deadline":{"task_id":deadline_id,"milliseconds":700,"worker_pid":pid,"root":root,"worker_stopped_before_fixture_cleanup":true,"failure_reason":task.failure_reason,"execution_allowance":1},
        "descendant_deadline":{"task_id":descendant_id,"milliseconds":1200,"parent_pid":parent_pid,"child_pid":child_pid,"parent_exited_before_live_child":true,
            "supervisor_pid":supervisor_pid,"supervisor_stopped_before_fixture_cleanup":true,"worker_stopped_before_fixture_cleanup":true,"failure_reason":descendant.failure_reason,"execution_allowance":1},
        "descendant_daemon_crash":{"task_id":orphan_id,"original_deadline_ms":2000,"supervisor_grace_ms":2000,"observation_tolerance_ms":500,
            "parent_pid":orphan_parent_pid,"child_pid":orphan_pid,"supervisor_pid":orphan_supervisor,"parent_exited_before_live_child":true,
            "child_alive_after_daemon_crash":true,"supervisor_alive_after_daemon_crash":true,"stopped_elapsed_ms":orphan_stopped_elapsed_ms,
            "child_stopped_before_fixture_cleanup":true,"supervisor_stopped_before_fixture_cleanup":true,"status_before_restart":orphan_before_restart.status,
            "status_after_restart":f.task(orphan_id).status,"execution_allowance":1}});
    f.finish("unresolved");
}
