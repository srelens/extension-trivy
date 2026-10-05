use serde_json::{json, Value};
use srelens_plugin_host::sidecar::data::{measure, DataDir};
use srelens_plugin_host::sidecar::{
    CgroupRoot, Limits, NoBroker, OsSandbox, Policy, SandboxConfig, SidecarCommand, SidecarConfig,
    SidecarStatus, StreamEvent, Supervisor,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn copy_tree(source: &Path, target: &Path) {
    std::fs::create_dir_all(target).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let to = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            assert!(entry.file_type().unwrap().is_file(), "fixture is a symlink");
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}

async fn start(fixture_key: &str) -> (tempfile::TempDir, PathBuf, Supervisor) {
    let root = tempfile::tempdir().unwrap();
    let data = DataDir::for_app(&root.path().join("apps"), "com.example.trivy-proof").unwrap();
    let fixtures = std::env::var_os(fixture_key).expect("set the proof fixture directory");
    copy_tree(Path::new(&fixtures), data.path());
    let binary = PathBuf::from(
        std::env::var_os("TRIVY_PROOF_BINARY").expect("set TRIVY_PROOF_BINARY to the built probe"),
    );
    let supervisor = Supervisor::start(
        SidecarConfig {
            command: SidecarCommand {
                app_id: "com.example.trivy-proof".into(),
                program: binary,
                args: vec![],
                env: vec![],
                data_dir: data.path().into(),
            },
            limits: Limits::default(),
            policy: Policy {
                backoff: vec![],
                ..Policy::default()
            },
        },
        Arc::new(OsSandbox::new(SandboxConfig {
            launcher: Some(
                std::env::var_os("TRIVY_PROOF_LAUNCHER")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| env!("CARGO_BIN_EXE_srelens-sandbox-launch").into()),
            ),
            cgroup: std::env::var_os("SRELENS_SANDBOX_CGROUP_ROOT")
                .map_or(CgroupRoot::SystemdScope, |p| {
                    CgroupRoot::Delegated(p.into())
                }),
        })),
        Arc::new(NoBroker),
    );
    let mut status = supervisor.watch();
    tokio::time::timeout(
        Duration::from_secs(30),
        status.wait_for(|s| !matches!(s, SidecarStatus::Starting)),
    )
    .await
    .expect("startup deadline")
    .unwrap();
    assert!(
        matches!(supervisor.status(), SidecarStatus::Running { .. }),
        "{:?}; {:?}",
        supervisor.status(),
        supervisor.logs()
    );
    (root, data.path().into(), supervisor)
}

#[tokio::test]
async fn offline_scan_under_the_real_supervisor_and_sandbox() {
    let (_root, data, host) = start("TRIVY_PROOF_FIXTURES").await;
    let started = Instant::now();
    let mut scan = host.open_stream("scan", json!({})).await.unwrap();
    let mut completed: Option<Value> = None;
    let mut peak = 0;
    let mut disk_peak = 0;
    let mut health_max = Duration::ZERO;
    let mut sample = tokio::time::interval(Duration::from_millis(2));
    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);
    loop {
        let health_start = Instant::now();
        tokio::time::timeout(Duration::from_secs(2), host.health())
            .await
            .expect("health deadline")
            .unwrap();
        health_max = health_max.max(health_start.elapsed());
        peak = peak.max(host.metrics().memory_bytes.unwrap_or(0));
        if let Ok(usage) = measure(&data, Limits::default().data_entries) {
            disk_peak = disk_peak.max(usage.bytes);
        }
        let event = tokio::select! {
            event = scan.next() => event,
            _ = &mut deadline => panic!("scan deadline"),
            _ = sample.tick() => continue,
        };
        match event {
            Some(StreamEvent::Data(frame)) => {
                if frame["state"] == "completed" {
                    completed = Some(frame);
                }
            }
            Some(StreamEvent::Closed) => break,
            other => panic!(
                "scan did not finish successfully: {other:?}; {:?}",
                host.logs()
            ),
        }
    }
    let report = completed.expect("the scan has no completed report");
    assert_eq!(report["engineVersion"], "0.75.0+srelens.1");
    assert_eq!(
        report["imageId"],
        "sha256:055936d3920576da37aa9bc460d70c5f212028bda1c08c0879aedf03d7a66ea1"
    );
    assert_eq!(report["architecture"], "amd64");
    let packages: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["id"] == "CVE-2019-1549")
        .map(|f| f["package"].as_str().unwrap())
        .collect();
    assert!(
        packages.contains(&"libcrypto1.1") && packages.contains(&"libssl1.1"),
        "{packages:?}"
    );
    assert!(
        peak > 0 && peak <= Limits::default().memory_bytes,
        "memory {peak}"
    );
    assert!(
        disk_peak > 0 && disk_peak <= Limits::default().data_bytes,
        "disk {disk_peak}"
    );
    #[cfg(target_os = "linux")]
    {
        let root = PathBuf::from(std::env::var_os("SRELENS_SANDBOX_CGROUP_ROOT").unwrap());
        for entry in std::fs::read_dir(root).unwrap().flatten() {
            let p = entry.path();
            if p.join("memory.max").is_file() && p.file_name().unwrap() != "host" {
                for file in [
                    "memory.max",
                    "memory.peak",
                    "memory.events",
                    "cpu.max",
                    "cpu.stat",
                ] {
                    println!(
                        "{file}: {}",
                        std::fs::read_to_string(p.join(file)).unwrap().trim()
                    );
                }
            }
        }
        let pid = match host.status() {
            SidecarStatus::Running { pid: Some(pid), .. } => pid,
            s => panic!("{s:?}"),
        };
        println!(
            "process memory: {}",
            std::fs::read_to_string(format!("/proc/{pid}/status"))
                .unwrap()
                .lines()
                .filter(|l| l.starts_with("VmRSS:") || l.starts_with("VmHWM:"))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    println!("scan_ms={} sampled_memory_bytes={peak} sampled_disk_bytes={disk_peak} max_health_ms={} data_root={}", started.elapsed().as_millis(), health_max.as_millis(), data.display());
    println!("findings={}", report["findings"].as_array().unwrap().len());
    host.stop().await;
    assert_eq!(host.metrics().unexpected_exits, 0);
}

#[tokio::test]
async fn cancel_scan_keeps_the_sidecar_responsive() {
    let (_root, _data, host) = start("TRIVY_PROOF_FIXTURES").await;
    let mut scan = host.open_stream("scan", json!({})).await.unwrap();
    assert!(matches!(scan.next().await, Some(StreamEvent::Data(_))));
    let started = Instant::now();
    drop(scan);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            host.health().await.unwrap();
            if host.metrics().open_streams == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancellation did not release the stream");
    // A second complete scan proves the first released its scanner and DB.
    let mut next = host.open_stream("scan", json!({})).await.unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(30), next.next())
            .await
            .unwrap()
        {
            Some(StreamEvent::Data(_)) => {}
            Some(StreamEvent::Closed) => break,
            other => panic!(
                "scanner was not reusable after cancellation: {other:?}; {:?}",
                host.logs()
            ),
        }
    }
    println!("cancel_and_rescan_ms={}", started.elapsed().as_millis());
    host.stop().await;
    assert_eq!(host.metrics().unexpected_exits, 0);
}

#[tokio::test]
async fn debian_image_must_scan_without_changing_file_modes_by_path() {
    let (_root, _data, host) = start("TRIVY_PROOF_DEBIAN_FIXTURES").await;
    let mut scan = host.open_stream("scan", json!({})).await.unwrap();
    let mut completed = false;
    loop {
        match tokio::time::timeout(Duration::from_secs(30), scan.next())
            .await
            .unwrap()
        {
            Some(StreamEvent::Data(frame)) => {
                if frame["state"] == "completed" {
                    assert_eq!(
                        frame["imageId"],
                        "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4"
                    );
                    completed = true;
                    println!("Debian findings={}", frame["findings"]);
                    assert!(frame["findings"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|f| f["id"] == "CVE-2019-1563"));
                }
            }
            Some(StreamEvent::Closed) => break,
            other => panic!(
                "Debian compatibility gate failed: {other:?}; {:?}",
                host.logs()
            ),
        }
    }
    assert!(completed);
    host.health().await.unwrap();
    host.stop().await;
}
