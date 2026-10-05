// The pinned host's unchanged launcher, built with the proof harness.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    srelens_plugin_host::sidecar::sandbox::launch::main()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {}
