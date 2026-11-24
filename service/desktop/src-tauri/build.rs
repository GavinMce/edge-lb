fn main() {
    // List the app's commands so Tauri enforces *who* may call them (see capabilities/): without
    // this, any window the app opens could invoke them.
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(&["get_state", "start_local", "connect_remote", "forget_remote", "plan_setup", "check_host", "trust_host", "setup_server"])),
    )
    .expect("failed to run tauri-build");
}
