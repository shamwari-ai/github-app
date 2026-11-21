//! Logging that lands in Workers Logs on wasm32 and on stderr elsewhere.

#[cfg(target_arch = "wasm32")]
pub fn info(msg: &str) {
    worker::console_log!("{}", msg);
}
#[cfg(target_arch = "wasm32")]
pub fn warn(msg: &str) {
    worker::console_warn!("{}", msg);
}
#[cfg(target_arch = "wasm32")]
pub fn error(msg: &str) {
    worker::console_error!("{}", msg);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn info(msg: &str) {
    eprintln!("[info] {msg}");
}
#[cfg(not(target_arch = "wasm32"))]
pub fn warn(msg: &str) {
    eprintln!("[warn] {msg}");
}
#[cfg(not(target_arch = "wasm32"))]
pub fn error(msg: &str) {
    eprintln!("[error] {msg}");
}
