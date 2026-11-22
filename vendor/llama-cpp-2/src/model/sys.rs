//! Owned Win32/CRT FILE bridge. No filename or new filesystem authority is used.
use std::{ffi::c_void, fs::File, io::Seek, os::windows::io::AsRawHandle};
unsafe extern "C" {
    fn nw_model_file_open(source: *mut c_void) -> *mut c_void;
    fn nw_model_file_close(stream: *mut c_void);
}
struct Stream(*mut c_void);
impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: created by the paired target-CRT function; this is its sole owner.
        unsafe { nw_model_file_close(self.0) };
    }
}
pub(super) fn load_open_file(
    file: &mut File,
    mut params: llama_cpp_sys_2::llama_model_params,
) -> *mut llama_cpp_sys_2::llama_model {
    if file.rewind().is_err() {
        return std::ptr::null_mut();
    }
    // SAFETY: the borrowed File remains live; C duplicates its handle and owns only the copy.
    let stream = unsafe { nw_model_file_open(file.as_raw_handle()) };
    if stream.is_null() {
        return std::ptr::null_mut();
    }
    let stream = Stream(stream);
    // Native loader completes all reads before return when mmap is disabled.
    params.load_mode = match params.load_mode {
        llama_cpp_sys_2::LLAMA_LOAD_MODE_MLOCK | llama_cpp_sys_2::LLAMA_LOAD_MODE_MMAP_MLOCK =>
            llama_cpp_sys_2::LLAMA_LOAD_MODE_MLOCK,
        _ => llama_cpp_sys_2::LLAMA_LOAD_MODE_NONE,
    };
    // SAFETY: this is a live target-CRT FILE*, positioned at the start of the file.
    // The pinned llama.cpp API borrows it. Stream closes it after synchronous loading.
    unsafe { llama_cpp_sys_2::llama_model_load_from_file_ptr(stream.0.cast(), params) }
}
