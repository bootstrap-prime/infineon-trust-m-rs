// taken from https://github.com/drone-os/drone-core

extern crate alloc;
use alloc::alloc::{alloc, alloc_zeroed, dealloc, Layout};
use core::ffi::c_void;

/// Allocator
#[no_mangle]
pub unsafe extern "C" fn pal_os_malloc(size: cty::size_t) -> *mut cty::c_void {
    alloc(Layout::from_size_align_unchecked(size, 1)) as *mut c_void
}
#[no_mangle]
pub unsafe extern "C" fn pal_os_calloc(nmemb: cty::size_t, size: cty::size_t) -> *mut cty::c_void {
    alloc_zeroed(Layout::from_size_align_unchecked(nmemb * size, 1)) as *mut c_void
}
#[no_mangle]
pub unsafe extern "C" fn pal_os_free(ptr: *mut cty::c_void) {
    dealloc(ptr as *mut u8, Layout::from_size_align_unchecked(1, 1));
}

#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const cty::c_char) -> usize {
    let mut n = 0;
    let mut s = s;
    while *s != 0 {
        n += 1;
        s = s.offset(1);
    }
    n
}
