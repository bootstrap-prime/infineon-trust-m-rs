// taken from https://github.com/drone-os/drone-core

extern crate alloc;
use alloc::alloc::{alloc, alloc_zeroed, dealloc, Layout};
use core::ffi::c_void;

/// Allocator
/// allocates uninitialized memory in the heap for size bytes
#[no_mangle]
pub extern "C" fn pal_os_malloc(size: cty::size_t) -> *mut cty::c_void {
    unsafe { alloc(Layout::from_size_align_unchecked(size, 1)) as *mut c_void }
}

/// allocates memory in the heap for an array of nmemb objects of size and initializes all bytes in storage to zero.
#[no_mangle]
pub extern "C" fn pal_os_calloc(nmemb: cty::size_t, size: cty::size_t) -> *mut cty::c_void {
    unsafe { alloc_zeroed(Layout::from_size_align_unchecked(nmemb * size, 1)) as *mut c_void }
}

/// # Safety
/// ptr must be a valid pointer to a location on the heap that was allocated with calloc or malloc
#[no_mangle]
pub unsafe extern "C" fn pal_os_free(ptr: *mut cty::c_void) {
    dealloc(ptr as *mut u8, Layout::from_size_align_unchecked(1, 1));
}

/// # Safety
/// s must be a valid pointer to a c like string.
#[no_mangle]
#[cfg(feature = "c_stubs-strlen")]
pub unsafe extern "C" fn strlen(s: *const cty::c_char) -> usize {
    let mut n = 0;
    let mut s = s;
    while *s != 0 {
        n += 1;
        s = s.offset(1);
    }
    n
}
