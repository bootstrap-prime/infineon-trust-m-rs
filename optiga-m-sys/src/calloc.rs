// taken from https://gist.github.com/richardeoin/5dc271f8fb186100eb3e9e73afffe1a3

use core::cmp;
use core::ptr;
use core::{mem, mem::MaybeUninit};

extern crate alloc;
use alloc::alloc::Layout;

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use hashbrown::HashMap;

static mut MALLOC_TABLE: MaybeUninit<HashMap<*mut u8, Layout>> = MaybeUninit::uninit();
static MALLOC_TABLE_INIT: AtomicBool = AtomicBool::new(false);

static BYTES_USED: AtomicUsize = AtomicUsize::new(0);
static BYTES_PEAK: AtomicUsize = AtomicUsize::new(0);

fn malloc_table_init() -> &'static mut HashMap<*mut u8, Layout> {
    if !MALLOC_TABLE_INIT.swap(true, Ordering::AcqRel) {
        unsafe {
            (*(&mut MALLOC_TABLE).assume_init_mut()) = HashMap::new();
        }
    }

    unsafe { (&mut MALLOC_TABLE).assume_init_mut() }
}

/// Allocator
#[no_mangle]
pub unsafe extern "C" fn pal_os_malloc(size: cty::size_t) -> *mut cty::c_void {
    //info!("malloc: {} bytes", size);
    let layout = Layout::from_size_align(size, mem::align_of::<u32>()).expect("Bad layout");

    // Allocate
    let mem = alloc::alloc::alloc(layout);

    // Remember layout (another allocate internally!)
    malloc_table_init().insert(mem, layout);

    // Track memory usage
    let current_usage = size + BYTES_USED.fetch_add(size, Ordering::Relaxed);
    BYTES_PEAK
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |peak| {
            Some(cmp::max(peak, current_usage))
        })
        .unwrap();

    mem::transmute::<*mut u8, *mut cty::c_void>(mem)
}
#[no_mangle]
pub unsafe extern "C" fn pal_os_calloc(nmemb: cty::size_t, size: cty::size_t) -> *mut cty::c_void {
    let mem = pal_os_malloc(nmemb * size);

    ptr::write_bytes(mem, 0, nmemb * size);

    mem
}
#[no_mangle]
pub unsafe extern "C" fn pal_os_free(ptr: *mut cty::c_void) {
    let ptr = mem::transmute::<*mut cty::c_void, *mut u8>(ptr);

    match malloc_table_init().remove(&ptr) {
        Some(layout) => {
            alloc::alloc::dealloc(ptr, layout);

            BYTES_USED.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        None => {
            // warn!("Could not find layout for memory at {:?}", ptr);
            // Leak memory
        }
    }
}

/// Gets the current and peak memory usage for the allocator
///
/// Returns (current, peak) bytes
#[allow(dead_code)]
pub fn get_memory_usage() -> (usize, usize) {
    (
        BYTES_USED.load(Ordering::Relaxed),
        BYTES_PEAK.load(Ordering::Relaxed),
    )
}
