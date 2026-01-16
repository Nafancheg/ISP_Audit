#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, c_void};
use std::mem;
use std::ptr;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{BOOL, FARPROC, HMODULE, SetLastError, ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

/// Совместимый с `WinDivertNative.Address` layout.
///
/// Размер: 80 байт = 8 (Timestamp) + 4 (LayerEventFlags) + 4 (Reserved2) + 64 (Union data).
#[repr(C)]
pub struct DivertAddress {
    pub timestamp: i64,
    pub layer_event_flags: u32,
    pub reserved2: u32,
    pub data: [u8; 64],
}

type WinDivertOpenFn = unsafe extern "system" fn(
    filter: *const c_char,
    layer: i32,
    priority: i16,
    flags: u64,
) -> *mut c_void;

type WinDivertRecvFn = unsafe extern "system" fn(
    handle: *mut c_void,
    packet: *mut c_void,
    packet_len: u32,
    recv_len: *mut u32,
    addr: *mut DivertAddress,
) -> BOOL;

type WinDivertSendFn = unsafe extern "system" fn(
    handle: *mut c_void,
    packet: *const c_void,
    packet_len: u32,
    send_len: *mut u32,
    addr: *const DivertAddress,
) -> BOOL;

type WinDivertShutdownFn = unsafe extern "system" fn(handle: *mut c_void, how: u32) -> BOOL;

type WinDivertCloseFn = unsafe extern "system" fn(handle: *mut c_void) -> BOOL;

type WinDivertHelperCalcChecksumsFn = unsafe extern "system" fn(
    packet: *mut c_void,
    packet_len: u32,
    addr: *mut DivertAddress,
    flags: u64,
) -> BOOL;

struct WinDivertApi {
    #[allow(dead_code)]
    module: HMODULE,
    open: WinDivertOpenFn,
    recv: WinDivertRecvFn,
    send: WinDivertSendFn,
    shutdown: WinDivertShutdownFn,
    close: WinDivertCloseFn,
    calc_checksums: WinDivertHelperCalcChecksumsFn,
}

static API: OnceLock<WinDivertApi> = OnceLock::new();

fn get_api() -> Option<&'static WinDivertApi> {
    API.get_or_try_init(|| unsafe { load_api() }).ok()
}

unsafe fn load_api() -> Result<WinDivertApi, ()> {
    // Важно: грузим WinDivert.dll динамически.
    // Это позволяет собирать DLL без WinDivert SDK/линковки.
    let module = LoadLibraryA(b"WinDivert.dll\0".as_ptr());
    if module == 0 {
        SetLastError(ERROR_MOD_NOT_FOUND);
        return Err(());
    }

    unsafe fn get_proc<T>(module: HMODULE, name: &'static [u8]) -> Result<T, ()> {
        let p: FARPROC = GetProcAddress(module, name.as_ptr());
        if p.is_null() {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return Err(());
        }
        Ok(mem::transmute_copy(&p))
    }

    let open: WinDivertOpenFn = get_proc(module, b"WinDivertOpen\0")?;
    let recv: WinDivertRecvFn = get_proc(module, b"WinDivertRecv\0")?;
    let send: WinDivertSendFn = get_proc(module, b"WinDivertSend\0")?;
    let shutdown: WinDivertShutdownFn = get_proc(module, b"WinDivertShutdown\0")?;
    let close: WinDivertCloseFn = get_proc(module, b"WinDivertClose\0")?;
    let calc_checksums: WinDivertHelperCalcChecksumsFn =
        get_proc(module, b"WinDivertHelperCalcChecksums\0")?;

    Ok(WinDivertApi {
        module,
        open,
        recv,
        send,
        shutdown,
        close,
        calc_checksums,
    })
}

/// Открывает WinDivert handle.
///
/// Сигнатура совместима с WinDivertOpen (ANSI filter) и calling convention `system`.
#[no_mangle]
pub unsafe extern "system" fn divert_open(
    filter: *const c_char,
    layer: i32,
    priority: i16,
    flags: u64,
) -> *mut c_void {
    let Some(api) = get_api() else {
        // SetLastError уже выставлен в load_api().
        return ptr::null_mut();
    };

    (api.open)(filter, layer, priority, flags)
}

/// Получает пакет из WinDivert.
#[no_mangle]
pub unsafe extern "system" fn divert_recv(
    handle: *mut c_void,
    packet: *mut c_void,
    packet_len: u32,
    recv_len: *mut u32,
    addr: *mut DivertAddress,
) -> BOOL {
    let Some(api) = get_api() else {
        return 0;
    };

    (api.recv)(handle, packet, packet_len, recv_len, addr)
}

/// Отправляет пакет через WinDivert.
#[no_mangle]
pub unsafe extern "system" fn divert_send(
    handle: *mut c_void,
    packet: *const c_void,
    packet_len: u32,
    send_len: *mut u32,
    addr: *const DivertAddress,
) -> BOOL {
    let Some(api) = get_api() else {
        return 0;
    };

    (api.send)(handle, packet, packet_len, send_len, addr)
}

/// Shutdown handle.
#[no_mangle]
pub unsafe extern "system" fn divert_shutdown(handle: *mut c_void, how: u32) -> BOOL {
    let Some(api) = get_api() else {
        return 0;
    };

    (api.shutdown)(handle, how)
}

/// Закрывает handle.
#[no_mangle]
pub unsafe extern "system" fn divert_close(handle: *mut c_void) -> BOOL {
    let Some(api) = get_api() else {
        return 0;
    };

    (api.close)(handle)
}

/// Пересчитывает checksums.
#[no_mangle]
pub unsafe extern "system" fn divert_calc_checksums(
    packet: *mut c_void,
    packet_len: u32,
    addr: *mut DivertAddress,
    flags: u64,
) -> BOOL {
    let Some(api) = get_api() else {
        return 0;
    };

    (api.calc_checksums)(packet, packet_len, addr, flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divert_address_layout_is_80_bytes() {
        assert_eq!(std::mem::size_of::<DivertAddress>(), 80);
        assert_eq!(std::mem::align_of::<DivertAddress>(), 8);
    }
}
