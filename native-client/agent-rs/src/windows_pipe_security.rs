#![cfg(windows)]
#![allow(unsafe_code)]

use anyhow::{Context, Result, bail};
use std::{ffi::c_void, io, mem::size_of, ptr};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

pub fn create_secure_named_pipe(path: &str, first: bool) -> Result<NamedPipeServer> {
    let sid = current_user_sid().context("resolve current Windows user SID")?;
    let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})");
    let mut security = PipeSecurity::from_sddl(&sddl).context("build named pipe DACL")?;
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first);
    // SAFETY: `security` owns a valid SECURITY_DESCRIPTOR and remains alive for the call.
    unsafe {
        options
            .create_with_security_attributes_raw(path, security.attributes_ptr())
            .context("create current-user-only control named pipe")
    }
}

fn current_user_sid() -> Result<String> {
    let mut raw_token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle and raw_token is a valid out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) } == 0 {
        return Err(io::Error::last_os_error()).context("open current process token");
    }
    let token = OwnedHandle(raw_token);
    let mut required = 0u32;
    // SAFETY: A null buffer with length zero is the documented size query.
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &raw mut required);
    }
    if required == 0 {
        return Err(io::Error::last_os_error()).context("size current token user");
    }
    let word = size_of::<usize>();
    let mut storage = vec![0usize; (required as usize).div_ceil(word)];
    // SAFETY: storage is aligned and contains at least `required` writable bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast::<c_void>(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("read current token user");
    }
    // SAFETY: GetTokenInformation initialized storage as TOKEN_USER.
    let token_user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let mut raw_string = ptr::null_mut();
    // SAFETY: token_user.User.Sid is valid while storage is alive; raw_string is an out pointer.
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &raw mut raw_string) } == 0 {
        return Err(io::Error::last_os_error()).context("format current user SID");
    }
    let sid_string = LocalAllocation(raw_string.cast::<c_void>());
    let mut length = 0usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated UTF-16 allocation.
    unsafe {
        while *raw_string.add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: the allocation contains `length` initialized UTF-16 code units.
    let slice = unsafe { std::slice::from_raw_parts(raw_string, length) };
    let value = String::from_utf16(slice).context("decode current user SID")?;
    drop(sid_string);
    Ok(value)
}

struct PipeSecurity {
    _descriptor: LocalAllocation,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: wide is NUL-terminated and descriptor is a valid out pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error()).context("convert named pipe SDDL");
        }
        if descriptor.is_null() {
            bail!("Windows returned a null security descriptor");
        }
        let descriptor = LocalAllocation(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .context("SECURITY_ATTRIBUTES size exceeds u32")?,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        Ok(Self {
            _descriptor: descriptor,
            attributes,
        })
    }

    const fn attributes_ptr(&mut self) -> *mut c_void {
        (&raw mut self.attributes).cast::<c_void>()
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns the token handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: LocalFree owns allocations returned by the conversion APIs above.
            unsafe { LocalFree(self.0) };
        }
    }
}
