use std::{
    fs::File,
    io,
    mem::{MaybeUninit, size_of, size_of_val},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};

use tempfile::NamedTempFile;
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, DACL_SECURITY_INFORMATION,
        EqualSid, GetAce, GetKernelObjectSecurity, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetTokenInformation, InitializeAcl,
        InitializeSecurityDescriptor, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
        SECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_RELATIVE, SECURITY_MAX_SID_SIZE,
        SetSecurityDescriptorControl, SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
    System::{
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

const ACL_SIZE: usize =
    size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() + SECURITY_MAX_SID_SIZE as usize;

#[repr(C)]
struct TokenUserBuffer {
    user: TOKEN_USER,
    sid: [u8; SECURITY_MAX_SID_SIZE as usize],
}

fn read_user_token(buffer: &mut MaybeUninit<TokenUserBuffer>) -> io::Result<PSID> {
    let mut token = ptr::null_mut();
    // SAFETY: The pseudo-process handle is valid and `token` can receive the owned token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken succeeded and transferred ownership of a real handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut length = 0;
    // SAFETY: The aligned buffer has room for TOKEN_USER and the largest possible SID. The SID
    // returned by Windows is borrowed from this buffer and callers keep it alive during use.
    unsafe {
        if GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size_of::<TokenUserBuffer>() as u32,
            &mut length,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((*buffer.as_ptr()).user.User.Sid)
    }
}

pub(super) fn private_tempfile(directory: &Path) -> io::Result<NamedTempFile> {
    let mut user_token = MaybeUninit::uninit();
    let sid = read_user_token(&mut user_token)?;
    let mut acl_storage = [0u32; ACL_SIZE.div_ceil(size_of::<u32>())];
    let acl = acl_storage.as_mut_ptr().cast::<ACL>();
    let mut descriptor_storage = MaybeUninit::<SECURITY_DESCRIPTOR>::uninit();
    let descriptor = descriptor_storage.as_mut_ptr().cast();
    // SAFETY: Each API initializes or uses the named buffers in order. All buffers outlive the
    // file creation call that borrows them. The protected DACL suppresses directory inheritance.
    unsafe {
        if InitializeAcl(acl, size_of_val(&acl_storage) as u32, ACL_REVISION) == 0
            || AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sid) == 0
            || InitializeSecurityDescriptor(descriptor, SECURITY_DESCRIPTOR_REVISION) == 0
            || SetSecurityDescriptorDacl(descriptor, 1, acl, 0) == 0
            || SetSecurityDescriptorControl(descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };

    let file = tempfile::Builder::new().make_in(directory, |path| {
        let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: The path is NUL-terminated, and the initialized attributes and their buffers
        // remain valid through CreateFileW. CREATE_NEW preserves existing files.
        unsafe {
            let handle = CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok(File::from_raw_handle(handle))
        }
    })?;
    // Filesystems can ignore security attributes. Check the effective DACL before writing.
    verify_private_acl(file.as_file(), sid)?;
    Ok(file)
}

fn verify_private_acl(file: &File, sid: PSID) -> io::Result<()> {
    const DESCRIPTOR_SIZE: usize = size_of::<SECURITY_DESCRIPTOR_RELATIVE>() + ACL_SIZE;
    let mut storage = [0u32; DESCRIPTOR_SIZE.div_ceil(size_of::<u32>())];
    let descriptor = storage.as_mut_ptr().cast();
    let mut length = 0;
    let mut control = 0;
    let mut revision = 0;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = ptr::null_mut();
    // SAFETY: `file` is open and both SID and output storage are valid for the duration of the
    // call. Successful pointer outputs refer to the descriptor buffer, which is kept alive.
    unsafe {
        if GetKernelObjectSecurity(
            file.as_raw_handle(),
            DACL_SECURITY_INFORMATION,
            descriptor,
            size_of_val(&storage) as u32,
            &mut length,
        ) == 0
            || GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
            || GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) == 0
        {
            return Err(io::Error::last_os_error());
        }
        if control & SE_DACL_PROTECTED != 0
            && present != 0
            && !acl.is_null()
            && (*acl).AceCount == 1
        {
            let mut entry = ptr::null_mut();
            if GetAce(acl, 0, &mut entry) == 0 {
                return Err(io::Error::last_os_error());
            }
            let ace = entry.cast::<ACCESS_ALLOWED_ACE>();
            if u32::from((*ace).Header.AceType) == ACCESS_ALLOWED_ACE_TYPE
                && (*ace).Header.AceFlags == 0
                && (*ace).Mask == FILE_ALL_ACCESS
                && EqualSid(ptr::addr_of_mut!((*ace).SidStart).cast(), sid) != 0
            {
                return Ok(());
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "private key file requires a protected user-only ACL",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_private_key_retains_its_protected_acl() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let private_key = directory.path().join("private.pem");
        let public_key = directory.path().join("public.pem");
        super::super::generate_keypair(
            &private_key,
            &public_key,
            super::super::Algorithm::Ed25519,
        )?;

        let mut user_token = MaybeUninit::uninit();
        let sid = read_user_token(&mut user_token)?;
        verify_private_acl(&File::open(private_key)?, sid)?;
        let inherited_file = File::create(directory.path().join("inherited.pem"))?;
        assert!(verify_private_acl(&inherited_file, sid).is_err());
        Ok(())
    }
}
