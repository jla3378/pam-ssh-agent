use anyhow::{Context, Result, anyhow};
use std::ffi::{CString, c_int, c_void};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
const O_RESOLVE_BENEATH: c_int = 0x0000_1000;
const O_UNIQUE: c_int = 0x0000_2000;

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
    fn acl_free(object: *mut c_void) -> c_int;
}

#[derive(Clone, Copy)]
enum ObjectKind {
    Directory,
    Policy,
}

#[derive(Eq, PartialEq)]
struct Snapshot {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u32,
    size: u64,
    modified: i64,
    modified_nanos: i64,
    changed: i64,
    changed_nanos: i64,
}

struct OpenedPolicy {
    file: File,
    parents: Vec<File>,
}

impl Snapshot {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            uid: metadata.uid(),
            size: metadata.size(),
            modified: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        }
    }
}

pub(crate) fn read_policy(path: &Path, required_uid: u32, limit: u64) -> Result<String> {
    let components = absolute_components(path)?;
    validate_lexical_path(path, &components, required_uid)?;
    let canonical = fs::canonicalize(path).context("Could not resolve trusted-key path")?;
    let canonical_components = absolute_components(&canonical)?;
    let root = open_root()?;
    let opened = open_relative(root, &canonical_components, required_uid, &mut |_| {})?;
    read_opened(opened, required_uid, limit, || {})
}

fn read_opened(
    mut opened: OpenedPolicy,
    required_uid: u32,
    limit: u64,
    before_read: impl FnOnce(),
) -> Result<String> {
    let before_file = Snapshot::from(&validate_object(
        &opened.file,
        required_uid,
        ObjectKind::Policy,
    )?);
    let before_parents = parent_snapshots(&opened.parents, required_uid)?;
    before_read();
    let mut bytes = Vec::new();
    (&mut opened.file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(anyhow!("Trusted-key policy exceeds {limit} bytes"));
    }
    let after_file = Snapshot::from(&validate_object(
        &opened.file,
        required_uid,
        ObjectKind::Policy,
    )?);
    let after_parents = parent_snapshots(&opened.parents, required_uid)?;
    if before_file != after_file || before_parents != after_parents {
        return Err(anyhow!("Trusted-key path changed while reading"));
    }
    Ok(String::from_utf8(bytes)?)
}

fn parent_snapshots(parents: &[File], required_uid: u32) -> Result<Vec<Snapshot>> {
    parents
        .iter()
        .map(|parent| {
            validate_object(parent, required_uid, ObjectKind::Directory)
                .map(|metadata| Snapshot::from(&metadata))
        })
        .collect()
}

fn open_root() -> Result<File> {
    let descriptor = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_SEARCH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    owned_file(descriptor, "Could not open trusted-key root")
}

fn open_relative(
    anchor: File,
    components: &[PathBuf],
    required_uid: u32,
    on_parent: &mut impl FnMut(usize),
) -> Result<OpenedPolicy> {
    let Some((filename, parents)) = components.split_last() else {
        return Err(anyhow!("Strict trusted-key path has no filename"));
    };
    let mut parents_opened = vec![anchor];
    validate_object(
        parents_opened.last().unwrap(),
        required_uid,
        ObjectKind::Directory,
    )?;
    for (index, component) in parents.iter().enumerate() {
        let directory = open_at(
            parents_opened.last().unwrap(),
            component,
            libc::O_SEARCH | libc::O_CLOEXEC | libc::O_NOFOLLOW | O_RESOLVE_BENEATH,
        )?;
        validate_object(&directory, required_uid, ObjectKind::Directory)?;
        parents_opened.push(directory);
        on_parent(index);
    }
    let file = open_at(
        parents_opened.last().unwrap(),
        filename,
        libc::O_RDONLY
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | O_RESOLVE_BENEATH
            | O_UNIQUE,
    )?;
    Ok(OpenedPolicy {
        file,
        parents: parents_opened,
    })
}

fn open_at(directory: &File, component: &Path, flags: c_int) -> Result<File> {
    let component = CString::new(component.as_os_str().as_bytes())?;
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), component.as_ptr(), flags) };
    owned_file(descriptor, "Could not open trusted-key path component")
}

fn owned_file(descriptor: c_int, context: &str) -> Result<File> {
    if descriptor == -1 {
        return Err(io::Error::last_os_error()).context(context.to_owned());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn validate_object(file: &File, required_uid: u32, kind: ObjectKind) -> Result<Metadata> {
    let metadata = file.metadata()?;
    if metadata.uid() != required_uid {
        return Err(anyhow!(
            "Trusted-key path is not owned by uid {required_uid}"
        ));
    }
    match kind {
        ObjectKind::Directory => {
            if !metadata.is_dir() {
                return Err(anyhow!("Trusted-key parent is not a directory"));
            }
            if metadata.mode() & 0o022 != 0 {
                return Err(anyhow!("Trusted-key parent is group- or world-writable"));
            }
        }
        ObjectKind::Policy => {
            if !metadata.is_file() {
                return Err(anyhow!("Trusted-key path is not a regular file"));
            }
            if metadata.mode() & 0o7777 != 0o600 {
                return Err(anyhow!("Strict trusted-key file mode must be 0600"));
            }
            if metadata.nlink() != 1 {
                return Err(anyhow!("Strict trusted-key file must have one link"));
            }
        }
    }
    reject_acl(file)?;
    Ok(metadata)
}

fn reject_acl(file: &File) -> Result<()> {
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if !acl.is_null() {
        let result = unsafe { acl_free(acl) };
        if result != 0 {
            return Err(io::Error::last_os_error()).context("Could not free file ACL");
        }
        return Err(anyhow!("Strict trusted-key path has an extended ACL"));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        return Ok(());
    }
    Err(error).context("Could not inspect file ACL")
}

fn validate_lexical_path(path: &Path, components: &[PathBuf], required_uid: u32) -> Result<()> {
    let root = open_root()?;
    validate_object(&root, required_uid, ObjectKind::Directory)?;
    let mut current = PathBuf::from("/");
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.uid() != required_uid {
            return Err(anyhow!(
                "Trusted-key path is not owned by uid {required_uid}"
            ));
        }
        let is_final = index + 1 == components.len();
        if metadata.file_type().is_symlink() {
            if is_final {
                return Err(anyhow!("Strict trusted-key file cannot be a symlink"));
            }
            continue;
        }
        if !is_final {
            let directory = open_absolute_directory(&current)?;
            validate_object(&directory, required_uid, ObjectKind::Directory)?;
        }
    }
    if current != path {
        return Err(anyhow!(
            "Strict trusted-key path must be absolute and normalized"
        ));
    }
    Ok(())
}

fn open_absolute_directory(path: &Path) -> Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_SEARCH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    owned_file(descriptor, "Could not open trusted-key parent")
}

fn absolute_components(path: &Path) -> Result<Vec<PathBuf>> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(anyhow!(
            "Strict trusted-key path must be absolute and normalized"
        ));
    }
    let mut names = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) => names.push(PathBuf::from(name)),
            _ => {
                return Err(anyhow!(
                    "Strict trusted-key path must be absolute and normalized"
                ));
            }
        }
    }
    let normalized = names.iter().fold(PathBuf::from("/"), |mut path, name| {
        path.push(name);
        path
    });
    if normalized.as_os_str().as_bytes() != path.as_os_str().as_bytes() {
        return Err(anyhow!(
            "Strict trusted-key path must be absolute and normalized"
        ));
    }
    Ok(names)
}

#[cfg(test)]
fn read_policy_at(anchor: File, path: &Path, required_uid: u32, limit: u64) -> Result<String> {
    let components = relative_components(path)?;
    let opened = open_relative(anchor, &components, required_uid, &mut |_| {})?;
    read_opened(opened, required_uid, limit, || {})
}

#[cfg(test)]
fn read_policy_at_with_hooks(
    anchor: File,
    path: &Path,
    required_uid: u32,
    limit: u64,
    mut on_parent: impl FnMut(usize),
    before_read: impl FnOnce(),
) -> Result<String> {
    let components = relative_components(path)?;
    let opened = open_relative(anchor, &components, required_uid, &mut on_parent)?;
    read_opened(opened, required_uid, limit, before_read)
}

#[cfg(test)]
fn relative_components(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_absolute() {
        return Err(anyhow!("Test trust path must be relative"));
    }
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => names.push(PathBuf::from(name)),
            _ => return Err(anyhow!("Test trust path must be normalized")),
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::{
        ACL_TYPE_EXTENDED, O_RESOLVE_BENEATH, O_UNIQUE, read_policy, read_policy_at,
        read_policy_at_with_hooks,
    };
    use std::ffi::{CString, c_int};
    use std::fs::{self, File};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        root: PathBuf,
    }

    struct RootFixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "pam-trust-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let policy = root.join("policy");
            fs::write(&policy, "trusted\n").unwrap();
            fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
            Self { root }
        }

        fn anchor(&self) -> File {
            File::open(&self.root).unwrap()
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }

        fn read(&self, name: &str) -> anyhow::Result<String> {
            read_policy_at(
                self.anchor(),
                Path::new(name),
                unsafe { libc::geteuid() },
                1024,
            )
        }

        fn write(&self, name: &str, contents: &str) {
            let path = self.path(name);
            fs::write(&path, contents).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn add_acl(&self, name: &str, rule: &str) {
            let status = Command::new("/bin/chmod")
                .args(["+a", rule])
                .arg(self.path(name))
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    impl Drop for RootFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn reads_valid_descriptor_bound_policy() {
        let fixture = Fixture::new();
        assert_eq!(fixture.read("policy").unwrap(), "trusted\n");
    }

    #[test]
    fn rejects_wrong_owner() {
        let fixture = Fixture::new();
        let wrong_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        assert!(read_policy_at(fixture.anchor(), Path::new("policy"), wrong_uid, 1024).is_err());
    }

    #[test]
    fn rejects_non_contract_modes_and_hard_links() {
        let fixture = Fixture::new();
        for mode in [0o400, 0o640, 0o644, 0o660, 0o6000] {
            fs::set_permissions(fixture.path("policy"), fs::Permissions::from_mode(mode)).unwrap();
            assert!(fixture.read("policy").is_err(), "accepted mode {mode:o}");
        }
        fs::set_permissions(fixture.path("policy"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(fixture.path("policy"), fixture.path("alias")).unwrap();
        assert!(fixture.read("policy").is_err());
    }

    #[test]
    fn rejects_writable_or_acl_controlled_parents() {
        let fixture = Fixture::new();
        for mode in [0o770, 0o707, 0o1777] {
            fs::set_permissions(&fixture.root, fs::Permissions::from_mode(mode)).unwrap();
            assert!(fixture.read("policy").is_err(), "accepted mode {mode:o}");
        }
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
        fixture.add_acl("", "everyone allow add_file,delete_child");
        assert!(fixture.read("policy").is_err());
    }

    #[test]
    fn rejects_extended_acl_on_policy() {
        let fixture = Fixture::new();
        fixture.add_acl("policy", "everyone allow write");
        assert!(fixture.read("policy").is_err());
    }

    #[test]
    fn rejects_links_and_non_regular_objects_without_blocking() {
        let fixture = Fixture::new();
        symlink("policy", fixture.path("link")).unwrap();
        assert!(fixture.read("link").is_err());

        fs::create_dir(fixture.path("directory")).unwrap();
        assert!(fixture.read("directory").is_err());

        let fifo = fixture.path("fifo");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(fixture.read("fifo").is_err());

        let _listener = UnixListener::bind(fixture.path("socket")).unwrap();
        assert!(fixture.read("socket").is_err());
        assert!(read_policy(Path::new("/dev/null"), 0, 1024).is_err());
    }

    #[test]
    fn parent_replacement_uses_open_directory() {
        let fixture = Fixture::new();
        let trusted = fixture.path("trusted");
        fs::create_dir(&trusted).unwrap();
        fs::set_permissions(&trusted, fs::Permissions::from_mode(0o700)).unwrap();
        fixture.write("trusted/policy", "trusted\n");
        let root = fixture.root.clone();
        let result = read_policy_at_with_hooks(
            fixture.anchor(),
            Path::new("trusted/policy"),
            unsafe { libc::geteuid() },
            1024,
            move |_| {
                fs::rename(root.join("trusted"), root.join("opened")).unwrap();
                fs::create_dir(root.join("trusted")).unwrap();
                fs::set_permissions(root.join("trusted"), fs::Permissions::from_mode(0o700))
                    .unwrap();
                fs::write(root.join("trusted/policy"), "hostile\n").unwrap();
                fs::set_permissions(
                    root.join("trusted/policy"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            },
            || {},
        );
        assert_eq!(result.unwrap(), "trusted\n");
    }

    #[test]
    fn final_symlink_swap_fails_closed() {
        let fixture = Fixture::new();
        let trusted = fixture.path("trusted");
        fs::create_dir(&trusted).unwrap();
        fs::set_permissions(&trusted, fs::Permissions::from_mode(0o700)).unwrap();
        fixture.write("trusted/policy", "trusted\n");
        fixture.write("hostile", "hostile\n");
        let root = fixture.root.clone();
        let result = read_policy_at_with_hooks(
            fixture.anchor(),
            Path::new("trusted/policy"),
            unsafe { libc::geteuid() },
            1024,
            move |_| {
                fs::remove_file(root.join("trusted/policy")).unwrap();
                symlink("../hostile", root.join("trusted/policy")).unwrap();
            },
            || {},
        );
        assert!(result.is_err());
    }

    #[test]
    fn content_change_after_validation_fails_closed() {
        let fixture = Fixture::new();
        let policy = fixture.path("policy");
        let result = read_policy_at_with_hooks(
            fixture.anchor(),
            Path::new("policy"),
            unsafe { libc::geteuid() },
            1024,
            |_| {},
            move || fs::write(policy, "hostile\n").unwrap(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn parent_mode_change_before_final_open_fails_closed() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.path("trusted")).unwrap();
        fs::set_permissions(fixture.path("trusted"), fs::Permissions::from_mode(0o700)).unwrap();
        fixture.write("trusted/policy", "trusted\n");
        let parent = fixture.path("trusted");
        let result = read_policy_at_with_hooks(
            fixture.anchor(),
            Path::new("trusted/policy"),
            unsafe { libc::geteuid() },
            1024,
            move |_| fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap(),
            || {},
        );
        assert!(result.is_err());
    }

    #[test]
    fn parent_acl_change_before_final_open_fails_closed() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.path("trusted")).unwrap();
        fs::set_permissions(fixture.path("trusted"), fs::Permissions::from_mode(0o700)).unwrap();
        fixture.write("trusted/policy", "trusted\n");
        let parent = fixture.path("trusted");
        let result = read_policy_at_with_hooks(
            fixture.anchor(),
            Path::new("trusted/policy"),
            unsafe { libc::geteuid() },
            1024,
            move |_| {
                let status = Command::new("/bin/chmod")
                    .args(["+a", "everyone allow add_file,delete_child"])
                    .arg(&parent)
                    .status()
                    .unwrap();
                assert!(status.success());
            },
            || {},
        );
        assert!(result.is_err());
    }

    #[test]
    fn parent_mode_change_during_read_fails_closed() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.path("trusted")).unwrap();
        fs::set_permissions(fixture.path("trusted"), fs::Permissions::from_mode(0o700)).unwrap();
        fixture.write("trusted/policy", "trusted\n");
        let parent = fixture.path("trusted");
        let result = read_policy_at_with_hooks(
            fixture.anchor(),
            Path::new("trusted/policy"),
            unsafe { libc::geteuid() },
            1024,
            |_| {},
            move || fs::set_permissions(parent, fs::Permissions::from_mode(0o777)).unwrap(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn policy_acl_change_during_read_fails_closed() {
        let fixture = Fixture::new();
        let policy = fixture.path("policy");
        let result = read_policy_at_with_hooks(
            fixture.anchor(),
            Path::new("policy"),
            unsafe { libc::geteuid() },
            1024,
            |_| {},
            move || {
                let status = Command::new("/bin/chmod")
                    .args(["+a", "everyone allow write"])
                    .arg(policy)
                    .status()
                    .unwrap();
                assert!(status.success());
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn link_created_after_validation_fails_closed() {
        let fixture = Fixture::new();
        let policy = fixture.path("policy");
        let alias = fixture.path("alias");
        let result = read_policy_at_with_hooks(
            fixture.anchor(),
            Path::new("policy"),
            unsafe { libc::geteuid() },
            1024,
            |_| {},
            move || fs::hard_link(policy, alias).unwrap(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn path_replacement_never_consumes_replacement() {
        let fixture = Fixture::new();
        let policy = fixture.path("policy");
        let opened = fixture.path("opened");
        let replacement = policy.clone();
        let result = read_policy_at_with_hooks(
            fixture.anchor(),
            Path::new("policy"),
            unsafe { libc::geteuid() },
            1024,
            |_| {},
            move || {
                fs::rename(policy, opened).unwrap();
                fs::write(&replacement, "hostile\n").unwrap();
                fs::set_permissions(replacement, fs::Permissions::from_mode(0o600)).unwrap();
            },
        );
        if let Ok(contents) = result {
            assert_eq!(contents, "trusted\n");
        }
    }

    #[test]
    fn filesystem_constants_match_installed_sdk() {
        let directory = std::env::temp_dir().join(format!(
            "pam-fs-constants-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let source = directory.join("constants.c");
        let binary = directory.join("constants");
        fs::write(
            &source,
            "#include <fcntl.h>\n#include <stdio.h>\n#include <sys/acl.h>\nint main(void) { printf(\"%d\\n%d\\n%d\\n\", O_RESOLVE_BENEATH, O_UNIQUE, ACL_TYPE_EXTENDED); }\n",
        )
        .unwrap();
        let output = Command::new("xcrun")
            .args(["clang"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(&binary).output().unwrap();
        assert!(output.status.success());
        let actual = String::from_utf8(output.stdout).unwrap();
        let actual: Vec<c_int> = actual.lines().map(|line| line.parse().unwrap()).collect();
        fs::remove_dir_all(directory).unwrap();
        assert_eq!(actual, vec![O_RESOLVE_BENEATH, O_UNIQUE, ACL_TYPE_EXTENDED]);
    }

    #[test]
    #[ignore = "requires a temporary root-owned fixture beneath /etc/security"]
    fn root_owned_etc_alias_and_policy() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let directory = PathBuf::from(format!(
            "/private/etc/security/pam-ssh-agent-test-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let fixture = RootFixture { root: directory };
        let directory = &fixture.root;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        let policy = directory.join("policy");
        fs::write(&policy, "trusted\n").unwrap();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = PathBuf::from("/etc/security")
            .join(directory.file_name().unwrap())
            .join("policy");
        assert_eq!(read_policy(&alias, 0, 1024).unwrap(), "trusted\n");
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_policy(&alias, 0, 1024).is_err());
    }
}
