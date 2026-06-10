# A macOS PAM module for authenticating using ssh-agent

This project provides a PAM authentication module for **macOS** that determines the identity of a user
based on a signature request and response sent via the ssh-agent protocol to a potentially remote
`ssh-agent`. macOS uses [OpenPAM](https://www.openpam.org/), and this module ships as a thin
**arm64e** Mach-O named `pam_ssh_agent.so`.

One scenario that this module can be used in is to grant escalated privileges using the `sudo` command.
The user proves their identity by signing a challenge using their private key, and the signature is
verified using a public key made available to the `pam-ssh-agent` module. Combined with a setup where the
private part of an authentication keypair is stored in custom hardware such as the macOS Secure Enclave,
a YubiKey, or a TPM chip, this can provide a high level of security as well as convenience. I use the
[Secretive](https://github.com/maxgoedjen/secretive) app on macOS for this purpose, which exposes a
Secure Enclave key over an `ssh-agent` socket.

This project is a re-implementation of the [pam_ssh_agent_auth](https://github.com/jbeverly/pam_ssh_agent_auth)
module but does not share any code with that project. It covers essentially all of the features of the
original implementation, along with some additional features such as authentication using SSH Certificates.

## Project goals

Since this is security sensitive software and a bug could easily result in undue privilege escalation, the
main goal of this project is to be robust and easy to follow for would-be reviewers.

The implementation leans heavily on crates available in the Rust ecosystem that implement the different
parts needed for the overall functionality, most notably the `ssh-key` and `ssh-agent-client-rs` crates
(the PAM FFI bindings live in this crate's own `src/openpam.rs`). All crypto is pure-Rust via `ssh-key`.
Using upstream libraries directly is intended to make it easier to ensure that implementation issues with
security implications get addressed in a timely manner. A secondary benefit is that it is easier to support
the full range of algorithms that OpenSSH supports.

## Building and installing on macOS

The shippable artifact is a **thin arm64e `.dylib`** that is installed under a `.so` name (OpenPAM loads
Mach-O modules that conventionally carry a `.so` name). Because `arm64e-apple-darwin` is a tier-3 Rust
target with no prebuilt `std`, building it requires a nightly toolchain plus `-Zbuild-std`. A `Makefile`
wraps the details:

```sh
make check      # cargo fmt --check, cargo clippy --no-deps, cargo test  (runs on the host arch)
make pam        # build the arm64e dylib (toolchain overridable via PAM_TOOLCHAIN, default nightly)
make install    # make pam, then sudo install to /usr/local/lib/pam/pam_ssh_agent.so
make clean      # cargo clean
```

`make pam` runs the build below, but pins nightly's `rustc` explicitly (via `rustup which`).
That matters when a Homebrew `rust` install is also present: its stable `rustc` can shadow
rustup's in `PATH`, and a bare `rustup run` then feeds `-Z` to stable `rustc`, which rejects it.

```sh
rustup run nightly cargo build -Z build-std=std --release --target arm64e-apple-darwin
# -> target/arm64e-apple-darwin/release/libpam_ssh_agent.dylib  (thin arm64e, ad-hoc signed)
```

Requires Rust 1.88+ (edition 2024) and a nightly toolchain for the arm64e build. The correctness checks in
`make check` run on the host toolchain/architecture, since the crypto and PAM logic is
architecture-independent.

### Installing the module

macOS System Integrity Protection (SIP) makes `/usr/lib/pam` **read-only even for root**, so install the
module under `/usr/local/lib/pam` instead and refer to it by **absolute path** in `/etc/pam.d`. `make install`
does this for you:

```sh
sudo install -d /usr/local/lib/pam
sudo install -m 0755 target/arm64e-apple-darwin/release/libpam_ssh_agent.dylib \
    /usr/local/lib/pam/pam_ssh_agent.so
```

### Wiring it into sudo

`/etc/pam.d/sudo` is Apple-managed (read-only and reset on OS updates) and includes `auth include sudo_local`.
The clean place to add this module is `/etc/pam.d/sudo_local`, which you create by copying
`/etc/pam.d/sudo_local.template`:

```
auth  sufficient  /usr/local/lib/pam/pam_ssh_agent.so  file=/etc/security/authorized_keys
```

`sudo` scrubs the environment, so it will not forward your agent socket unless you tell it to. Add:

```
Defaults env_keep += "SSH_AUTH_SOCK"
```

for example in `/etc/sudoers.d/ssh_agent_env`. Then add a public key that your `ssh-agent` knows about to
`/etc/security/authorized_keys` (that directory already exists on macOS).

> :warning: **Lockout safety.** Misconfiguring sudo's PAM stack can lock you out of privilege escalation,
> and macOS recovery is painful. While testing: keep a root shell open in a separate window, use the
> `sufficient` control so that a module failure falls through to the normal password prompt, and try the
> module against a throwaway service before touching `sudo`.

### Agent and scope notes

* Use an `ssh-agent` that exposes a Secure Enclave key, such as
  [Secretive](https://github.com/maxgoedjen/secretive), and make sure `SSH_AUTH_SOCK` is set in the
  environment that runs `sudo`.
* This module only affects services configured under `/etc/pam.d` (`sudo`, `su`, `login`, `sshd`). Most
  macOS privilege prompts go through Authorization Services rather than PAM, and GUI auth paths
  (`authorizationhost`, `securityagent`, the screen saver) have no agent socket available.

### Viewing logs

The module logs to the syslog `AUTHPRIV` facility, which macOS routes into the unified logging system
(not `/var/log`). Watch it with:

```sh
log stream --predicate 'eventMessage CONTAINS "pam_ssh_agent"'
```

## Using a command to dynamically obtain trusted keys

This plugin can be configured with `authorized_keys_command` which will call an external binary to obtain
trusted keys for authentication. An example of such a program is [sss_ssh_authorizedkeys](https://manpages.debian.org/testing/sssd-common/sss_ssh_authorizedkeys.1.en.html).

Since this module is expected to be invoked in a privileged context, some care has been taken to reduce
the risks involved in invoking external commands with potentially elevated privilege in the following way:

By default, the external command is invoked with the privileges of the calling user. The group id is also
set to the least-privilege `nobody` group, group id `(gid_t)-2` (i.e. `4294967294`) on macOS. It is
recommended that the unprivileged user is specified using the `authorized_keys_command_user`, for example
`nobody`.

## Configuration options

PAM modules can be configured using space separated options after `pam_ssh_agent.so` in the applicable
configuration file in `/etc/pam.d`. pam_ssh_agent currently understands the following options:

* `debug` Increase log output to the AUTHPRIV syslog facility.
* `file=/file/name` Override/modify the file from which authorized public keys are read. If not
  specified, the default is `/etc/security/authorized_keys`. This path is subject to the variable
  expansions mentioned below.
* `ca_keys_file=/ca/keys/filename`. Read trusted certificate authorities from a file that doesn't
  include any key options prefixes. See below for further information about certificate
  authentication and the subtle format difference in file format compared to `file`.
* `authorized_keys_command=/path/executable` Specify a command that should be run to dynamically
  retrieve/prepare a list of authorized public keys. When invoked, the username of the 
  requesting user will be passed as a single argument. The command should print keys to STDOUT in 
  authorized_keys format.
* `authorized_keys_command_user=NON_PRIVILEGED_USER` If set, specifies the user that `authorized_keys_command`
  will be executed as. If not specified, the command will be run as the requesting user.
* `default_ssh_auth_sock=/path/to/ssh_agent_unix_socket` the path to use if the `SSH_AUTH_SOCK` environment variable
  is not set.

## SSH Certificates

Besides authenticating using signatures corresponding to ssh public keys, SSH certificates can also
be used. A certificate is considered valid if the following conditions are met:

* The current time is within the validity period
* The certificate signature is valid and was made by a trusted certificate key
* The username provided to the plugin by the PAM_USER item is in the certificate's list of principals
* The certificate type is specified to "User"

> [!NOTE]
> Please note that as of now, certificates need to have an expiry time. Once the fix to
> [this bug](https://github.com/RustCrypto/SSH/issues/174) has made it into a stable release
> we can relax this requirement but for now just add an expiry time very far into the future if you 
> want to emulate a certificate without an expiry time.

Just like with OpenSSH there are two ways to specify a certificate authority key. In the same way as the
authorized_keys format, a certificate authority key can be specified alongside the regular ssh keys by being
prefixed by a list of options that include the `cert-authority` option. In the simplest case, this means
that the key is prefixed with `cert-authority` followed by a space and the key in its usual single line format.

The second way to specify certificate authority keys work in the same way as the OpenSSH option `TrustedUserCAKeys`
where keys without the `cert-authority` option are specified, one per line. To enable this mode of operation,
set the `ca_keys_file` option.

## Variable expansions

> :warning: Using the home directory expansion is unsafe. It allows an attacker with access to an account with sudo
> rights to elevate their privileges with an ssh key of their choosing. If such a setup is desired, configuring
> sudo with the `NOPASSWD` option is a better option as it makes the insecure configuration explicit.

It is possible to use variable expansion in any of the configuration options. In the current age of configuration
management systems, it might make more sense to move the complexity of using the right `authorized_keys` file 
to those systems, but these variable expansions are available to users that might want them. It also makes the 
upgrade path from `pam_ssh_agent_auth` smoother as the previous functionality is retained.

* `~` same as in shells, without specifying a username this expands to the home directory referred to by `PAM_USER`, 
  normally the user attempting to authenticate. If a username is specified, the home directory of that user will be
  used such that `~alice` might expand to `/Users/alice`.
* `%h` same as `~`, the home directory of the user referred to by the PAM item `PAM_USER`.
* `%H` the value returned by `gethostname(3)`, truncated after the first period such that if `gethostname(3)` returns
  `host.example.com` this `%H` will turn into `host`.
* `%f` the value returned by `gethostname(3)`. For the systems I have looked at, this value is not a fully qualified
  domain name but if it was it would be returned. This behaviour, although a bit surprising is consistent with how
  `pam_ssh_agent_auth` works.
* `%u` the username of the user attempting to authenticate.
* `%U` numeric uid of the user attempting to authenticate.

> [!NOTE]
> On macOS the value returned by `gethostname(3)` (used by `%H` and `%f`) changes as the machine moves
> between networks and as Bonjour adjusts the local hostname, so key paths templated with `%H`/`%f` can be
> unstable. Prefer a fixed path or a configuration-management-managed file if you need stability.

## Special behaviour when called by sshd

Another feature inherited from `pam_ssh_agent_auth` is that when calling `pam_get_item(3)` with the `PAM_SERVICE`
argument returns the string `sshd`, special logic is triggered: If the environment variable `SSH_AUTH_INFO_0` is set
and contains a public key and that public key matches any of the configured public keys, this plugin invocation
returns `PAM_SUCCESS`. The environment variable is set by `sshd` to contain the public key that was used by its
pubkey authentication method. This requires `ExposeAuthInfo yes` in `sshd_config`.

This allows for `sshd` to be configured with this module as a `sufficient` authentication mechanism along with
other mechanisms such as for example a time based one-time-password. If the key used in `sshd`'s initial authentication
is in the list of higher security keys that this plugin is configured with, no additional authentication is required. 
However, if the key is not in the list a secondary authentication method can be configured.

## Set up a fallback authentication method

Because a PAM misconfiguration can prevent you from elevating privileges, it is wise to keep a working
fallback while you set this up. Using the `sufficient` control (as in the `sudo_local` example above) means
that if this module fails, PAM falls through to the normal password prompt rather than denying access. Keep
a root shell open while testing so you can revert `/etc/pam.d` changes if anything goes wrong.

## License

Licensed under either of the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or the
[MIT license](http://opensource.org/licenses/MIT) at your option.

## How to contribute

Open a pull request. There is a github action that runs the tests, `cargo fmt`, and `cargo clippy` against
diffs, so it would be nice if you ran `make check` first locally to save a round-trip or two.

### Contribution licensing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
