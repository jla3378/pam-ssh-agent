# Documenting the process around making a new release

## Ubuntu ppa builds
At some point I want to automate this, but for now it is a little manual

1. Make sure that the version in create-deb-dsc.sh matches the new version
2. Create a new entry in debian/changelog to bring the new version
3. Run `create-deb-dsc.sh`
4. Attempt to build the resulting `../*.dsc` with something like `sbuild -d noble pam-ssh-agent_0.9.6-1~noble.dsc`
5. upload with `dput ppa:nresare/ppa .dsc` when everything looks good

## RPM builds

1. Release a new version to crates.io
2. Update the version in the [srpm Makefile](https://github.com/nresare/rpm-packaging/blob/main/pam-ssh-agent/Makefile#L2)
3. Run `make srpm outdir=/tmp/out`, have it fail and use the downloaded artifact to update the crate.sha256 file
4. Build the RPM with `mock --addrepo=https://download.copr.fedorainfracloud.org/results/noa/rust/fedora-44-aarch64 /tmp/out/*.src.rpm`
5. If it builds okay, commit the changes to the rpm-pacakging repo, navigate to the previous build in the [COPR ui](https://copr.fedorainfracloud.org/coprs/noa/rust/builds/)
6. Click the "Resubmit" button and hope that it builds correctly

