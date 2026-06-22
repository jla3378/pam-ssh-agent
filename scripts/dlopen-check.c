/* Load-check harness for the shippable PAM module.
 *
 * dlopen()s the dylib passed as argv[1] and confirms both C entry points resolve, the
 * same way macOS's PAM host (sudo/su) loads it. Build for arm64e to match the shipped
 * artifact: `cc -arch arm64e -o loadcheck dlopen-check.c`. Used by `make verify-load`.
 *
 * Note: this must run on the target macOS (it is a load test, not a static inspection),
 * and the host must permit running a third-party arm64e executable.
 */
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path-to-dylib>\n", argv[0]);
        return 2;
    }
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen FAILED: %s\n", dlerror());
        return 1;
    }
    void *auth = dlsym(h, "pam_sm_authenticate");
    void *setcred = dlsym(h, "pam_sm_setcred");
    if (!auth || !setcred) {
        fprintf(stderr, "missing entry point(s): pam_sm_authenticate=%p pam_sm_setcred=%p\n",
                auth, setcred);
        return 1;
    }
    printf("dlopen OK: pam_sm_authenticate + pam_sm_setcred resolved\n");
    return 0;
}
