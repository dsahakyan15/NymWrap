// CI fixture only: install a fresh memory-only key on the new test filesystem.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fscrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int result = 1, filesystem = -1, directory = -1, locked = 0;
    const size_t length = sizeof(struct fscrypt_add_key_arg) + 64;
    struct fscrypt_add_key_arg *key = calloc(1, length);
    if (argc != 3 || !key) goto cleanup;
    if (mlock(key, length) != 0) goto cleanup;
    locked = 1;
    filesystem = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    directory = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (filesystem < 0 || directory < 0) goto cleanup;
    for (size_t count = 0; count < 64;) {
        ssize_t size = getrandom(key->raw + count, 64 - count, 0);
        if (size < 0 && errno == EINTR) continue;
        if (size <= 0) goto cleanup;
        count += (size_t)size;
    }
    key->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    key->raw_size = 64;
    if (ioctl(filesystem, FS_IOC_ADD_ENCRYPTION_KEY, key) != 0) goto cleanup;
    struct fscrypt_policy_v2 policy = {
        .version = FSCRYPT_POLICY_V2,
        .contents_encryption_mode = FSCRYPT_MODE_AES_256_XTS,
        .filenames_encryption_mode = FSCRYPT_MODE_AES_256_CTS,
        .flags = FSCRYPT_POLICY_FLAGS_PAD_32,
    };
    memcpy(policy.master_key_identifier, key->key_spec.u.identifier,
           sizeof(policy.master_key_identifier));
    if (ioctl(directory, FS_IOC_SET_ENCRYPTION_POLICY, &policy) != 0) goto cleanup;
    result = 0;
cleanup:
    if (key) {
        explicit_bzero(key, length);
        if (locked) munlock(key, length);
        free(key);
    }
    if (directory >= 0) close(directory);
    if (filesystem >= 0) close(filesystem);
    if (result) fputs("fscrypt_fixture_setup_failed\n", stderr);
    return result;
}
