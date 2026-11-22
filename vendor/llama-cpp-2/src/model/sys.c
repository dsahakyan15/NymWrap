/* NymWrap: bridge a duplicated read handle using the same target CRT as llama.cpp. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>

void * nw_model_file_open(void * source) {
    HANDLE copy = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)source, GetCurrentProcess(),
                         &copy, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        return NULL;
    }
    const int fd = _open_osfhandle((intptr_t)copy, _O_RDONLY | _O_BINARY);
    if (fd == -1) {
        CloseHandle(copy);
        return NULL;
    }
    FILE * stream = _fdopen(fd, "rb");
    if (!stream) {
        _close(fd);
    }
    return stream;
}

void nw_model_file_close(void * stream) {
    fclose((FILE *)stream);
}
