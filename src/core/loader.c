#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <library.so>\n", argv[0]);
    return 1;
  }

  void *handle = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 1;
  }

  printf("Library loaded successfully at %p\n", handle);
  return 0;
}
