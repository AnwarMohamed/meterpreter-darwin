#include <dlfcn.h>

void*	dlopen(const char *filename, int flag) { return 0; }
char*	dlerror(void) { return 0; }
void*	dlsym(void *handle, const char *symbol) { return 0; }
int 	dladdr(const void *addr, Dl_info *info) { return 0; }
int 	dlclose(void *handle) { return 0; }
void*	dlopenbuf(const char *filename, void *buf, unsigned int len) { return 0; }

#if defined(__i386__) || defined(__sh__)
int dl_iterate_phdr(int (*cb)(void *info, void *size, void *data),
                    void *data) { return 0; }
#endif
