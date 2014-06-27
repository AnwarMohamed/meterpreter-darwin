#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <err.h>

#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <pthread.h>
#include <sys/param.h>

#define BUNDLE_MAIN "run"

extern boolean_t exc_server(mach_msg_header_t *request,
                            mach_msg_header_t *reply);

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t code_count;
    mach_exception_data_t code;
    char pad[512];
} exc_msg_t;

kern_return_t
remote_copyout(task_t task, void* src, vm_address_t dest, size_t n);

kern_return_t
remote_copyin(task_t task, vm_address_t src, void* dest, size_t n);

extern vm_address_t
remote_malloc(task_t task, size_t size);
    
extern kern_return_t
remote_free(task_t task, vm_address_t addr);

kern_return_t
remote_copyout(mach_port_t task, void* src, vm_address_t dest, size_t n)
{
    kern_return_t kr = KERN_SUCCESS;
    void* buf;
    
    buf = malloc((n + PAGE_SIZE) & ~PAGE_SIZE);
    memcpy(buf, src, n);
    
    if ((kr = vm_write(task, dest, (vm_offset_t)buf, n))) {
        return kr;
    }

    free(buf);

    return kr;
}

kern_return_t
remote_copyin(mach_port_t task, vm_address_t src, void* dest, size_t n)
{
    kern_return_t kr = KERN_SUCCESS;
    vm_size_t size = n;
    
    if ((kr = vm_read_overwrite(task, src, n, (vm_offset_t)dest, &size))) {
        return kr;
    }

    return kr;
}

vm_address_t
remote_malloc(mach_port_t task, size_t size)
{
    kern_return_t kr = KERN_SUCCESS;
    vm_address_t addr;
    
    if ((kr = vm_allocate(task, &addr, size + sizeof(size), TRUE)))
        return (vm_address_t)NULL;

    if (remote_copyout(task, &size, addr, sizeof(size))) {
        vm_deallocate(task, addr, size);
        return (vm_address_t)NULL;
    }

    return addr + sizeof(size);
}


kern_return_t
remote_free(mach_port_t task, vm_address_t addr)
{
    kern_return_t kr = KERN_SUCCESS;
    size_t size;
    
    if ((kr = remote_copyin(task, addr - sizeof(size), &size, sizeof(size)))) {
        return kr;
    }

    kr = vm_deallocate(task, addr - sizeof(size), size);
    return kr;
}

typedef enum {
    UNINIT,       // Remote thread not yet initialized (error returned)
    CREATED,      // Thread and remote stack created and allocated
    RUNNING,      // Thread is running
    SUSPENDED,    // Thread suspended, but still allocated
    TERMINATED    // Thread terminated and remote stack deallocated
} remote_thread_state_t;

typedef struct {
    remote_thread_state_t state;
    task_t                task;
    thread_t              thread;
    vm_address_t          stack;
    size_t                stack_size;
} remote_thread_t;

#define MAGIC_RETURN 0xfffffba0
#define STACK_SIZE   (512*1024)
#define PTHREAD_SIZE (4096)    // Size to reserve for pthread_t struct

kern_return_t
create_remote_thread(mach_port_t task, remote_thread_t* rt, 
             vm_address_t start_address, int argc, ...);

kern_return_t
join_remote_thread(remote_thread_t* remote_thread, void** return_value);

kern_return_t catch_exception_raise_state_identity(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    exception_data_t code,
    mach_msg_type_number_t code_count,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t *new_state_count)
{
    switch (*flavor) {
#if defined(__i386__)
    case x86_THREAD_STATE32:

    if (((x86_thread_state32_t*)old_state)->eip == MAGIC_RETURN) {
        thread_suspend(thread);
            
        /*
         * Signal that exception was handled
         */
        return MIG_NO_REPLY;
    }
    
    break;
#endif
    }

    return KERN_INVALID_ARGUMENT;
}

kern_return_t
join_remote_thread(remote_thread_t* remote_thread, void** return_value)
{
    kern_return_t kr;
    mach_port_t exception_port;
    thread_basic_info_data_t thread_basic_info;
    mach_msg_type_number_t thread_basic_info_count = THREAD_BASIC_INFO_COUNT;

    if ((kr = mach_port_allocate(mach_task_self(),
                                 MACH_PORT_RIGHT_RECEIVE,
                                 &exception_port))) {
        errx(EXIT_FAILURE, "mach_port_allocate: %s", mach_error_string(kr));
    }

    if ((kr = mach_port_insert_right(mach_task_self(),
                                     exception_port, exception_port,
                                     MACH_MSG_TYPE_MAKE_SEND))) {
        errx(EXIT_FAILURE, "mach_port_insert_right: %s",
             mach_error_string(kr));
    }

#if defined(__i386__)
    if ((kr = thread_set_exception_ports(remote_thread->thread,
                                         EXC_MASK_BAD_ACCESS,
                                         exception_port,
                                         EXCEPTION_STATE_IDENTITY,
                                         x86_THREAD_STATE32))) {
        errx(EXIT_FAILURE, "thread_set_exception_ports: %s",
             mach_error_string(kr));
    }
#endif
    
    if ((kr = thread_resume(remote_thread->thread))) {
        errx(EXIT_FAILURE, "thread_resume: %s", mach_error_string(kr));
    }

    remote_thread->state = RUNNING;
    
    while (1) {
        if ((kr = mach_msg_server_once(exc_server, sizeof(exc_msg_t),
                                       exception_port,
                                       MACH_MSG_TIMEOUT_NONE))) {
            errx(EXIT_FAILURE, "mach_msg_server: %s", mach_error_string(kr));
        }

        if ((kr = thread_info(remote_thread->thread, THREAD_BASIC_INFO,
                              (thread_info_t)&thread_basic_info,
                              &thread_basic_info_count))) {
            errx(EXIT_FAILURE, "thread_info: %s", mach_error_string(kr));
        }
        
        if (thread_basic_info.suspend_count > 0) {
            remote_thread->state = SUSPENDED;
            
#if defined(__i386__)
        x86_thread_state32_t remote_thread_state;
            mach_msg_type_number_t thread_state_count =
        x86_THREAD_STATE32_COUNT;

            if ((kr = thread_get_state(remote_thread->thread,
                                       x86_THREAD_STATE32,
                                       (thread_state_t)&remote_thread_state,
                                       &thread_state_count))) {
                errx(EXIT_FAILURE, "thread_get_state: %s",
                     mach_error_string(kr));
            }

            *return_value = (void*)remote_thread_state.eax;
#endif
            if ((kr = thread_terminate(remote_thread->thread))) {
                errx(EXIT_FAILURE, "thread_terminate: %s",
                     mach_error_string(kr));
            }

            if ((kr = vm_deallocate(remote_thread->task,
                                    remote_thread->stack,
                                    remote_thread->stack_size))) {
                errx(EXIT_FAILURE, "vm_deallocate: %s",
                     mach_error_string(kr));
            }
            
            remote_thread->state = TERMINATED;

            break;
        }
    }

    return kr;
}

#if defined(__i386__)
#define MACH_THREAD_TRAMPOLINE_SIZE (16)
/*asm */void mach_thread_trampoline(void)
{
    asm("pop  %eax\n"
        "call *(%eax)\n"
        "add  %esp, 4\n"
        "pop  %eax\n"
        "call *(%eax)\n"
        "add  %esp, 4\n"
        "pop  %eax\n"
        "jmp  *(%eax)\n");
}

#define PTHREAD_TRAMPOLINE_SIZE (4)
/*asm */void pthread_trampoline(void)
{
    asm("nop\n"
        "nop\n"
        "nop\n"
        "nop\n");
}
#endif

kern_return_t
create_remote_thread(mach_port_t task, remote_thread_t* rt, 
             vm_address_t start_address, int argc, ...)
{
    va_list ap;
    int i;
    kern_return_t kr;
    thread_t remote_thread;
    vm_address_t remote_stack, pthread,
    mach_thread_trampoline_code, pthread_trampoline_code;
    size_t stack_size = STACK_SIZE;
    unsigned long* stack, *sp;
    static void (*pthread_set_self)(pthread_t) = NULL;
    static void (*cthread_set_self)(void*) = NULL;

    rt->state = UNINIT;
    rt->task = rt->thread = 0;
    rt->stack = rt->stack_size = 0;

    if (argc > 8) {
        return KERN_FAILURE;
    }


    if (pthread_set_self == NULL) {
    pthread_set_self = (void (*)(pthread_t))
        dlsym(RTLD_DEFAULT, "__pthread_set_self");
    }

    if (cthread_set_self == NULL) {
    cthread_set_self = (void (*)(void*))
        dlsym(RTLD_DEFAULT, "cthread_set_self");
    }

    if ((kr = vm_allocate(task, &remote_stack, stack_size, TRUE)))
        return kr;
    
    stack = malloc(stack_size);
    sp = (unsigned long*)((char*)stack + stack_size);

    sp = (unsigned long*)
    ((char*)sp - PTHREAD_SIZE);
    pthread = remote_stack + (vm_address_t)sp - (vm_address_t)stack;
    
    sp = (unsigned long*)((char*)sp - MACH_THREAD_TRAMPOLINE_SIZE);
    memcpy(sp, &mach_thread_trampoline, MACH_THREAD_TRAMPOLINE_SIZE);
    mach_thread_trampoline_code =
    remote_stack + (vm_address_t)sp - (vm_address_t)stack;

    sp = (unsigned long*)((char*)sp - PTHREAD_TRAMPOLINE_SIZE);
    memcpy(sp, &pthread_trampoline, PTHREAD_TRAMPOLINE_SIZE);
    pthread_trampoline_code =
    remote_stack + (vm_address_t)sp - (vm_address_t)stack;
    
    if ((kr = thread_create(task, &remote_thread))) {
        errx(EXIT_FAILURE, "thread_create: %s", mach_error_string(kr));
    }

#if defined(__i386__)
    {
    x86_thread_state32_t remote_thread_state;
        vm_address_t remote_sp;
        unsigned long* args;  

        sp -= argc;
        sp -= ((unsigned int)sp % 16) / sizeof(*sp);
        
        args = sp;
        
        va_start(ap, argc);
        for (i = 0; i < argc; i++) {
            unsigned long arg = va_arg(ap, unsigned long);
            *(args + i) = arg;
        }
        va_end(ap);
        
    *(--sp) = MAGIC_RETURN;
        *(--sp) = (unsigned long)start_address;
    
        *(--sp) = pthread;
        *(--sp) = (unsigned long)cthread_set_self;
        *(--sp) = pthread;
        *(--sp) = (unsigned long)pthread_set_self;

        remote_sp = remote_stack + (vm_address_t)sp - (vm_address_t)stack;
        
        if ((kr = vm_write(task, remote_stack,
                           (pointer_t)stack, stack_size))) {
            errx(EXIT_FAILURE, "vm_write: %s", mach_error_string(kr));
        }
        
    bzero(&remote_thread_state, sizeof(remote_thread_state));
    
    remote_thread_state.eip = mach_thread_trampoline_code;
    remote_thread_state.esp = remote_sp;
        
    if ((kr = thread_set_state(remote_thread, x86_THREAD_STATE32,
                                   (thread_state_t)&remote_thread_state,
                                   x86_THREAD_STATE32_COUNT))) {
        errx(EXIT_FAILURE, "thread_set_state: %s", mach_error_string(kr));
    }
    }
#endif

    rt->state = CREATED;
    rt->task = task;
    rt->thread = remote_thread;
    rt->stack = remote_stack;
    rt->stack_size = stack_size;
    
    return kr;
}

kern_return_t
remote_getpid(task_t task, pid_t* pid)
{
    kern_return_t kr;
    remote_thread_t thread;
    
    if ((kr = create_remote_thread(task, &thread,
                                   (vm_address_t)&getpid, 0))) {
        warnx("create_remote_thread() failed: %s", mach_error_string(kr));
        return kr;
    }

    if ((kr = join_remote_thread(&thread, (void**)pid))) {
        warnx("join_remote_thread() failed: %s", mach_error_string(kr));
        return kr;
    }

    return kr;
}

kern_return_t
inject_bundle(task_t task, const char* bundle_path, void** return_value)
{
    kern_return_t kr;
    char path[PATH_MAX];
    vm_address_t path_rptr, sub_rptr;
    remote_thread_t thread;
    void* dl_handle = 0, *sub_addr = 0;

    if (!realpath(bundle_path, path)) {
        warn("realpath");
        return KERN_FAILURE;
    }
    
    /*
     * dl_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL)
     */
    path_rptr = remote_malloc(task, sizeof(path));
    remote_copyout(task, path, path_rptr, sizeof(path));

    if ((kr = create_remote_thread(task, &thread,
                                   (vm_address_t)&dlopen, 2,
                                   path_rptr, RTLD_NOW | RTLD_LOCAL))) {
    warnx("create_remote_thread dlopen() failed: %s",
              mach_error_string(kr));
        return kr;
    }

    if ((kr = join_remote_thread(&thread, &dl_handle))) {
    warnx("join_remote_thread dlopen() failed: %s",
              mach_error_string(kr));
        return kr;
    }

    remote_free(task, path_rptr);

    if (dl_handle == NULL) {
        warnx("dlopen() failed");
        return KERN_FAILURE;
    }
    
    /*
     * sub_addr = dlsym(dl_handle, "run")
     */
    sub_rptr = remote_malloc(task, strlen(BUNDLE_MAIN) + 1);
    remote_copyout(task, BUNDLE_MAIN, sub_rptr, strlen(BUNDLE_MAIN) + 1);

    if ((kr = create_remote_thread(task, &thread,
                                   (vm_address_t)&dlsym, 2,
                                   dl_handle, sub_rptr))) {
        warnx("create_remote_thread dlsym() failed: %s",
              mach_error_string(kr));
        return kr;
    }

    if ((kr = join_remote_thread(&thread, &sub_addr))) {
    warnx("join_remote_thread dlsym() failed: %s",
              mach_error_string(kr));
        return kr;
    }

    remote_free(task, sub_rptr);

    if (sub_addr) {
        /*
         * return_value = run()
         */
        if ((kr = create_remote_thread(task, &thread,
                                       (vm_address_t)sub_addr, 0))) {
            warnx("create_remote_thread run() failed: %s",
                   mach_error_string(kr));
            return kr;
        }
        
        if ((kr = join_remote_thread(&thread, return_value))) {
            warnx("join_remote_thread run() failed: %s",
                  mach_error_string(kr));
            return kr;
        }
        
        return (int)return_value;
    }

    return kr;
}


int main(int argc, char* argv[])
{
    pid_t pid;
    kern_return_t kr;
    task_t task;
    void* return_value;
    
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path to bundle> [<pid>]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (argc == 3) {
        pid = atoi(argv[2]);
        if ((kr = task_for_pid(mach_task_self(), pid, &task))) {
            errx(EXIT_FAILURE, "task_for_pid: %s", mach_error_string(kr));
        }
    }
    else {
        task = mach_task_self();
    }
    
    inject_bundle(task, argv[1], &return_value);
    return (int)return_value;
}
