#include "common.h"
#include <pthread.h>
#include <sys/syscall.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

int futex_wait(volatile void *ftx, int val, const struct timespec *timeout)
{
//    return futex((int*)ftx, FUTEX_WAIT, val, timeout, NULL, 0);
}

int futex_wake(volatile void *ftx, int count)
{
//    return futex((int*)ftx, FUTEX_WAKE, count, NULL, NULL, 0);
}

#include <time.h>
#include <signal.h>

// thread.c contains wrappers for the primitives of locks, events and threads for use in 
// the multithreaded meterpreter. This is the win32/win64 implementation.

/*****************************************************************************************/

/*
 * Create a new lock. We choose Mutex's over CriticalSections as their appears to be an issue
 * when using CriticalSections with OpenSSL on some Windows systems. Mutex's are not as optimal
 * as CriticalSections but they appear to resolve the OpenSSL deadlock issue.
 */
LOCK * lock_create( VOID )
{
	LOCK * lock = (LOCK *)malloc( sizeof( LOCK ) );
	if( lock != NULL )
	{
		memset( lock, 0, sizeof( LOCK ) );
		lock->handle = (pthread_mutex_t*)malloc( sizeof(pthread_mutex_t) );
		pthread_mutex_init(lock->handle, NULL);
	}
	return lock;
}

/*
 * Destroy a lock that is no longer required.
 */
VOID lock_destroy( LOCK * lock )
{
	if( lock != NULL  )
	{
		lock_release( lock );
		pthread_mutex_destroy(lock->handle);

		free( lock );
	}
}

/*
 * Acquire a lock and block untill it is acquired.
 */
VOID lock_acquire( LOCK * lock )
{
	if( lock != NULL  ) {
		pthread_mutex_lock(lock->handle);
	}
}

/*
 * Release a lock previously held.
 */
VOID lock_release( LOCK * lock )
{
	if( lock != NULL  ) {
		pthread_mutex_unlock(lock->handle);
	}
}

/*****************************************************************************************/

/*
 * Create a new event which can be signaled/polled/and blocked on.
 */
EVENT * event_create( VOID )
{
	EVENT * event = NULL;

	event = (EVENT *)malloc( sizeof( EVENT ) );
	if( event == NULL )
		return NULL;

	memset( event, 0, sizeof( EVENT ) );
	return event;
}

/*
 * Destroy an event.
 */
BOOL event_destroy( EVENT * event )
{
	if( event == NULL )
		return FALSE;

	free( event );

	return TRUE;
}

/*
 * Signal an event.
 */
BOOL event_signal( EVENT * event )
{
	if( event == NULL )
		return FALSE;

	event->handle = (HANDLE)1;
	futex_wake(&(event->handle), 1);

	return TRUE;
}

/*
 * Poll an event to see if it has been signaled. Set timeout to -1 to block indefinatly.
 * If timeout is 0 this function does not block but returns immediately.
 */
BOOL event_poll( EVENT * event, DWORD timeout )
{
	BOOL result = FALSE;

	// DWORD WINAPI WaitForSingleObject(
	// __in  HANDLE hHandle,
	// __in  DWORD dwMilliseconds
	// );
	// http://msdn.microsoft.com/en-us/library/ms687032(VS.85).aspx

	if( event == NULL )
		return FALSE;

	if(timeout) {
		struct timespec ts;

		// XXX, need to verify for -1. below modified from bionic/pthread.c
		// and maybe loop if needed ;\

		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout%1000)*1000000;
		if (ts.tv_nsec >= 1000000000) {
			ts.tv_sec++;
			ts.tv_nsec -= 1000000000;
		}

		// atomically checks if event->handle is 0, if so, 
		// it sleeps for timeout. if event->handle is 1, it 
		// returns straight away.

		futex_wait(&(event->handle), 0, &ts);
	}

	// We should behave like an auto-reset event
	result = event->handle ? TRUE : FALSE;
	if( result )
		event->handle = (HANDLE)0;

	return result;
}

/*****************************************************************************************/

/*
 * Opens and create a THREAD item for the current/calling thread.
 */
THREAD * thread_open( VOID )
{
	THREAD * thread        = NULL;
	thread = (THREAD *)malloc( sizeof( THREAD ) );

	if( thread != NULL )
	{
		memset( thread, 0, sizeof(THREAD) );

 		pthread_threadid_np(NULL, &thread->id);
		thread->sigterm = event_create();
		thread->pid	= pthread_self();
	}
	return thread;
}

struct thread_conditional {
	pthread_mutex_t suspend_mutex;
	pthread_cond_t suspend_cond;
	int engine_running;
	THREADFUNK (*funk)(void *arg);
	THREAD *thread;
};

void __thread_cancelled(int signo)
{
	signal(SIGTERM, SIG_DFL);
	pthread_exit(NULL);
}

/*
 * This is the entry point for threads created with thread_create. 
 * 
 * To implement suspended threads, we need to do some messing around with
 * mutexes and conditional broadcasts ;\
 */

void *__paused_thread(void *req)
{
	LPVOID (*funk)(void *arg);
	THREAD *thread;

	struct thread_conditional *tc = (struct thread_conditional *)(req);
	pthread_threadid_np(NULL, &tc->thread->id);

	signal(SIGTERM, __thread_cancelled);

	pthread_mutex_lock(&tc->suspend_mutex);

	while(tc->engine_running == FALSE) {
		pthread_cond_wait(&tc->suspend_cond, &tc->suspend_mutex);
	}

	pthread_mutex_unlock(&tc->suspend_mutex);

	funk = tc->funk;
	thread = tc->thread;
	free(tc); 

	if(event_poll(thread->sigterm, 0) == TRUE) {
		/*
		 * In some cases, we might want to stop a thread before it does anything :/
		 */
		return NULL;
	}

	return funk(thread);	
}

/*
 * Create a new thread in a suspended state.
 */
THREAD * thread_create( THREADFUNK funk, LPVOID param1, LPVOID param2, LPVOID param3 )
{
	THREAD * thread = NULL;
	
	if( funk == NULL )
		return NULL;

	thread = (THREAD *)malloc( sizeof( THREAD ) );
	if( thread == NULL )
		return NULL;

	memset( thread, 0, sizeof( THREAD ) );

	thread->sigterm = event_create();
	if( thread->sigterm == NULL )
	{
		free( thread );
		return NULL;
	}


	thread->parameter1 = param1;
	thread->parameter2 = param2;
	thread->parameter3 = param3;

	// PKS, this is fucky.
	// we need to use conditionals to implement this. 

	thread->thread_started = FALSE;

	do {
		pthread_t pid;

		struct thread_conditional *tc;
		tc = (struct thread_conditional *) malloc(sizeof(struct thread_conditional));

		if( tc == NULL ) {
			event_destroy(thread->sigterm);
			free(thread);
			return NULL;
		}
		
		memset( tc, 0, sizeof(struct thread_conditional));

		pthread_mutex_init(&tc->suspend_mutex, NULL);
		pthread_cond_init(&tc->suspend_cond, NULL);

		tc->funk = funk;		
		tc->thread = thread;

		thread->suspend_thread_data = (void *)(tc);

		if(pthread_create(&(thread->pid), NULL, __paused_thread, tc) == -1) {
			free(tc);
			event_destroy(thread->sigterm);
			free(thread);
			return NULL;
		}
		// __paused_thread free's the allocated memory.

	} while(0);
	return thread;
}

/*
 * Run a thread.
 */
BOOL thread_run( THREAD * thread )
{
	if( thread == NULL )
		return FALSE;

	struct thread_conditional *tc;
	tc = (struct thread_conditional *)thread->suspend_thread_data;
	pthread_mutex_lock(&tc->suspend_mutex);
	tc->engine_running = TRUE;
	pthread_mutex_unlock(&tc->suspend_mutex);
	pthread_cond_signal(&tc->suspend_cond);

	thread->thread_started = TRUE;
	return TRUE;
}

/*
 * Signals the thread to terminate. It is the responsibility of the thread to wait for and process this signal.
 * Should be used to signal the thread to terminate.
 */
BOOL thread_sigterm( THREAD * thread )
{
	BOOL ret;

	if( thread == NULL )
		return FALSE;

	ret = event_signal( thread->sigterm );

	/* 
	 * If we sig term a thread before it's started execution, we will leak memory / not be 
	 * able to join on the thread, etc.
	 * 
	 * Therefore, we need to start the thread executing before calling thread_join
	 */
	if(thread->thread_started != TRUE) {
		thread_run(thread);
	}

	return ret;
}

/*
 * Terminate a thread. Use with caution! better to signal your thread to terminate and wait for it to do so.
 */
BOOL thread_kill( THREAD * thread )
{
	if( thread == NULL )
		return FALSE;

	// bionic/libc/bionic/CAVEATS
	// - pthread cancellation is *not* supported. this seemingly simple "feature" is the source
	// of much bloat and complexity in a C library. Besides, you'd better write correct
	// multi-threaded code instead of relying on this stuff.

	// pthread_kill says: Note  that  pthread_kill()  only  causes  the
	// signal to be handled in the context of the given thread; the signal
	// action (termination or stopping) affects the process as a whole.

	// We send our thread a SIGTERM, and a signal handler calls pthread_exit().

	pthread_kill(thread->id, SIGTERM);
	return FALSE;
}


/*
 * Blocks untill the thread has terminated.
 */
BOOL thread_join( THREAD * thread )
{
	if( thread == NULL )
		return FALSE;

	if(pthread_join(thread->pid, NULL) == 0) 
		return TRUE;

	return FALSE;
}

/*
 * Destroys a previously created thread. Note, this does not terminate the thread. You must signal your
 * thread to terminate and wait for it to do so (via thread_signal/thread_join).
 */
BOOL thread_destroy( THREAD * thread )
{
	if( thread == NULL )
		return FALSE;
	
	event_destroy( thread->sigterm );
	pthread_detach(thread->pid);

	free( thread );

	return TRUE;
}
