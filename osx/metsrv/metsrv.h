#ifndef _METERPRETER_SERVER_METSRV_H
#define _METERPRETER_SERVER_METSRV_H

/*
 * Version number
 *                               v------- major major
 *                                 v----- major minor
 *                                   v--- minor major
 *                                     v- minor minor
 */
#define METSRV_VERSION_NUMBER 0x00000500

#define METERPRETER_EXPORTS
#include "../common/common.h"

#include "remote_dispatch.h"
#include "libloader.h"

DWORD server_setup(SOCKET fd);
typedef DWORD (*PSRVINIT)(Remote *remote);
typedef DWORD (*PSRVDEINIT)(Remote *remote);

typedef struct _EXTENSION
{
	HMODULE library;
	PSRVINIT init;
	PSRVDEINIT deinit;
} EXTENSION;

#endif
