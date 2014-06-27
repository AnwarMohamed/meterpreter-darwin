#include "common.h"
#include <sys/errno.h>

DWORD packet_find_tlv_buf(Packet *packet, PUCHAR payload, DWORD payloadLength, DWORD index,
		TlvType type, Tlv *tlv);

DWORD send_core_console_write( Remote *remote, LPCSTR fmt, ... )
{
	Packet *request = NULL;
	CHAR buf[8192];
	va_list ap;
	DWORD res;

	do
	{
		va_start(ap, fmt);
		_vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
		va_end(ap);

		if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, "core_console_write")))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		if ((res = packet_add_tlv_string(request, TLV_TYPE_STRING, buf)) != NO_ERROR)
			break;

		res = packet_transmit(remote, request, NULL);

	} while (0);

	if (res != ERROR_SUCCESS)
	{
		if (request)
			packet_destroy(request);
	}

	return res;
}

HANDLE core_update_thread_token( Remote *remote, HANDLE token )
{
	HANDLE temp = NULL;
	return(token);
}

VOID core_update_desktop( Remote * remote, DWORD dwSessionID, char * cpStationName, char * cpDesktopName )
{
}

Packet *packet_create( PacketTlvType type, LPCSTR method )
{
	Packet *packet = NULL;
	BOOL success = FALSE;

	do
	{
		if (!(packet = (Packet *)malloc(sizeof(Packet))))
			break;

		memset(packet, 0, sizeof(Packet));

		packet->header.length = htonl(sizeof(TlvHeader));
		packet->header.type   = htonl((DWORD)type);

		packet->payload       = NULL;
		packet->payloadLength = 0;

		if (method)
		{
			if (packet_add_tlv_string(packet, TLV_TYPE_METHOD, method) != ERROR_SUCCESS)
				break;
		}

		success = TRUE;

	} while (0);

	if ((!success) && (packet))
	{
		packet_destroy(packet);

		packet = NULL;
	}

	return packet;
}

Packet* packet_create_group()
{
	Packet* packet = NULL;
	do
	{
		if (!(packet = (Packet*)malloc(sizeof(Packet))))
		{
			break;
		}

		memset(packet, 0, sizeof(Packet));

		packet->payload = NULL;
		packet->payloadLength = 0;

		return packet;
	} while (0);

	if (packet)
	{
		free(packet);
	}
	return NULL;
}

DWORD packet_add_group(Packet* packet, TlvType type, Packet* groupPacket)
{
	DWORD result = packet_add_tlv_raw(packet, type, groupPacket->payload, groupPacket->payloadLength);
	if (result == ERROR_SUCCESS)
	{
		packet_destroy(groupPacket);
		return ERROR_SUCCESS;
	}

	return result;
}

Packet *packet_create_response( Packet *request )
{
	Packet *response = NULL;
	Tlv method, requestId;
	BOOL success = FALSE;
	PacketTlvType responseType;

	if (packet_get_type(request) == PACKET_TLV_TYPE_PLAIN_REQUEST)
		responseType = PACKET_TLV_TYPE_PLAIN_RESPONSE;
	else
		responseType = PACKET_TLV_TYPE_RESPONSE;

	do
	{
		if (packet_get_tlv_string(request, TLV_TYPE_METHOD, &method) != ERROR_SUCCESS)
			break;

		if (!(response = packet_create(responseType, (PCHAR)method.buffer)))
			break;

		if (packet_get_tlv_string(request, TLV_TYPE_REQUEST_ID, &requestId) != ERROR_SUCCESS)
			break;

		packet_add_tlv_string(response, TLV_TYPE_REQUEST_ID, (PCHAR)requestId.buffer);

		success = TRUE;

	} while (0);

	if (!success)
	{
		if (response)
			packet_destroy(response);

		response = NULL;
	}

	return response;
}

VOID packet_destroy( Packet * packet )
{
	if( packet == NULL )
		return;

	if( packet->payload )
	{
		memset( packet->payload, 0, packet->payloadLength );
		free( packet->payload );
	}

	if( packet->decompressed_buffers )
	{
		while( TRUE )
		{
			DECOMPRESSED_BUFFER * buf = list_pop( packet->decompressed_buffers );
			if( !buf )
				break;

			if( buf->buffer )
			{
				memset( buf->buffer, 0, buf->length );
				free( buf->buffer );
			}
			
			free( buf );
		}

		list_destroy( packet->decompressed_buffers );
	}

	memset( packet, 0, sizeof(Packet) );

	free( packet );
}

DWORD packet_add_tlv_string( Packet *packet, TlvType type, LPCSTR str )
{
	return packet_add_tlv_raw(packet, type, (PUCHAR)str, (DWORD)strlen(str) + 1);
}

DWORD packet_add_tlv_wstring_len(Packet *packet, TlvType type, LPCWSTR str, size_t strLength)
{
	DWORD dwResult;
	LPSTR lpStr = (LPSTR)malloc(strLength + 1);

	if (lpStr)
	{
		wcstombs(lpStr, str, strLength);
		lpStr[strLength] = 0;
		dwResult = packet_add_tlv_raw(packet, type, (PUCHAR)lpStr, (DWORD)strLength + 1);
		free(lpStr);
	}
	else
	{
		dwResult = ERROR_NOT_ENOUGH_MEMORY;
	}

	return dwResult;
}

DWORD packet_add_tlv_wstring(Packet *packet, TlvType type, LPCWSTR str)
{
	return packet_add_tlv_wstring_len(packet, type, str, wcslen(str));
}

DWORD packet_add_tlv_uint( Packet *packet, TlvType type, UINT val )
{
	val = htonl(val);

	return packet_add_tlv_raw(packet, type, (PUCHAR)&val, sizeof(val));
}

DWORD packet_add_tlv_qword( Packet *packet, TlvType type, QWORD val )
{
#ifdef __BIG_ENDIAN__
#else
	DWORD t;
	union
	{
		QWORD q;
		DWORD l[2];
	} x;

	x.q = val;
	t = x.l[0];
	x.l[0] = htonl(x.l[1]);
	x.l[1] = htonl(t);

	val = x.q;
#endif

	return packet_add_tlv_raw( packet, type, (PUCHAR)&val, sizeof(QWORD) );
}

DWORD packet_add_tlv_bool(Packet *packet, TlvType type, BOOL val)
{
	return packet_add_tlv_raw(packet, type, (PUCHAR)&val, 1);
}

DWORD packet_add_tlv_group( Packet *packet, TlvType type, Tlv *entries, DWORD numEntries )
{
    DWORD totalSize = 0, 
        offset = 0,
        index = 0, 
        res = ERROR_SUCCESS;
    PCHAR buffer = NULL;

    for (index = 0; index < numEntries; index++)
        totalSize += entries[index].header.length + sizeof(TlvHeader);

    do
    {
        if (!(buffer = (PCHAR)malloc(totalSize)))
        {
            res = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        for (index = 0; index < numEntries; index++)
        {
            TlvHeader rawHeader;

            rawHeader.length = htonl(entries[index].header.length + sizeof(TlvHeader));
            rawHeader.type   = htonl((DWORD)entries[index].header.type);

            memcpy(buffer + offset, &rawHeader, sizeof(TlvHeader));
            memcpy(buffer + offset + sizeof(TlvHeader), entries[index].buffer, entries[index].header.length);

            offset += entries[index].header.length + sizeof(TlvHeader);
        }

        res = packet_add_tlv_raw(packet, type, buffer, totalSize);

    } while (0);

    if (buffer)
        free(buffer);

    return res;
}


DWORD packet_add_tlvs( Packet *packet, Tlv *entries, DWORD numEntries )
{
    DWORD index;

    for (index = 0; index < numEntries; index++)
        packet_add_tlv_raw(packet, (TlvType)entries[index].header.type, entries[index].buffer, entries[index].header.length);

    return ERROR_SUCCESS;
}

DWORD packet_add_tlv_raw_compressed( Packet *packet, TlvType type, LPVOID buf, DWORD length )
{
    DWORD result            = ERROR_SUCCESS;
    DWORD headerLength      = sizeof( TlvHeader );
    PUCHAR newPayload       = NULL;
    BYTE * compressed_buf   = NULL;
    DWORD realLength        = 0;
    DWORD newPayloadLength  = 0;
    DWORD compressed_length = (DWORD)( 1.01 * ( length + 12 ) + 1 );

    do
    {
        compressed_buf = (BYTE *)malloc( compressed_length );
        if( !compressed_buf )
        {
            result = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        if( compress2( compressed_buf, &compressed_length, buf, length, Z_BEST_COMPRESSION ) != Z_OK )
        {
            result = ERROR_UNSUPPORTED_COMPRESSION;
            break;
        }

        realLength       = compressed_length + headerLength;
        newPayloadLength = packet->payloadLength + realLength;
        
        // Allocate/Reallocate the packet's payload
        if( packet->payload )
            newPayload = (PUCHAR)realloc(packet->payload, newPayloadLength);
        else
            newPayload = (PUCHAR)malloc(newPayloadLength);
    
        if( !newPayload )
        {
            result = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        ((LPDWORD)(newPayload + packet->payloadLength))[0] = htonl(realLength);
        ((LPDWORD)(newPayload + packet->payloadLength))[1] = htonl((DWORD)type);

        memcpy(newPayload + packet->payloadLength + headerLength, compressed_buf, compressed_length );

        packet->header.length = htonl(ntohl(packet->header.length) + realLength);
        packet->payload       = newPayload;
        packet->payloadLength = newPayloadLength;

        result = ERROR_SUCCESS;

    } while( 0 );

    if( compressed_buf )
        free( compressed_buf );

    return result;
}

DWORD packet_add_tlv_raw( Packet *packet, TlvType type, LPVOID buf, DWORD length )
{
    DWORD headerLength     = sizeof(TlvHeader);
    DWORD realLength       = length + headerLength;
    DWORD newPayloadLength = packet->payloadLength + realLength;
    PUCHAR newPayload      = NULL;

    if( ( type & TLV_META_TYPE_COMPRESSED ) == TLV_META_TYPE_COMPRESSED )
        return packet_add_tlv_raw_compressed( packet, type, buf, length );

    if (packet->payload)
        newPayload = (PUCHAR)realloc( packet->payload, newPayloadLength );
    else
        newPayload = (PUCHAR)malloc( newPayloadLength );
    
    if (!newPayload)
        return ERROR_NOT_ENOUGH_MEMORY;

    ((LPDWORD)(newPayload + packet->payloadLength))[0] = htonl(realLength);
    ((LPDWORD)(newPayload + packet->payloadLength))[1] = htonl((DWORD)type);

    memcpy( newPayload + packet->payloadLength + headerLength, buf, length );

    packet->header.length = htonl(ntohl(packet->header.length) + realLength);
    packet->payload       = newPayload;
    packet->payloadLength = newPayloadLength;

    return ERROR_SUCCESS;
}
DWORD packet_is_tlv_null_terminated( Tlv *tlv )
{
    if ((tlv->header.length) && (tlv->buffer[tlv->header.length - 1] != 0))
        return ERROR_NOT_FOUND;

    return ERROR_SUCCESS;
}

PacketTlvType packet_get_type( Packet *packet )
{
    return (PacketTlvType)ntohl( packet->header.type );
}

TlvMetaType packet_get_tlv_meta( Packet *packet, Tlv *tlv )
{
    return TLV_META_TYPE_MASK( tlv->header.type );
}

DWORD packet_get_tlv( Packet *packet, TlvType type, Tlv *tlv )
{
    return packet_enum_tlv( packet, 0, type, tlv );
}

DWORD packet_get_tlv_string( Packet *packet, TlvType type, Tlv *tlv )
{
    DWORD res;

    if ((res = packet_get_tlv( packet, type, tlv )) == ERROR_SUCCESS)
        res = packet_is_tlv_null_terminated( tlv );

    return res;
}

DWORD packet_get_tlv_group_entry( Packet *packet, Tlv *group, TlvType type, Tlv *entry )
{
    return packet_find_tlv_buf( packet, group->buffer, group->header.length, 0, type, entry );
}

DWORD packet_enum_tlv( Packet *packet, DWORD index, TlvType type, Tlv *tlv )
{
    return packet_find_tlv_buf( packet, packet->payload, packet->payloadLength, index, type, tlv );
}

PCHAR packet_get_tlv_value_string( Packet *packet, TlvType type )
{
    Tlv stringTlv;
    PCHAR string = NULL;

    if (packet_get_tlv_string( packet, type, &stringTlv ) == ERROR_SUCCESS)
        string = (PCHAR)stringTlv.buffer;

    return string;
}

UINT packet_get_tlv_value_uint( Packet *packet, TlvType type )
{
    Tlv uintTlv;

    if ((packet_get_tlv( packet, type, &uintTlv ) != ERROR_SUCCESS) || (uintTlv.header.length < sizeof(DWORD)))
        return 0;

    return ntohl(*(LPDWORD)uintTlv.buffer);
}

BYTE * packet_get_tlv_value_raw( Packet * packet, TlvType type )
{
    Tlv tlv;

    if( packet_get_tlv( packet, type, &tlv ) != ERROR_SUCCESS )
        return NULL;

    return tlv.buffer;
}

QWORD packet_get_tlv_value_qword( Packet *packet, TlvType type )
{
    Tlv qwordTlv;

    if( ( packet_get_tlv( packet, type, &qwordTlv ) != ERROR_SUCCESS ) || ( qwordTlv.header.length < sizeof(QWORD) ) )
        return 0;

#ifdef __BIG_ENDIAN__
	return *(QWORD *)qwordTlv.buffer;
#else
	u_int32_t t;
	union
	{
		u_int64_t q;
		u_int32_t l[2];
	} x;

	x.q = *(QWORD *)qwordTlv.buffer;
	t = x.l[0];
	x.l[0] = ntohl(x.l[1]);
	x.l[1] = ntohl(t);

	return x.q;
#endif
}

BOOL packet_get_tlv_value_bool( Packet *packet, TlvType type )
{
    Tlv boolTlv;
    BOOL val = FALSE;

    if (packet_get_tlv( packet, type, &boolTlv ) == ERROR_SUCCESS)
        val = (BOOL)(*(PCHAR)boolTlv.buffer);

    return val;
}

DWORD packet_add_exception( Packet *packet, DWORD code, PCHAR fmt, ... )
{
    DWORD codeNbo = htonl(code);
    char buf[8192];
    Tlv entries[2];
    va_list ap;

    buf[sizeof(buf) - 1] = 0;

    va_start(ap, fmt);
    _vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);

    entries[0].header.type   = TLV_TYPE_EXCEPTION_CODE;
    entries[0].header.length = 4;
    entries[0].buffer        = (PUCHAR)&codeNbo;
    entries[1].header.type   = TLV_TYPE_EXCEPTION_STRING;
    entries[1].header.length = (DWORD)strlen(buf) + 1;
    entries[1].buffer        = (PUCHAR)buf;

    return packet_add_tlv_group( packet, TLV_TYPE_EXCEPTION, entries, 2 );
}



DWORD packet_get_result( Packet *packet )
{
    return packet_get_tlv_value_uint( packet, TLV_TYPE_RESULT );
}


PacketCompletionRoutineEntry *packetCompletionRoutineList = NULL;

DWORD packet_find_tlv_buf( Packet *packet, PUCHAR payload, DWORD payloadLength, DWORD index, TlvType type, Tlv *tlv )
{
    DWORD currentIndex = 0;
    DWORD offset = 0, length = 0;
    BOOL found = FALSE;
    PUCHAR current;

    memset(tlv, 0, sizeof(Tlv));

    do
    {
        for( current = payload, length = 0 ; !found && current ; offset += length, current += length )
        {
            TlvHeader *header    = (TlvHeader *)current;
            TlvType current_type = TLV_TYPE_ANY; // effectively '0'

            if ((current + sizeof(TlvHeader) > payload + payloadLength) || (current < payload))
                break;

            length = ntohl(header->length);

            current_type = (TlvType)ntohl( header->type );

            if( ( current_type & TLV_META_TYPE_COMPRESSED ) == TLV_META_TYPE_COMPRESSED )
                current_type = (TlvType)(current_type ^ TLV_META_TYPE_COMPRESSED);
            
            if( (current_type != type) && (type != TLV_TYPE_ANY) )
                continue;
        
            if (currentIndex != index)
            {
                currentIndex++;
                continue;
            }

            if ((current + length > payload + payloadLength) || (current < payload))
                break;

            tlv->header.type   = ntohl(header->type);
            tlv->header.length = ntohl(header->length) - sizeof(TlvHeader);
            tlv->buffer        = payload + offset + sizeof(TlvHeader);

            if( ( tlv->header.type & TLV_META_TYPE_COMPRESSED ) == TLV_META_TYPE_COMPRESSED )
            {
                DECOMPRESSED_BUFFER * decompressed_buf = NULL;

                do
                {
                    decompressed_buf = (DECOMPRESSED_BUFFER *)malloc( sizeof(DECOMPRESSED_BUFFER) );
                    if( !decompressed_buf )
                        break;
                    
                    decompressed_buf->length = ntohl( *(DWORD *)tlv->buffer );
                    if( !decompressed_buf->length )
                        break;

                    decompressed_buf->buffer = (BYTE *)malloc( decompressed_buf->length );
                    if( !decompressed_buf->buffer )
                        break;

                    tlv->header.length -= sizeof( DWORD );
                    tlv->buffer += sizeof( DWORD );
                    
                    if( uncompress( (Bytef*)decompressed_buf->buffer, &decompressed_buf->length, tlv->buffer, tlv->header.length ) != Z_OK )
                        break;
                    
                    tlv->header.type   = tlv->header.type ^ TLV_META_TYPE_COMPRESSED;
                    tlv->header.length = decompressed_buf->length;
                    tlv->buffer        = (PUCHAR)decompressed_buf->buffer;

                    if( !packet->decompressed_buffers )
                        packet->decompressed_buffers = list_create();
                    
                    if( !packet->decompressed_buffers )
                        break;

                    list_push( packet->decompressed_buffers, decompressed_buf );

                    found = TRUE;

                } while( 0 );

                if( !found && decompressed_buf )
                {
                    if( decompressed_buf->buffer )
                        free( decompressed_buf->buffer );
                    free( decompressed_buf );
                }
            }
            else
            {
                found = TRUE;
            }
        }

    } while (0);

    return (found) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}



DWORD packet_add_completion_handler( LPCSTR requestId, PacketRequestCompletion *completion )
{
    PacketCompletionRoutineEntry *entry;
    DWORD res = ERROR_SUCCESS;

    do
    {
        if (!(entry = (PacketCompletionRoutineEntry *)malloc( sizeof(PacketCompletionRoutineEntry) )))
        {
            res = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        memcpy( &entry->handler, completion, sizeof(PacketRequestCompletion) );

        if (!(entry->requestId = _strdup( requestId )))
        {
            res = ERROR_NOT_ENOUGH_MEMORY;

            free(entry);

            break;
        }

        entry->next                 = packetCompletionRoutineList;
        packetCompletionRoutineList = entry;

    } while (0);

    return res;
}

DWORD packet_call_completion_handlers( Remote *remote, Packet *response, LPCSTR requestId )
{
    PacketCompletionRoutineEntry *current;
    DWORD result = packet_get_result( response );
    DWORD matches = 0;
    Tlv methodTlv;
    LPCSTR method = NULL;

    if (packet_get_tlv_string(response, TLV_TYPE_METHOD, &methodTlv) == ERROR_SUCCESS)
        method = (LPCSTR)methodTlv.buffer;


    for (current = packetCompletionRoutineList; current; current = current->next)
    {
        if (strcmp(requestId, current->requestId))
            continue;

        current->handler.routine(remote, response, current->handler.context,
                method, result);

        matches++;
    }

    if (matches)
        packet_remove_completion_handler(requestId);

    return (matches > 0) ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}

DWORD packet_remove_completion_handler( LPCSTR requestId )
{
    PacketCompletionRoutineEntry *current, *next, *prev;

    for (current = packetCompletionRoutineList, next = NULL, prev = NULL;
         current;
          prev = current, current = next)
    {
        next = current->next;

        if (strcmp(requestId, current->requestId))
            continue;

        if (prev)
            prev->next = next;
        else
            packetCompletionRoutineList = next;
    
        free((PCHAR)current->requestId);
        free(current);
    }

    return ERROR_SUCCESS;
}

DWORD packet_transmit( Remote *remote, Packet *packet, PacketRequestCompletion *completion )
{
    if (remote->transport == METERPRETER_TRANSPORT_SSL) {
        return packet_transmit_via_ssl(remote, packet, completion);
    }
    if (remote->transport == METERPRETER_TRANSPORT_HTTP || remote->transport == METERPRETER_TRANSPORT_HTTPS) {
        return packet_transmit_via_http(remote, packet, completion);
    }
    return 0;
}

DWORD packet_transmit_via_ssl( Remote *remote, Packet *packet, PacketRequestCompletion *completion )
{
    CryptoContext *crypto;
    Tlv requestId;
    DWORD res;
    DWORD idx;
#ifdef _UNIX
    int local_error = -1;
#endif

    lock_acquire( remote->lock );

    if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,&requestId) != ERROR_SUCCESS)
    {
        DWORD index;
        CHAR rid[32];

        rid[sizeof(rid) - 1] = 0;

        for (index = 0; index < sizeof(rid) - 1; index++)
            rid[index] = (rand() % 0x5e) + 0x21;

        packet_add_tlv_string(packet, TLV_TYPE_REQUEST_ID, rid);
    }

    do
    {
        if ((completion) &&
            (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,
                &requestId) == ERROR_SUCCESS))
            packet_add_completion_handler((LPCSTR)requestId.buffer, completion);

        if ((crypto = remote_get_cipher(remote)) &&
            (packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
            (packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
        {
            ULONG origPayloadLength = packet->payloadLength;
            PUCHAR origPayload = packet->payload;

            if ((res = crypto->handlers.encrypt(crypto, packet->payload, 
                    packet->payloadLength, &packet->payload, 
                    &packet->payloadLength)) !=
                    ERROR_SUCCESS)
            {
                SetLastError(res);
                break;
            }

            free(origPayload);

            packet->header.length = htonl(packet->payloadLength + sizeof(TlvHeader));
        }

        idx = 0;
        while( idx < sizeof(packet->header))
        { 
            res = SSL_write(
                remote->ssl, 
                (LPCSTR)(&packet->header) + idx, 
                sizeof(packet->header) - idx
            );
            
            if(res <= 0) {
                dprintf("[PACKET] transmit header failed with return %d at index %d\n", res, idx);
                break;
            }
            idx += res;
        }

        if(res < 0)
            break;

        idx = 0;
        while( idx < packet->payloadLength)
        { 
            res = SSL_write(
                remote->ssl, 
                packet->payload + idx,
                packet->payloadLength - idx
            );
            if(res < 0)
                break;

            idx += res;
        }

        if(res < 0) {
            dprintf("[PACKET] transmit header failed with return %d at index %d\n", res, idx);
            break;
        }

        SetLastError(ERROR_SUCCESS);
    } while (0);

    res = GetLastError();

    packet_destroy(packet);

    lock_release( remote->lock );

    return res;
}

DWORD packet_transmit_via_http( Remote *remote, Packet *packet, PacketRequestCompletion *completion )
{
    CryptoContext *crypto;
    Tlv requestId;
    DWORD res;
#ifdef _UNIX
    int local_error = -1;
#endif

    lock_acquire( remote->lock );

    if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,&requestId) != ERROR_SUCCESS)
    {
        DWORD index;
        CHAR rid[32];

        rid[sizeof(rid) - 1] = 0;

        for (index = 0; index < sizeof(rid) - 1; index++)
            rid[index] = (rand() % 0x5e) + 0x21;

        packet_add_tlv_string(packet, TLV_TYPE_REQUEST_ID, rid);
    }

    do
    {
        if ((completion) &&
            (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,
                &requestId) == ERROR_SUCCESS))
            packet_add_completion_handler((LPCSTR)requestId.buffer, completion);

        if ((crypto = remote_get_cipher(remote)) &&
            (packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
            (packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
        {
            ULONG origPayloadLength = packet->payloadLength;
            PUCHAR origPayload = packet->payload;

            if ((res = crypto->handlers.encrypt(crypto, packet->payload, 
                    packet->payloadLength, &packet->payload, 
                    &packet->payloadLength)) !=
                    ERROR_SUCCESS)
            {
                SetLastError(res);
                break;
            }

            free(origPayload);

            packet->header.length = htonl(packet->payloadLength + sizeof(TlvHeader));
        }

        if(res < 0) {
            dprintf("[PACKET] transmit failed with return %d\n", res);
            break;
        }

        SetLastError(ERROR_SUCCESS);
    } while (0);

    res = GetLastError();

    packet_destroy(packet);

    lock_release( remote->lock );

    return res;
}


DWORD packet_transmit_empty_response( Remote *remote, Packet *packet, DWORD res )
{
    Packet *response = packet_create_response(packet);

    if (!response)
        return ERROR_NOT_ENOUGH_MEMORY;

    packet_add_tlv_uint(response, TLV_TYPE_RESULT, res);

    return packet_transmit(remote, response, NULL);
}

DWORD packet_receive( Remote *remote, Packet **packet )
{
    DWORD headerBytes = 0, payloadBytesLeft = 0, res; 
    CryptoContext *crypto = NULL;
    Packet *localPacket = NULL;
    TlvHeader header;
    LONG bytesRead;
    BOOL inHeader = TRUE;
    PUCHAR payload = NULL;
    ULONG payloadLength;

#ifdef _UNIX
    int local_error = -1;
#endif
    
    if (remote->transport == METERPRETER_TRANSPORT_HTTP || remote->transport == METERPRETER_TRANSPORT_HTTPS)
        return packet_receive_via_http( remote, packet );
    
    lock_acquire( remote->lock );

    do
    {
        while (inHeader)
        {
            if ((bytesRead = SSL_read(remote->ssl, ((PUCHAR)&header + headerBytes), sizeof(TlvHeader) - headerBytes)) <= 0)
            {
                if (!bytesRead)
                    SetLastError(ERROR_NOT_FOUND);

                if(bytesRead < 0) {
                    dprintf("[PACKET] receive header failed with error code %d. SSLerror=%d, WSALastError=%d\n", bytesRead, SSL_get_error( remote->ssl, bytesRead ), WSAGetLastError() );
                    SetLastError(ERROR_NOT_FOUND);
                }

                break;
            }

            headerBytes += bytesRead;
    
            if (headerBytes != sizeof(TlvHeader))
                continue;
            else
                inHeader = FALSE;
        }
        
        if (headerBytes != sizeof(TlvHeader))
            break;

        header.length    = header.length;
        header.type      = header.type;
        payloadLength    = ntohl( header.length ) - sizeof(TlvHeader);
        payloadBytesLeft = payloadLength;

        if (!(payload = (PUCHAR)malloc( payloadLength )))
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            break;
        }

        while (payloadBytesLeft > 0)
        {
            if ((bytesRead = SSL_read( remote->ssl, payload + payloadLength - payloadBytesLeft, payloadBytesLeft )) <= 0)
            {
                if (GetLastError() == 10035)
                    continue;

                if (!bytesRead)
                    SetLastError(ERROR_NOT_FOUND);

                if(bytesRead < 0) {
                    dprintf("[PACKET] receive payload of length %d failed with error code %d. SSLerror=%d\n", payloadLength, bytesRead, SSL_get_error( remote->ssl, bytesRead ) );
                    SetLastError(ERROR_NOT_FOUND);
                }

                break;
            }

            payloadBytesLeft -= bytesRead;
        }
        
        if (payloadBytesLeft)
            break;

        if (!(localPacket = (Packet *)malloc( sizeof(Packet) )))
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            break;
        }

        memset( localPacket, 0, sizeof(Packet) );

        if ((crypto = remote_get_cipher( remote )) &&
            (packet_get_type( localPacket ) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
            (packet_get_type( localPacket ) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
        {
            ULONG origPayloadLength = payloadLength;
            PUCHAR origPayload = payload;

            if ((res = crypto->handlers.decrypt( crypto, payload, payloadLength,&payload, &payloadLength )) != ERROR_SUCCESS)
            {
                SetLastError(res);
                break;
            }

            free(origPayload);
        }

        localPacket->header.length = header.length;
        localPacket->header.type   = header.type;
        localPacket->payload       = payload;
        localPacket->payloadLength = payloadLength;

        *packet = localPacket;

        SetLastError(ERROR_SUCCESS);

    } while (0);

    res = GetLastError();

    if ( res != ERROR_SUCCESS )
    {
        if (payload)
            free( payload );
        if (localPacket)
            free( localPacket );
    }

    lock_release( remote->lock );

    return res;
}

DWORD packet_receive_via_http( Remote *remote, Packet **packet )
{
    return 0;
}
