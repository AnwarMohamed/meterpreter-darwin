#include "common.h"

VOID channel_add_list_entry(Channel *channel);
VOID channel_remove_list_entry(Channel *channel);

VOID channel_set_buffer_io_handler(ChannelBuffer *buffer, LPVOID context,
        DirectIoHandler dio);
VOID channel_write_buffer(Channel *channel, ChannelBuffer *buffer, 
        PUCHAR chunk, ULONG chunkLength, PULONG bytesWritten);
VOID channel_read_buffer(Channel *channel, ChannelBuffer *buffer, 
        PUCHAR chunk, ULONG chunkLength, PULONG bytesRead);

DWORD channelIdPool  = 0;

Channel *channel_create(DWORD identifier, DWORD flags)
{
    Channel *channel = NULL;

    do
    {
        if (!(channel = (Channel *)malloc(sizeof(Channel))))
            break;

        memset(channel, 0, sizeof(Channel));

        channel->identifier  = (!identifier) ? ++channelIdPool : identifier;
        channel->interactive = FALSE;
        channel->flags       = flags;
        channel->cls         = CHANNEL_CLASS_BUFFERED;
        channel->lock        = lock_create();

        memset(&channel->ops, 0, sizeof(channel->ops));

        channel_set_buffered_io_handler(channel, &channel->ops.buffered,
                channel_default_io_handler);

        channel_add_list_entry(channel);

    } while (0);

    return channel;
}

LINKAGE Channel *channel_create_stream(DWORD identifier, 
        DWORD flags, StreamChannelOps *ops)
{
    Channel *channel = channel_create(identifier, flags);

    if (channel)
    {
        channel->cls = CHANNEL_CLASS_STREAM;

        if (ops)
            memcpy(&channel->ops.stream, ops, sizeof(StreamChannelOps));
        else
            memset(&channel->ops, 0, sizeof(channel->ops));
    }

    return channel;
}

LINKAGE Channel *channel_create_datagram(DWORD identifier, 
        DWORD flags, DatagramChannelOps *ops)
{
    Channel *channel = channel_create(identifier, flags);

    if (channel)
    {
        channel->cls = CHANNEL_CLASS_DATAGRAM;

        if (ops)
            memcpy(&channel->ops.datagram, ops, sizeof(DatagramChannelOps));
        else
            memset(&channel->ops, 0, sizeof(channel->ops));
    }

    return channel;
}

LINKAGE Channel *channel_create_pool(DWORD identifier, 
        DWORD flags, PoolChannelOps *ops)
{
    Channel *channel = channel_create(identifier, flags);

    if (channel)
    {
        channel->cls = CHANNEL_CLASS_POOL;

        if (ops)
            memcpy(&channel->ops.pool, ops, sizeof(PoolChannelOps));
        else
            memset(&channel->ops, 0, sizeof(channel->ops));
    }

    return channel;
}

VOID channel_destroy(Channel *channel, Packet *request)
{
    dprintf( "[CHANNEL] channel_destroy. channel=0x%08X", channel );
    if ((channel_get_class(channel) == CHANNEL_CLASS_BUFFERED) &&
        (channel->ops.buffered.dio))
    {
        channel->ops.buffered.dio(channel, &channel->ops.buffered, 
                channel->ops.buffered.dioContext, CHANNEL_DIO_MODE_CLOSE,
                NULL, 0, NULL);

        if (channel->ops.buffered.buffer)
            free(channel->ops.buffered.buffer);
    }
    else
    {
        NativeChannelOps *ops = (NativeChannelOps *)&channel->ops;

        if (ops->close)
            ops->close(channel, request, ops->context);
    }

    channel_remove_list_entry(channel);

    lock_destroy( channel->lock );

    dprintf( "[CHANNEL] Free up the channel context 0x%p", channel );
    free(channel);
}

DWORD channel_get_id(Channel *channel)
{
    return channel->identifier;
}

VOID channel_set_type(Channel *channel, PCHAR type)
{
    if (channel->type)
        free(channel->type);

    channel->type = NULL;

    if (type)
        channel->type = _strdup(type);
}

PCHAR channel_get_type(Channel *channel)
{
    return channel->type;
}

DWORD channel_get_class(Channel *channel)
{
    return channel->cls;
}

VOID channel_set_flags(Channel *channel, ULONG flags)
{
    channel->flags = flags;
}

BOOLEAN channel_is_flag(Channel *channel, ULONG flag)
{
    return ((channel->flags & flag) == flag) ? TRUE : FALSE;
}

ULONG channel_get_flags(Channel *channel)
{
    return channel->flags;
}

VOID channel_set_interactive(Channel *channel, BOOL interactive)
{
    channel->interactive = interactive;
}

BOOL channel_is_interactive(Channel *channel)
{
    return channel->interactive;
}

VOID channel_set_buffered_io_handler(Channel *channel, LPVOID dioContext,
        DirectIoHandler dio)
{
    channel_set_buffer_io_handler(&channel->ops.buffered, dioContext, dio);
}

PVOID channel_get_buffered_io_context(Channel *channel)
{
    return channel->ops.buffered.dioContext;
}

DWORD channel_write_to_remote(Remote *remote, Channel *channel, PUCHAR chunk, 
        ULONG chunkLength, PULONG bytesWritten)
{
    Packet *request = packet_create(PACKET_TLV_TYPE_REQUEST, 
            "core_channel_write");
    DWORD res = ERROR_SUCCESS;
    Tlv entries[2];
    DWORD idNbo;

    do
    {
        if (!request)
        {
            res = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        idNbo = htonl(channel_get_id(channel));

        entries[0].header.type   = TLV_TYPE_CHANNEL_ID;
        entries[0].header.length = sizeof(DWORD);
        entries[0].buffer        = (PUCHAR)&idNbo;

        if( channel_is_flag( channel, CHANNEL_FLAG_COMPRESS ) )
            entries[1].header.type = TLV_TYPE_CHANNEL_DATA|TLV_META_TYPE_COMPRESSED;
        else
            entries[1].header.type = TLV_TYPE_CHANNEL_DATA;

        entries[1].header.length = chunkLength;
        entries[1].buffer        = chunk;

        if ((res = packet_add_tlv_group(request, TLV_TYPE_CHANNEL_DATA_GROUP, entries, 2)) != ERROR_SUCCESS)
            break;

        res = packet_transmit(remote, request, NULL);

    } while (0);

    return res;
}

DWORD channel_write_to_buffered(Channel *channel, PUCHAR chunk, ULONG chunkLength,
        PULONG bytesWritten)
{
    return channel->ops.buffered.dio(channel, &channel->ops.buffered, 
            channel->ops.buffered.dioContext, CHANNEL_DIO_MODE_WRITE, chunk, 
            chunkLength, bytesWritten);
}

DWORD channel_read_from_buffered(Channel *channel, PUCHAR chunk, ULONG chunkLength, 
        PULONG bytesRead)
{
    return channel->ops.buffered.dio(channel, &channel->ops.buffered, 
            channel->ops.buffered.dioContext, CHANNEL_DIO_MODE_READ, chunk, chunkLength,
            bytesRead);
}

VOID channel_set_buffer_io_handler(ChannelBuffer *buffer, LPVOID context,
        DirectIoHandler dio)
{
    if (!dio)
    {
        dio     = channel_default_io_handler;
        context = NULL;
    }

    buffer->dioContext = context;
    buffer->dio        = dio;
}

LINKAGE VOID channel_set_native_io_context(Channel *channel, LPVOID context)
{
    NativeChannelOps *ops = (NativeChannelOps *)&channel->ops;

    ops->context = context;
}

LINKAGE LPVOID channel_get_native_io_context(Channel *channel)
{
    NativeChannelOps *ops = (NativeChannelOps *)&channel->ops;
    
    return ops->context;
}

ChannelCompletionRoutine *channel_duplicate_completion_routine(
        ChannelCompletionRoutine *in)
{
    ChannelCompletionRoutine *ret = NULL;

    if ((ret = (ChannelCompletionRoutine *)malloc(
            sizeof(ChannelCompletionRoutine))))
        memcpy(ret, in, sizeof(ChannelCompletionRoutine));

    return ret;
}

DWORD _channel_packet_completion_routine(Remote *remote, Packet *packet, 
        LPVOID context, LPCSTR method, DWORD result)
{
    ChannelCompletionRoutine *comp = (ChannelCompletionRoutine *)context;
    DWORD channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);
    Channel *channel = channel_find_by_id(channelId);
    DWORD res = ERROR_NOT_FOUND;

    dprintf( "[CHANNEL] _channel_packet_completion_routine. channel=0x%08X method=%s", channel, method );

    if (!channel && strcmp(method, "core_channel_open"))
        return ERROR_NOT_FOUND;

    if ((!strcmp(method, "core_channel_open")) &&
        (comp->routine.open))
        res = comp->routine.open(remote, channel, comp->context, result);
    else if ((!strcmp(method, "core_channel_read")) &&
             (comp->routine.read))
    {
        ULONG length = 0, realLength = 0;
        PUCHAR buffer = NULL;

        length = packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH);

        if ((length) && (buffer = (PUCHAR)malloc(length)))
        {
            memset(buffer, 0, length);

            channel_read_from_buffered(channel, buffer, length, &realLength);
        }

        res = comp->routine.read(remote, channel, comp->context, result,
                buffer, realLength);

        if (buffer)
            free(buffer);
    }
    else if ((!strcmp(method, "core_channel_write")) &&
             (comp->routine.write))
    {
        Tlv lengthTlv;
        ULONG length = 0;

        if ((packet_get_tlv(packet, TLV_TYPE_LENGTH, &lengthTlv)
                == ERROR_SUCCESS) &&
            (lengthTlv.header.length >= sizeof(DWORD)))
            length = ntohl(*(LPDWORD)lengthTlv.buffer);

        res = comp->routine.write(remote, channel, comp->context, result,
                length);
    }
    else if ((!strcmp(method, "core_channel_close")) &&
             (comp->routine.close)) {
        dprintf( "[CHANNEL] freeing up the completion context" );
        res = comp->routine.close(remote, channel, comp->context, result);
    }
    else if ((!strcmp(method, "core_channel_interact")) &&
             (comp->routine.interact))
        res = comp->routine.interact(remote, channel, comp->context, result);

    dprintf( "[CHANNEL] freeing up the completion context" );
    free(comp);

    return res;
}

DWORD channel_open(Remote *remote, Tlv *addend, DWORD addendLength,
        ChannelCompletionRoutine *completionRoutine)
{
    PacketRequestCompletion requestCompletion, *realRequestCompletion = NULL;
    ChannelCompletionRoutine *dupe = NULL;
    DWORD res = ERROR_SUCCESS;
    PCHAR method = "core_channel_open";
    Packet *request;
    Tlv methodTlv;

    do
    {
        if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST,
                NULL)))
        {
            res = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        packet_add_tlvs(request, addend, addendLength);

        if (packet_get_tlv(request, TLV_TYPE_METHOD,
                &methodTlv) != ERROR_SUCCESS)
            packet_add_tlv_string(request, TLV_TYPE_METHOD,
                    method);

        if (completionRoutine)
        {
            dupe = channel_duplicate_completion_routine(completionRoutine);

            requestCompletion.context = dupe;
            requestCompletion.routine = _channel_packet_completion_routine;
            realRequestCompletion     = &requestCompletion;
        }

        res = packet_transmit(remote, request, realRequestCompletion);

    } while (0);

    return res;
}

DWORD channel_read(Channel *channel, Remote *remote, Tlv *addend,
        DWORD addendLength, ULONG length, 
        ChannelCompletionRoutine *completionRoutine)
{
    PacketRequestCompletion requestCompletion, *realRequestCompletion = NULL;
    ChannelCompletionRoutine *dupe = NULL;
    Packet *request;
    DWORD res = ERROR_SUCCESS;
    PCHAR method = "core_channel_read";
    Tlv methodTlv;

    do
    {
        if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, 
                NULL)))
        {
            res = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        packet_add_tlvs(request, addend, addendLength);

        if (packet_get_tlv(request, TLV_TYPE_METHOD,
                &methodTlv) != ERROR_SUCCESS)
            packet_add_tlv_string(request, TLV_TYPE_METHOD,
                    method);

        packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_ID,
                channel_get_id(channel));
        packet_add_tlv_uint(request, TLV_TYPE_LENGTH,
                length);

        if (completionRoutine)
        {
            dupe = channel_duplicate_completion_routine(completionRoutine);

            requestCompletion.context = dupe;
            requestCompletion.routine = _channel_packet_completion_routine;
            realRequestCompletion     = &requestCompletion;
        }

        res = packet_transmit(remote, request, realRequestCompletion);

    } while (0);

    return res;
}

DWORD channel_close(Channel *channel, Remote *remote, Tlv *addend,
        DWORD addendLength, ChannelCompletionRoutine *completionRoutine)
{
    PacketRequestCompletion requestCompletion, *realRequestCompletion = NULL;
    ChannelCompletionRoutine *dupe = NULL;
    LPCSTR method = "core_channel_close";
    DWORD res = ERROR_SUCCESS;
    Packet *request;
    Tlv methodTlv;

    do
    {
        if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, 
                NULL)))
        {
            res = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }
        packet_add_tlvs(request, addend, addendLength);

        if (packet_get_tlv(request, TLV_TYPE_METHOD,
                &methodTlv) != ERROR_SUCCESS)
            packet_add_tlv_string(request, TLV_TYPE_METHOD,
                    method);

        packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_ID,
                channel_get_id(channel));

        if (completionRoutine)
        {
            dupe = channel_duplicate_completion_routine(completionRoutine);

            requestCompletion.context = dupe;
            requestCompletion.routine = _channel_packet_completion_routine;
            realRequestCompletion     = &requestCompletion;
        }

        dprintf( "[CHANNEL] channel_close. channel=0x%08X completion=0x%.8x", channel, completionRoutine );

        res = packet_transmit(remote, request, realRequestCompletion);

    } while (0);
    return res;
}

DWORD channel_write(Channel *channel, Remote *remote, Tlv *addend,
        DWORD addendLength, PUCHAR buffer, ULONG length, 
        ChannelCompletionRoutine *completionRoutine)
{
    PacketRequestCompletion requestCompletion, *realRequestCompletion = NULL;
    ChannelCompletionRoutine *dupe = NULL;
    DWORD res = ERROR_SUCCESS;
    LPCSTR method = "core_channel_write";
    Packet *request;
    Tlv methodTlv;

    do
    {
        if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, NULL)))
        {
            res = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        packet_add_tlvs(request, addend, addendLength);

        if (packet_get_tlv(request, TLV_TYPE_METHOD, &methodTlv) != ERROR_SUCCESS)
            packet_add_tlv_string(request, TLV_TYPE_METHOD, method);

        packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_ID, channel_get_id(channel));

        if( channel_is_flag( channel, CHANNEL_FLAG_COMPRESS ) )
            packet_add_tlv_raw(request, TLV_TYPE_CHANNEL_DATA|TLV_META_TYPE_COMPRESSED, buffer, length);
        else
            packet_add_tlv_raw(request, TLV_TYPE_CHANNEL_DATA, buffer, length);

        packet_add_tlv_uint(request, TLV_TYPE_LENGTH, channel_get_id(channel));

        if (completionRoutine)
        {
            dupe = channel_duplicate_completion_routine(completionRoutine);

            requestCompletion.context = dupe;
            requestCompletion.routine = _channel_packet_completion_routine;
            realRequestCompletion     = &requestCompletion;
        }

        res = packet_transmit(remote, request, realRequestCompletion);

    } while (0);

    return res;
}

Channel *channelList = NULL;

DWORD channel_interact(Channel *channel, Remote *remote, Tlv *addend,
        DWORD addendLength, BOOL enable, 
        ChannelCompletionRoutine *completionRoutine)
{
    PacketRequestCompletion requestCompletion, *realRequestCompletion = NULL;
    ChannelCompletionRoutine *dupe = NULL;
    LPCSTR method = "core_channel_interact";
    DWORD res = ERROR_SUCCESS;
    Packet *request;
    Tlv methodTlv;

    do
    {
        if (!(request = packet_create(PACKET_TLV_TYPE_REQUEST, 
                NULL)))
        {
            res = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        packet_add_tlvs(request, addend, addendLength);

        if (packet_get_tlv(request, TLV_TYPE_METHOD,
                &methodTlv) != ERROR_SUCCESS)
            packet_add_tlv_string(request, TLV_TYPE_METHOD,
                    method);

        packet_add_tlv_uint(request, TLV_TYPE_CHANNEL_ID,
                channel_get_id(channel));

        packet_add_tlv_bool(request, TLV_TYPE_BOOL, enable);

        if (completionRoutine)
        {
            dupe = channel_duplicate_completion_routine(completionRoutine);

            requestCompletion.context = dupe;
            requestCompletion.routine = _channel_packet_completion_routine;
            realRequestCompletion     = &requestCompletion;
        }

        res = packet_transmit(remote, request, realRequestCompletion);

    } while (0);

    return res;
}

Channel *channel_find_by_id(DWORD id)
{
    Channel *current;

    for (current = channelList;
         current;
         current = current->next)
    {
        if (current->identifier == id)
            break;
    }

    return current;
}

VOID channel_add_list_entry(Channel *channel)
{
    if (channelList)
        channelList->prev = channel;

    channel->next = channelList;
    channel->prev = NULL;
    channelList   = channel;
}

VOID channel_remove_list_entry(Channel *channel)
{
    if (channel->prev)
        channel->prev->next = channel->next;
    else
        channelList = channel->next;

    if (channel->next)
        channel->next->prev = channel->prev;
}

DWORD channel_default_io_handler(Channel *channel, ChannelBuffer *buffer,
        LPVOID context, ChannelDioMode mode, PUCHAR chunk, ULONG length, 
        PULONG bytesXfered)
{
    switch (mode)
    {
        case CHANNEL_DIO_MODE_READ:
            channel_read_buffer(channel, buffer, chunk, length, bytesXfered);
            break;
        case CHANNEL_DIO_MODE_WRITE:
            channel_write_buffer(channel, buffer, chunk, length, bytesXfered);
            break;
        default:
            break;
    }

    return ERROR_SUCCESS;
}

VOID channel_write_buffer(Channel *channel, ChannelBuffer *buffer, 
        PUCHAR chunk, ULONG chunkLength, PULONG bytesWritten)
{
    if (buffer->currentSize + chunkLength > buffer->totalSize)
    {
        PUCHAR newBuffer = NULL;
        ULONG newSize = 0;

        newSize  = buffer->currentSize + chunkLength;
        newSize += CHANNEL_CHUNK_SIZE + (newSize & (CHANNEL_CHUNK_SIZE - 1));

        if (buffer->totalSize)
            newBuffer = (PUCHAR)realloc(buffer->buffer, newSize);
        else
            newBuffer = (PUCHAR)malloc(newSize);

        if (!newBuffer)
        {
            if (buffer->buffer)
                free(buffer->buffer);

            memset(buffer, 0, sizeof(ChannelBuffer));

            return;
        }

        buffer->buffer    = newBuffer;
        buffer->totalSize = newSize;
    }

    memcpy(buffer->buffer + buffer->currentSize,
            chunk, chunkLength);

    buffer->currentSize += chunkLength;

    if (bytesWritten)
        *bytesWritten = chunkLength;
}

VOID channel_read_buffer(Channel *channel, ChannelBuffer *buffer, PUCHAR chunk,
        ULONG chunkLength, PULONG bytesRead)
{
    ULONG actualSize = chunkLength;

    if (actualSize > buffer->currentSize)
        actualSize = buffer->currentSize;

    memcpy(chunk, buffer->buffer, actualSize);

    if (actualSize != buffer->currentSize)
        memcpy(buffer->buffer, buffer->buffer + actualSize,
                buffer->currentSize - actualSize);

    buffer->currentSize -= actualSize;

    if (bytesRead)
        *bytesRead = actualSize;
}
