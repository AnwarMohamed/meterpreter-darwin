#include "common.h"

DWORD args_parse(UINT argc, CHAR **argv, PCHAR params, 
        ArgumentContext *ctx)
{
    DWORD index = 0;

    if (!ctx->currentIndex)
        ctx->currentIndex = 1;

    index = ctx->currentIndex;

    if (index >= argc)
        return ERROR_NOT_FOUND;

    if (argv[index][0] == '-')
    {
        PCHAR currentParam = params;
        BOOL hasParam = FALSE;

        while (*currentParam)
        {
            if (*currentParam == argv[index][1])
            {
                hasParam = (*(currentParam + 1) == ':') ? TRUE : FALSE;
                break;
            }

            currentParam++;
        }

        if ((hasParam) &&
            (index + 1 >= argc))
            return ERROR_INVALID_PARAMETER;

        ctx->argument = (hasParam) ? argv[index+1] : NULL;
        ctx->toggle   = argv[index][1]; 

        if (hasParam)
            ++index;
    }
    else
        ctx->toggle = 0;

    ctx->currentIndex = ++index;

    return ERROR_SUCCESS;
}
