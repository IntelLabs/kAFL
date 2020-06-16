
#include <ntddk.h>


#define DEVICE_NAME         L"\\Device\\testKafl"
#define DOS_DEVICE_NAME     L"\\DosDevices\\testKafl"
#define IOCTL_KAFL_INPUT    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)



/*========================== jsmn.h ============================== */

/**
 * JSON type identifier. Basic types are:
 *  o Object
 *  o Array
 *  o String
 *  o Other primitive: number, boolean (true/false) or null
 */
typedef enum {
    JSMN_UNDEFINED = 0,
    JSMN_OBJECT = 1,
    JSMN_ARRAY = 2,
    JSMN_STRING = 3,
    JSMN_PRIMITIVE = 4
} jsmntype_t;

enum jsmnerr {
    /* Not enough tokens were provided */
    JSMN_ERROR_NOMEM = -1,
    /* Invalid character inside JSON string */
    JSMN_ERROR_INVAL = -2,
    /* The string is not a full JSON packet, more bytes expected */
    JSMN_ERROR_PART = -3
};

/**
 * JSON token description.
 * type     type (object, array, string etc.)
 * start    start position in JSON data string
 * end      end position in JSON data string
 */
typedef struct {
    jsmntype_t type;
    int start;
    int end;
    int size;
#ifdef JSMN_PARENT_LINKS
    int parent;
#endif
} jsmntok_t;

/**
 * JSON parser. Contains an array of token blocks available. Also stores
 * the string being parsed now and current position in that string
 */
typedef struct {
    unsigned int pos; /* offset in the JSON string */
    unsigned int toknext; /* next token to allocate */
    int toksuper; /* superior token node, e.g parent object or array */
} jsmn_parser;

/**
 * Create JSON parser over an array of tokens
 */
void jsmn_init(jsmn_parser *parser);

/**
 * Run JSON parser. It parses a JSON data string into and array of tokens, each describing
 * a single JSON object.
 */
int jsmn_parse(jsmn_parser *parser, const char *js, size_t len,
        jsmntok_t *tokens, unsigned int num_tokens);


/*========================== jsmn.c ============================== */

/**
 * Allocates a fresh unused token from the token pull.
 */
static jsmntok_t *jsmn_alloc_token(jsmn_parser *parser,
        jsmntok_t *tokens, size_t num_tokens) {
    jsmntok_t *tok;
    if (parser->toknext >= num_tokens) {
        return NULL;
    }
    tok = &tokens[parser->toknext++];
    tok->start = tok->end = -1;
    tok->size = 0;
#ifdef JSMN_PARENT_LINKS
    tok->parent = -1;
#endif
    return tok;
}

/**
 * Fills token type and boundaries.
 */
static void jsmn_fill_token(jsmntok_t *token, jsmntype_t type,
                            int start, int end) {
    token->type = type;
    token->start = start;
    token->end = end;
    token->size = 0;
}

/**
 * Fills next available token with JSON primitive.
 */
static int jsmn_parse_primitive(jsmn_parser *parser, const char *js,
        size_t len, jsmntok_t *tokens, size_t num_tokens) {
    jsmntok_t *token;
    int start;

    start = parser->pos;

    for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
        switch (js[parser->pos]) {
#ifndef JSMN_STRICT
            /* In strict mode primitive must be followed by "," or "}" or "]" */
            case ':':
#endif
            case '\t' : case '\r' : case '\n' : case ' ' :
            case ','  : case ']'  : case '}' :
                goto found;
        }
        if (js[parser->pos] < 32 || js[parser->pos] >= 127) {
            parser->pos = start;
            return JSMN_ERROR_INVAL;
        }
    }
#ifdef JSMN_STRICT
    /* In strict mode primitive must be followed by a comma/object/array */
    parser->pos = start;
    return JSMN_ERROR_PART;
#endif

found:
    if (tokens == NULL) {
        parser->pos--;
        return 0;
    }
    token = jsmn_alloc_token(parser, tokens, num_tokens);
    if (token == NULL) {
        parser->pos = start;
        return JSMN_ERROR_NOMEM;
    }
    jsmn_fill_token(token, JSMN_PRIMITIVE, start, parser->pos);
#ifdef JSMN_PARENT_LINKS
    token->parent = parser->toksuper;
#endif
    parser->pos--;
    return 0;
}

/**
 * Fills next token with JSON string.
 */
static int jsmn_parse_string(jsmn_parser *parser, const char *js,
        size_t len, jsmntok_t *tokens, size_t num_tokens) {
    jsmntok_t *token;

    int start = parser->pos;

    parser->pos++;

    /* Skip starting quote */
    for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
        char c = js[parser->pos];

        /* Quote: end of string */
        if (c == '\"') {
            if (tokens == NULL) {
                return 0;
            }
            token = jsmn_alloc_token(parser, tokens, num_tokens);
            if (token == NULL) {
                parser->pos = start;
                return JSMN_ERROR_NOMEM;
            }
            jsmn_fill_token(token, JSMN_STRING, start+1, parser->pos);
#ifdef JSMN_PARENT_LINKS
            token->parent = parser->toksuper;
#endif
            return 0;
        }

        /* Backslash: Quoted symbol expected */
        if (c == '\\' && parser->pos + 1 < len) {
            int i;
            parser->pos++;
            switch (js[parser->pos]) {
                /* Allowed escaped symbols */
                case '\"': case '/' : case '\\' : case 'b' :
                case 'f' : case 'r' : case 'n'  : case 't' :
                    break;
                /* Allows escaped symbol \uXXXX */
                case 'u':
                    parser->pos++;
                    for(i = 0; i < 4 && parser->pos < len && js[parser->pos] != '\0'; i++) {
                        /* If it isn't a hex character we have an error */
                        if(!((js[parser->pos] >= 48 && js[parser->pos] <= 57) || /* 0-9 */
                                    (js[parser->pos] >= 65 && js[parser->pos] <= 70) || /* A-F */
                                    (js[parser->pos] >= 97 && js[parser->pos] <= 102))) { /* a-f */
                            parser->pos = start;
                            return JSMN_ERROR_INVAL;
                        }
                        parser->pos++;
                    }
                    parser->pos--;
                    break;
                /* Unexpected symbol */
                default:
                    parser->pos = start;
                    return JSMN_ERROR_INVAL;
            }
        }
    }
    parser->pos = start;
    return JSMN_ERROR_PART;
}

/**
 * Parse JSON string and fill tokens.
 */
int jsmn_parse(jsmn_parser *parser, const char *js, size_t len,
        jsmntok_t *tokens, unsigned int num_tokens) {
    int r;
    int i;
    jsmntok_t *token;
    int count = parser->toknext;

    for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
        char c;
        jsmntype_t type;

        c = js[parser->pos];
        switch (c) {
            case '{': case '[':
                count++;
                if (tokens == NULL) {
                    break;
                }
                token = jsmn_alloc_token(parser, tokens, num_tokens);
                if (token == NULL)
                    return JSMN_ERROR_NOMEM;
                if (parser->toksuper != -1) {
                    tokens[parser->toksuper].size++;
#ifdef JSMN_PARENT_LINKS
                    token->parent = parser->toksuper;
#endif
                }
                token->type = (c == '{' ? JSMN_OBJECT : JSMN_ARRAY);
                token->start = parser->pos;
                parser->toksuper = parser->toknext - 1;
                break;
            case '}': case ']':
                if (tokens == NULL)
                    break;
                type = (c == '}' ? JSMN_OBJECT : JSMN_ARRAY);
#ifdef JSMN_PARENT_LINKS
                if (parser->toknext < 1) {
                    return JSMN_ERROR_INVAL;
                }
                token = &tokens[parser->toknext - 1];
                for (;;) {
                    if (token->start != -1 && token->end == -1) {
                        if (token->type != type) {
                            return JSMN_ERROR_INVAL;
                        }
                        token->end = parser->pos + 1;
                        parser->toksuper = token->parent;
                        break;
                    }
                    if (token->parent == -1) {
                        if(token->type != type || parser->toksuper == -1) {
                            return JSMN_ERROR_INVAL;
                        }
                        break;
                    }
                    token = &tokens[token->parent];
                }
#else
                for (i = parser->toknext - 1; i >= 0; i--) {
                    token = &tokens[i];
                    if (token->start != -1 && token->end == -1) {
                        if (token->type != type) {
                            return JSMN_ERROR_INVAL;
                        }
                        parser->toksuper = -1;
                        token->end = parser->pos + 1;
                        break;
                    }
                }
                /* Error if unmatched closing bracket */
                if (i == -1) return JSMN_ERROR_INVAL;
                for (; i >= 0; i--) {
                    token = &tokens[i];
                    if (token->start != -1 && token->end == -1) {
                        parser->toksuper = i;
                        break;
                    }
                }
#endif
                break;
            case '\"':
                r = jsmn_parse_string(parser, js, len, tokens, num_tokens);
                if (r < 0) return r;
                count++;
                if (parser->toksuper != -1 && tokens != NULL)
                    tokens[parser->toksuper].size++;
                break;
            case '\t' : case '\r' : case '\n' : case ' ':
                break;
            case ':':
                parser->toksuper = parser->toknext - 1;
                break;
            case ',':
                if (tokens != NULL && parser->toksuper != -1 &&
                        tokens[parser->toksuper].type != JSMN_ARRAY &&
                        tokens[parser->toksuper].type != JSMN_OBJECT) {
#ifdef JSMN_PARENT_LINKS
                    parser->toksuper = tokens[parser->toksuper].parent;
#else
                    for (i = parser->toknext - 1; i >= 0; i--) {
                        if (tokens[i].type == JSMN_ARRAY || tokens[i].type == JSMN_OBJECT) {
                            if (tokens[i].start != -1 && tokens[i].end == -1) {
                                parser->toksuper = i;
                                break;
                            }
                        }
                    }
#endif
                }
                break;
#ifdef JSMN_STRICT
            /* In strict mode primitives are: numbers and booleans */
            case '-': case '0': case '1' : case '2': case '3' : case '4':
            case '5': case '6': case '7' : case '8': case '9':
            case 't': case 'f': case 'n' :
                /* And they must not be keys of the object */
                if (tokens != NULL && parser->toksuper != -1) {
                    jsmntok_t *t = &tokens[parser->toksuper];
                    if (t->type == JSMN_OBJECT ||
                            (t->type == JSMN_STRING && t->size != 0)) {
                        return JSMN_ERROR_INVAL;
                    }
                }
#else
            /* In non-strict mode every unquoted value is a primitive */
            default:
#endif
                r = jsmn_parse_primitive(parser, js, len, tokens, num_tokens);
                if (r < 0) return r;
                count++;
                if (parser->toksuper != -1 && tokens != NULL)
                    tokens[parser->toksuper].size++;
                break;

#ifdef JSMN_STRICT
            /* Unexpected char in strict mode */
            default:
                return JSMN_ERROR_INVAL;
#endif
        }
    }

    if (tokens != NULL) {
        for (i = parser->toknext - 1; i >= 0; i--) {
            /* Unmatched opened object or array */
            if (tokens[i].start != -1 && tokens[i].end == -1) {
                return JSMN_ERROR_PART;
            }
        }
    }

    return count;
}

/**
 * Creates a new parser based over a given  buffer with an array of tokens
 * available.
 */
void jsmn_init(jsmn_parser *parser) {
    parser->pos = 0;
    parser->toknext = 0;
    parser->toksuper = -1;
}


/*========================== VULN DRIVER ============================== */


NTSTATUS crashMe(IN PIO_STACK_LOCATION IrpStack){
    SIZE_T len = 0;
    PCHAR input = NULL;

    input = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
    len = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    if (len >= 256){
        return STATUS_SUCCESS;
    }

    //DbgPrint("[+] KAFL vuln drv -- 0\n");

    jsmn_parser parser;
    jsmntok_t tokens[5];
    jsmn_init(&parser);

    int res = jsmn_parse(&parser, input, len, tokens, 5);
    if(res >= 2){
        //DbgPrint("[+] KAFL vuln drv -- 1\n");
        if(tokens[0].type == JSMN_STRING){
            //DbgPrint("[+] KAFL vuln drv -- 2\n");
            int json_len = tokens[0].end - tokens[0].start;
            //DbgPrint("[+] KAFL vuln drv -- 3\n");
            if(json_len > 0 && input[tokens[0].start+0] == 'K'){
                //DbgPrint("[+] KAFL vuln drv -- 4\n");
                if(json_len > 1 && input[tokens[0].start+1] == 'A'){
                    //DbgPrint("[+] KAFL vuln drv -- 5\n");
                    if(json_len > 2 && input[tokens[0].start+2] == 'F'){
                        //DbgPrint("[+] KAFL vuln drv -- 6\n");
                        if(json_len > 3 && input[tokens[0].start+3] == 'L'){
                            //DbgPrint("[+] KAFL vuln drv -- 7\n");
                          len = *((PSIZE_T)(0x0));
                        }
                    }
                }
            }
        }
    }

   
    return STATUS_SUCCESS;
}


NTSTATUS handleIrp(IN PDEVICE_OBJECT DeviceObj, IN PIRP pIrp){
    PIO_STACK_LOCATION  irpStack = 0;
    ULONG               ioctl;

    irpStack = IoGetCurrentIrpStackLocation(pIrp);

    pIrp->IoStatus.Information = 0;
    pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(DeviceObj);
    PAGED_CODE();

    switch(irpStack->MajorFunction){
        case IRP_MJ_DEVICE_CONTROL:
            ioctl = irpStack->Parameters.DeviceIoControl.IoControlCode;
            switch(ioctl){
                case IOCTL_KAFL_INPUT:
                    DbgPrint("[+] KAFL vuln drv -- crash attempt\n");
                    pIrp->IoStatus.Status = crashMe(irpStack);
                    break;
                default:
                    pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                    break;
            }
            break;
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            pIrp->IoStatus.Status = STATUS_SUCCESS;
            break;
    };

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return pIrp->IoStatus.Status;
}


void DriverUnload(PDRIVER_OBJECT pDriverObject){
    UNICODE_STRING dosDeviceName = { 0 };
    RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&dosDeviceName);
    IoDeleteDevice(pDriverObject->DeviceObject);
    DbgPrint("[+] KAFL vuln drv -- unloaded");
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObj, IN PUNICODE_STRING RegPath){
    UINT32          i = 0;
    NTSTATUS        ntstatus;
    PDEVICE_OBJECT  deviceObject = NULL;
    UNICODE_STRING  deviceName, dosDeviceName = { 0 };

    UNREFERENCED_PARAMETER(RegPath);
    PAGED_CODE();

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);

    ntstatus = IoCreateDevice(DriverObj, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if(!NT_SUCCESS(ntstatus)){
        DbgPrint("[-] KAFL vuln drv -- IoCreateDevice failed: 0x%X\n", ntstatus);
        IoDeleteDevice(DriverObj->DeviceObject);
        return ntstatus;
    }

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++){
        DriverObj->MajorFunction[i] = handleIrp;
    }

    DriverObj->DriverUnload = DriverUnload;
    deviceObject->Flags |= DO_DIRECT_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    ntstatus = IoCreateSymbolicLink(&dosDeviceName, &deviceName);

    DbgPrint("[+] KAFL vuln drv -- loaded");
    return ntstatus;
}

