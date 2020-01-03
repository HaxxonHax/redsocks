#include <stdio.h>
#include <stdlib.h> /* malloc() */
#include <stdint.h>
#include <string.h> /* strncpy() */
#include <sys/socket.h>
#include <sys/types.h>

#define SERVER_NAME_LEN 256
#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif


static int parse_tls_header(const uint8_t*, size_t, char **);
static int parse_extensions(const uint8_t*, size_t, char **);
static int parse_server_name_extension(const uint8_t*, size_t, char **);


unsigned char good_data_2[] = {
    // TLS record
    0x16, // Content Type: Handshake
    0x03, 0x01, // Version: TLS 1.0
    0x00, 0x6c, // Length (use for bounds checking)
        // Handshake
        0x01, // Handshake Type: Client Hello
        0x00, 0x00, 0x68, // Length (use for bounds checking)
        0x03, 0x03, // Version: TLS 1.2
        // Random (32 bytes fixed length)
        0xb6, 0xb2, 0x6a, 0xfb, 0x55, 0x5e, 0x03, 0xd5,
        0x65, 0xa3, 0x6a, 0xf0, 0x5e, 0xa5, 0x43, 0x02,
        0x93, 0xb9, 0x59, 0xa7, 0x54, 0xc3, 0xdd, 0x78,
        0x57, 0x58, 0x34, 0xc5, 0x82, 0xfd, 0x53, 0xd1,
        0x00, // Session ID Length (skip past this much)
        0x00, 0x04, // Cipher Suites Length (skip past this much)
            0x00, 0x01, // NULL-MD5
            0x00, 0xff, // RENEGOTIATION INFO SCSV
        0x01, // Compression Methods Length (skip past this much)
            0x00, // NULL
        0x00, 0x3b, // Extensions Length (use for bounds checking)
            // Extension
            0x00, 0x00, // Extension Type: Server Name (check extension type)
            0x00, 0x0e, // Length (use for bounds checking)
            0x00, 0x0c, // Server Name Indication Length
                0x00, // Server Name Type: host_name (check server name type)
                0x00, 0x09, // Length (length of your data)
                // "localhost" (data your after)
                0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
            // Extension
            0x00, 0x0d, // Extension Type: Signature Algorithms (check extension type)
            0x00, 0x20, // Length (skip past since this is the wrong extension)
            // Data
            0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03,
            0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01,
            0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02,
            0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
            // Extension
            0x00, 0x0f, // Extension Type: Heart Beat (check extension type)
            0x00, 0x01, // Length (skip past since this is the wrong extension)
            0x01 // Mode: Peer allows to send requests
};

/* Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first servername found (pointer to static
 * array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid TLS client hello
 */
static int
parse_tls_header(const uint8_t *data, size_t data_len, char **hostname) {
    uint8_t tls_content_type;
    uint8_t tls_version_major;
    uint8_t tls_version_minor;
    size_t pos = TLS_HEADER_LEN;
    size_t len;

    if (hostname == NULL)
        return -3;

    /* Check that our TCP payload is at least large enough for a TLS header */
    if (data_len < TLS_HEADER_LEN)
        return -1;

    /* SSL 2.0 compatible Client Hello
     *
     * High bit of first byte (length) and content type is Client Hello
     *
     * See RFC5246 Appendix E.2
     */
    if (data[0] & 0x80 && data[2] == 1) {
        return -2;
    }

    tls_content_type = data[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        return -5;
    }

    tls_version_major = data[1];
    tls_version_minor = data[2];
    if (tls_version_major < 3) {
        return -2;
    }

    /* TLS record length */
    len = ((size_t)data[3] << 8) +
        (size_t)data[4] + TLS_HEADER_LEN;
    data_len = MIN(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len)
        return -1;

    /*
     * Handshake
     */
    if (pos + 1 > data_len) {
        return -5;
    }
    if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        return -5;
    }

    /* Skip past fixed length records:
       1    Handshake Type
       3    Length
       2    Version (again)
       32   Random
       to   Session ID Length
     */
    pos += 38;

    /* Session ID */
    if (pos + 1 > data_len)
        return -5;
    len = (size_t)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len)
        return -5;
    len = ((size_t)data[pos] << 8) + (size_t)data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len)
        return -5;
    len = (size_t)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
        return -2;
    }

    /* Extensions */
    if (pos + 2 > data_len)
        return -5;
    len = ((size_t)data[pos] << 8) + (size_t)data[pos + 1];
    pos += 2;

    if (pos + len > data_len)
        return -5;
    return parse_extensions(data + pos, len, hostname);
}

static int
parse_extensions(const uint8_t *data, size_t data_len, char **hostname) {
    size_t pos = 0;
    size_t len;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        len = ((size_t)data[pos + 2] << 8) +
            (size_t)data[pos + 3];

        /* Check if it's a server name extension */
        if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
            /* There can be only one extension of each type, so we break
               our state and move p to beinnging of the extension here */
            if (pos + 4 + len > data_len)
                return -5;
            return parse_server_name_extension(data + pos + 4, len, hostname);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

static int
parse_server_name_extension(const uint8_t *data, size_t data_len,
        char **hostname) {
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < data_len) {
        len = ((size_t)data[pos + 1] << 8) +
            (size_t)data[pos + 2];

        if (pos + 3 + len > data_len)
            return -5;

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                *hostname = malloc(len + 1);
                if (*hostname == NULL) {
                    return -4;
                }

                strncpy(*hostname, (const char *)(data + pos + 3), len);

                (*hostname)[len] = '\0';
                printf("hostname: %s\n",hostname);

                return len;
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

char *get_TLS_SNI(const unsigned char *bytes, int* len)
{
    unsigned char *curr;
    unsigned char sidlen = bytes[43];
    printf("Initializing curr.\n");
    curr = bytes + 1 + 43 + sidlen;
    unsigned short cslen = ntohs(*(unsigned short*)curr);
    printf("Bypassing cslen.\n");
    curr += 2 + cslen;
    unsigned char cmplen = *curr;
    printf("Bypassing cmplen.\n");
    curr += 1 + cmplen;
    printf("Getting maxchar.\n");
    unsigned char *maxchar = curr + 2 + ntohs(*(unsigned short*)curr);
    curr += 2;
    unsigned short ext_type = 1;
    unsigned short ext_len;
    printf("Bypassing ext_type.\n");
    while(curr < maxchar && ext_type != 0)
    {
        printf("Getting ntohs (1).\n");
        ext_type = ntohs(*(unsigned short*)curr);
        curr += 2;
        printf("Getting ntohs (2).\n");
        ext_len = ntohs(*(unsigned short*)curr);
        curr += 2;
        if(ext_type == 0)
        {
            printf("ext_type is 0\n");
            curr += 3;
            printf("getting namelen from ntohs\n");
            unsigned short namelen = ntohs(*(unsigned short*)curr);
            printf("incrementing curr by 2\n");
            curr += 2;
            printf("Copying len to namelen.\n");
            // *len = namelen;
            printf("Returning curr as a string.\n");
            printf("curr is %s\n",curr);
            return (char*)curr;
        }
        else curr += ext_len;
    }
    if (curr != maxchar) return("BAD");
    return NULL; //SNI was not present
}

void main(void)
{
    char HOST[791]="none";
    int parsereturn = 216;
    printf("%s\n",good_data_2);
    parsereturn = parse_tls_header(good_data_2, sizeof(good_data_2), &HOST);
    printf("parse returned %d\n", parsereturn);
    printf("%s\n",HOST);
    strcpy(HOST,get_TLS_SNI(good_data_2, sizeof(good_data_2)));
    printf("HOST is %s\n",HOST);
}