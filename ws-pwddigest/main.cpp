/* ------------------------
 * Digest creator
 *
 * By Gustavo Campos@Ericsson
 * -----------------------
 */



#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <stdlib.h>


#include <ctime>



using namespace std;

/*
 SHA-1 in C
 By Steve Reid <steve@edmweb.com>
 100% Public Domain
 
 Reported by Gustavo Campos
 
 Test Vectors (from FIPS PUB 180-1)
 "abc"
 A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
 A million repetitions of "a"
 34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
 */

/* #define LITTLE_ENDIAN * This should be #define'd already, if true. */
/* #define SHA1HANDSOFF * Copies data before messing with it. */

#define SHA1HANDSOFF

#include <stdio.h>
#include <string.h>

/* for uint32_t */
#include <stdint.h>

/*
 SHA-1 in C
 By Steve Reid <steve@edmweb.com>
 100% Public Domain
 */

#include "stdint.h"

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;


#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
|(rol(block->l[i],8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(
                   uint32_t state[5],
                   const unsigned char buffer[64]
                   )
{
    uint32_t a, b, c, d, e;
    
    typedef union
    {
        unsigned char c[64];
        uint32_t l[16];
    } CHAR64LONG16;
    
#ifdef SHA1HANDSOFF
    CHAR64LONG16 block[1];      /* use array to appear as a pointer */
    
    memcpy(block, buffer, 64);
#else
    /* The following had better never be used because it causes the
     * pointer-to-const buffer to be cast into a pointer to non-const.
     * And the result is written through.  I threw a "const" in, hoping
     * this will cause a diagnostic.
     */
    CHAR64LONG16 *block = (const CHAR64LONG16 *) buffer;
#endif
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
#ifdef SHA1HANDSOFF
    memset(block, '\0', sizeof(block));
#endif
}


/* SHA1Init - Initialize new context */

void SHA1Init(
              SHA1_CTX * context
              )
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(
                SHA1_CTX * context,
                const unsigned char *data,
                uint32_t len
                )
{
    uint32_t i;
    
    uint32_t j;
    
    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
        context->count[1]++;
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if ((j + len) > 63)
    {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64)
        {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else
        i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void SHA1Final(
               unsigned char digest[20],
               SHA1_CTX * context
               )
{
    unsigned i;
    
    unsigned char finalcount[8];
    
    unsigned char c;
    
#if 0    /* untested "improvement" by DHR */
    /* Convert context->count to a sequence of bytes
     * in finalcount.  Second element first, but
     * big-endian order within element.
     * But we do it all backwards.
     */
    unsigned char *fcp = &finalcount[8];
    
    for (i = 0; i < 2; i++)
    {
        uint32_t t = context->count[i];
        
        int j;
        
        for (j = 0; j < 4; t >>= 8, j++)
            *--fcp = (unsigned char) t}
#else
    for (i = 0; i < 8; i++)
    {
        finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);      /* Endian independent */
    }
#endif
    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448)
    {
        c = 0000;
        SHA1Update(context, &c, 1);
    }
    SHA1Update(context, finalcount, 8); /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++)
    {
        digest[i] = (unsigned char)
        ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
    /* Wipe variables */
    memset(context, '\0', sizeof(*context));
    memset(&finalcount, '\0', sizeof(finalcount));
}

void SHA1(char *hash_out, const char *str, size_t len)
{
    SHA1_CTX ctx;
    unsigned int ii;
    
    SHA1Init(&ctx);
    for (ii=0; ii<len; ii+=1)
        SHA1Update(&ctx, (const unsigned char*)str + ii, 1);
    SHA1Final((unsigned char *)hash_out, &ctx);
    hash_out[20] = '\0';
}



string getSHA1(const string strValue)
{
    char pszReturn [21];
    
    SHA1 (pszReturn, strValue.c_str(), strValue.length());
    
    return string (pszReturn, sizeof (pszReturn)-1);
}


/* crc_tab[] -- this crcTable is being build by chksum_crc32GenTab().
 *        so make sure, you call it before using the other
 *        functions!
 */
uint32_t crc_tab[256];


/* chksum_crc() -- to a given block, this one calculates the
 *                crc32-checksum until the length is
 *                reached. the crc32-checksum will be
 *                the result.
 */
uint32_t Util_CRC32 (const uint8_t *block, size_t length, uint32_t crc_start)
{
    uint32_t crc;
    uint32_t i;
    static bool bTable = false;
    
    if (bTable == false)
    {
        uint32_t crc, poly;
        int i, j;
        
        poly = 0xEDB88320L;
        for (i = 0; i < 256; i++)
        {
            crc = i;
            for (j = 8; j > 0; j--)
            {
                if (crc & 1)
                {
                    crc = (crc >> 1) ^ poly;
                }
                else
                {
                    crc >>= 1;
                }
            }
            crc_tab[i] = crc;
        }
    }
    
    
    crc = crc_start == 0 ? 0xFFFFFFFF : crc_start;
    
    for (i = 0; i < length; i++)
    {
        crc = ((crc >> 8) & 0x00FFFFFF) ^ crc_tab[(crc ^ *block++) & 0xFF];
    }
    return (crc ^ 0xFFFFFFFF);
}



void UTil_PrintDataToDebug (const uint8_t* szSectionData, long int nDataLen)
{
    size_t nCount;
    size_t nCount1;
    size_t nLen;
    char szPData [20];
    
    printf ("%s : Total Visualizing: [%-8lu]\n", __FUNCTION__, nDataLen);
    printf ("%s :       ADDRESS       00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15  [    DATA  RAW   ]\n", __FUNCTION__);
    printf ("%s : ------------------- |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  -------------------\n", __FUNCTION__);
    
    for (nCount=0; nCount < nDataLen; nCount = nCount + 16)
    {
        nLen = nCount + 16 > nDataLen ? nDataLen - nCount : 16;
        
        printf ("%s : Addr: [%-.10lu] ", __FUNCTION__, nCount);
        for (nCount1=0; nCount1 < 16; nCount1++)
        {
            if (nCount1 + nCount < nDataLen)
            {
                printf ("%-.2X ", (uint8_t) szSectionData [nCount + nCount1]);
                szPData [nCount1] = szSectionData [nCount + nCount1] < 32 || szSectionData [nCount + nCount1] >= 127 || szSectionData [nCount + nCount1] == '>' || szSectionData [nCount + nCount1] == '<' ? '.' : szSectionData [nCount + nCount1];
            }
            else
            {
                printf (".. "); szPData [nCount1] = '.';
            }
            
        }
        
        szPData [nCount1] = '\0';
        
        printf ("  [%s]\n", szPData);
    }
    
    printf ("CHECKSUM  [%X-%X]\n", Util_CRC32 (szSectionData, nDataLen, 0xFFFF), Util_CRC32 (szSectionData, nDataLen, 0x0));
    
    fflush (stdout);
}




static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'};

static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


string base64_encode(const unsigned char *data,
                      size_t input_length,
                      size_t& output_length) {
    
    output_length = 4 * ((input_length + 2) / 3);
    
    char* encoded_data = (char*) malloc(output_length);
    if (encoded_data == NULL) return NULL;
    
    for (int i = 0, j = 0; i < input_length;) {
        
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
        
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        
        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }
    
    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';
    
    string strReturn (encoded_data, output_length);
    
    free (encoded_data);
    
    return strReturn;
}



void build_decoding_table()
{
    
    decoding_table = (char*) malloc(256);
    
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_cleanup()
{
    free(decoding_table);
}



string base64_decode(const char *data,
                             size_t input_length,
                             size_t& output_length) {
    
    if (decoding_table == NULL) build_decoding_table();
    
    if (input_length % 4 != 0) return NULL;
    
    output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (output_length)--;
    if (data[input_length - 2] == '=') (output_length)--;
    
    unsigned char decoded_data [output_length];
    
    for (int i = 0, j = 0; i < input_length;) {
        
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        
        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);
        
        if (j < output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
    
    return string ((const char*) decoded_data, output_length);
}



string getNonce ()
{
    
    //int nCount = 0;
    char shArray [16];
    
    timespec ts = { 0, 0};
    //clock_gettime(CLOCK_MONOTONIC, &ts); // Works on FreeBSD
    clock_gettime(CLOCK_REALTIME, &ts); // Works on Linux
    
    srand ((unsigned int) (time (NULL) * (ts.tv_sec & ts.tv_nsec)));
    
    int nRand = 0;
    double nRndFactor;
    for (size_t nCount=0; nCount < (sizeof (shArray) / sizeof (char)); nCount++)
    {
        //nRand++;
        nRand = rand();
        nRndFactor = (double) nRand / RAND_MAX;
        
        shArray [nCount] = (int) ((double) nRndFactor * 256);
        
        printf (" *** Rand [%d] max: [%d] VAL> [%f] clock: [%lu]\n", nRand, RAND_MAX, nRndFactor, ts.tv_sec & ts.tv_nsec);
    }
    
    //memcpy(shArray, "12345678901234567890", sizeof (shArray)); //Used for testing only. please Keep it commented.
    
    UTil_PrintDataToDebug ((uint8_t*) shArray, sizeof (shArray));
    
    string strValue (shArray, sizeof (shArray));
    string strRandonSha1 = getSHA1(strValue);
    
    UTil_PrintDataToDebug ((uint8_t*) strRandonSha1.c_str(), strRandonSha1.length());
    
    size_t nBase64len = 0;
    
    string strBase64Nonce  = base64_encode ((const unsigned char*)strRandonSha1.c_str (), strRandonSha1.length(), nBase64len);
    
    string strNonce (strBase64Nonce.c_str(), strBase64Nonce.length() );
    
    printf ("Generated NONCE = [%s]\n", strNonce.c_str ());
    
    return strNonce;
}




int main (int nArgs, char** ppszArgs)
{
    
    
    
    clock ();
    
    if (nArgs != 3)
    {
        printf ("Use: \"UTC Date\" and \"Password\" nArgs [%d]\n", nArgs);
        exit (1);
    }
    
    string* strUTCDate = new string((char*) ppszArgs [1]);
    string* strPasswd  = new string((char*) ppszArgs [2]);
    
    printf ("Creating digest for: [%s]@[%s]\n", strUTCDate->c_str(), strPasswd->c_str());
    
    
    string strNonce = getNonce ();
    
    printf ("NONCE> [%s][%lu]\n\n", strNonce.c_str(), strNonce.length());
    
    size_t nDecoded64Len = 0;
    string strNonceBin = base64_decode (strNonce.c_str(), strNonce.length(), nDecoded64Len);
    
    printf ("Decoded--------------------------------------Deconded Len: [%lu]\n", nDecoded64Len);
    UTil_PrintDataToDebug ((uint8_t*) strNonceBin.c_str(), strNonceBin.length());
    
    string strPlainDigest (strNonceBin);
    
    strPlainDigest.append (*strUTCDate);
    strPlainDigest.append (*strPasswd);
    
    
    printf ("PRE-DIGEST-------------------------------------- Len: [%lu]\n", strPlainDigest.length());
    UTil_PrintDataToDebug ((uint8_t*) strPlainDigest.c_str(), strPlainDigest.length());
    
    string strDigestSHA1 = getSHA1 (strPlainDigest);
    
    
    
    printf ("PRE-DIGEST-SHA1--------------------------------- Len: [%lu]\n", strDigestSHA1.length());
    UTil_PrintDataToDebug ((uint8_t*) strDigestSHA1.c_str(), strDigestSHA1.length());
    
    
    size_t nLen;
    string strPasswdDigest = base64_encode ((const unsigned char*) strDigestSHA1.c_str(), (size_t) strDigestSHA1.length(), nLen);
    
    printf ("PRE-DIGEST-PWD--------------------------------- Len: [%lu]\n", strPasswdDigest.length());
    UTil_PrintDataToDebug ((uint8_t*) strPasswdDigest.c_str(), strPasswdDigest.length());
    
    
    printf ("***;%s;%s\n", strNonce.c_str(), strPasswdDigest.c_str());
    
    
    return 0;
}

