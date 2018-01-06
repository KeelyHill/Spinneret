#include <Python.h>


/************Start this guy's chacha*************/

// #pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

struct Chacha20Block {
    // This is basically a random number generator seeded with key and nonce.
    // Generates 64 random bytes every time count is incremented.

    uint32_t state[16];

    static uint32_t rotl32(uint32_t x, int n){
        return (x << n) | (x >> (32 - n));
    }

    static uint32_t pack4(const uint8_t *a){
        return
            uint32_t(a[0] << 0*8) |
            uint32_t(a[1] << 1*8) |
            uint32_t(a[2] << 2*8) |
            uint32_t(a[3] << 3*8);
    }

    static void unpack4(uint32_t src, uint8_t *dst){
        dst[0] = (src >> 0*8) & 0xff;
        dst[1] = (src >> 1*8) & 0xff;
        dst[2] = (src >> 2*8) & 0xff;
        dst[3] = (src >> 3*8) & 0xff;
    }

    Chacha20Block(const uint8_t key[32], const uint8_t nonce[8]){
        const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";
        state[ 0] = pack4(magic_constant + 0*4);
        state[ 1] = pack4(magic_constant + 1*4);
        state[ 2] = pack4(magic_constant + 2*4);
        state[ 3] = pack4(magic_constant + 3*4);
        state[ 4] = pack4(key + 0*4);
        state[ 5] = pack4(key + 1*4);
        state[ 6] = pack4(key + 2*4);
        state[ 7] = pack4(key + 3*4);
        state[ 8] = pack4(key + 4*4);
        state[ 9] = pack4(key + 5*4);
        state[10] = pack4(key + 6*4);
        state[11] = pack4(key + 7*4);
        // 64 bit counter initialized to zero by default.
        state[12] = 0;
        state[13] = 0;
        state[14] = pack4(nonce + 0*4);
        state[15] = pack4(nonce + 1*4);
    }

    void set_counter(uint64_t counter){
        // Want to process many blocks in parallel?
        // No problem! Just set the counter to the block you want to process.
        state[12] = uint32_t(counter);
        state[13] = counter >> 32;
    }

    void next(uint32_t result[16]){
        // This is where the crazy voodoo magic happens.
        // Mix the bytes a lot and hope that nobody finds out how to undo it.
        for (int i = 0; i < 16; i++) result[i] = state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);

        for (int i = 0; i < 10; i++){
            CHACHA20_QUARTERROUND(result, 0, 4, 8, 12)
            CHACHA20_QUARTERROUND(result, 1, 5, 9, 13)
            CHACHA20_QUARTERROUND(result, 2, 6, 10, 14)
            CHACHA20_QUARTERROUND(result, 3, 7, 11, 15)
            CHACHA20_QUARTERROUND(result, 0, 5, 10, 15)
            CHACHA20_QUARTERROUND(result, 1, 6, 11, 12)
            CHACHA20_QUARTERROUND(result, 2, 7, 8, 13)
            CHACHA20_QUARTERROUND(result, 3, 4, 9, 14)
        }

        for (int i = 0; i < 16; i++) result[i] += state[i];

        uint32_t *counter = state + 12;
        // increment counter
        counter[0]++;
        if (0 == counter[0]){
            // wrap around occured, increment higher 32 bits of counter
            counter[1]++;
            // Limited to 2^64 blocks of 64 bytes each.
            // If you want to process more than 1180591620717411303424 bytes
            // you have other problems.
            // We could keep counting with counter[2] and counter[3] (nonce),
            // but then we risk reusing the nonce which is very bad.
            assert(0 != counter[1]);
        }
    }
};

struct Chacha20 {
    // XORs plaintext/encrypted bytes with whatever Chacha20Block generates.
    // Encryption and decryption are the same operation.
    // Chacha20Blocks can be skipped, so this can be done in parallel.
    // If keys are reused, messages can be decrypted.
    // Known encrypted text with known position can be tampered with.
    // See https://en.wikipedia.org/wiki/Stream_cipher_attack

    Chacha20Block block;
    uint32_t keystream32[16];
    size_t position;

    Chacha20(
        const uint8_t key[32],
        const uint8_t nonce[8],
        uint64_t counter = 0
    ): block(key, nonce), position(64){
        block.set_counter(counter);
    }

    void crypt(uint8_t *bytes, size_t n_bytes){
        uint8_t *keystream8 = (uint8_t*)keystream32;
        for (size_t i = 0; i < n_bytes; i++){
            if (position >= 64){
                block.next(keystream32);
                position = 0;
            }
            bytes[i] ^= keystream8[position];
            position++;
        }
    }
};

/*************End other guy's chacha*****************/

size_t
strlen(const char *str)
{
    const char *s;
    for (s = str; *s; ++s);
    return(s - str);
}

/** ChaCha uses the same opperation for encytion and decryption.

Use: pass in the message/cypher, the 8 byte nonce, and 32 byte key.
>>> chacha20.crypt(messaeg, nonce, key)

Nonces should only be use ONCE.

*/
static PyObject * chacha_crypt(PyObject *self, PyObject *args) {

    uint8_t *m;
    size_t *m_len;

    const uint8_t *nonce;
    size_t *nl;

    const uint8_t *key;
    size_t kl;

    if (!PyArg_ParseTuple(args, "y#y#y#", &m, &m_len, &nonce, &nl, &key, &kl))
        return NULL;

    // printf("m_len = %lu\n", (size_t)m_len);

    Chacha20 cc = Chacha20((const uint8_t *)key, nonce);
    cc.crypt((uint8_t *)m, (size_t)m_len);

    return Py_BuildValue("y#", m, m_len);
    // TODO figure out if some kind of memoerty management is a thing before the return.
}


static PyObject * chacha_foobar(PyObject *self, PyObject *args) {
    char bytes[] = "Hello world";

    // return PyLong_FromLong(42);
    return Py_BuildValue("y", bytes);
}


static PyMethodDef ChaChaMethods[] = {
    {"foobar",  chacha_foobar, METH_VARARGS, "A foo bar test."},
    {"crypt",  chacha_crypt, METH_VARARGS, "'Crypts a thing. Encryption and decryption are same operation.'"},

    {NULL, NULL, 0, NULL} /* Sentinel */
};




static struct PyModuleDef chacha20module = {
    PyModuleDef_HEAD_INIT,
    "_chacha20",   /* name of module */
    NULL, /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                or -1 if the module keeps state in global variables. */
    ChaChaMethods
};

PyMODINIT_FUNC PyInit__chacha20(void) {
    return PyModule_Create(&chacha20module);
}
