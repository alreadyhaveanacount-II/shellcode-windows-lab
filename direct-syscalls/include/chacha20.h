typedef unsigned int uint32_t __attribute__((mode(SI)));
typedef unsigned int uint8_t __attribute__((mode(QI)));

#define ROL(x, by) ((x << by) | (x >> (32-by)))
#define ROR(x, by) ((x >> by) | (x << (32-by)))

typedef struct {
    uint32_t state[16];
} ChaCha20;

void quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = ROL(*d, 16);
    *c += *d; *b ^= *c; *b = ROL(*b, 12);
    *a += *b; *d ^= *a; *d = ROL(*d, 8);
    *c += *d; *b ^= *c; *b = ROL(*b, 7);
}


ChaCha20 new_chacha(uint32_t key[8], uint32_t nonce[3]) {
    ChaCha20 instance;
    
    instance.state[0] = 0x61707865;
    instance.state[1] = 0x3320646e;
    instance.state[2] = 0x79622d32;
    instance.state[3] = 0x6b206574;

    for (size_t i = 0; i < 8; ++i) {
        instance.state[4 + i] = key[i];
    }

    instance.state[12] = 0;

    for (size_t i = 0; i < 3; ++i) {
        instance.state[13 + i] = nonce[i];
    }

    return instance;
}

void blockFunction(uint32_t out[16], ChaCha20* curr_state) {
    uint32_t curr_block[16];

    for(int i=0; i<16; i++) curr_block[i] = curr_state->state[i];

    for (int i = 0; i < 10; ++i) {
        quarter_round(&curr_block[0], &curr_block[4], &curr_block[8], &curr_block[12]);
        quarter_round(&curr_block[1], &curr_block[5], &curr_block[9], &curr_block[13]);
        quarter_round(&curr_block[2], &curr_block[6], &curr_block[10], &curr_block[14]);
        quarter_round(&curr_block[3], &curr_block[7], &curr_block[11], &curr_block[15]);
        quarter_round(&curr_block[0], &curr_block[5], &curr_block[10], &curr_block[15]);
        quarter_round(&curr_block[1], &curr_block[6], &curr_block[11], &curr_block[12]);
        quarter_round(&curr_block[2], &curr_block[7], &curr_block[8], &curr_block[13]);
        quarter_round(&curr_block[3], &curr_block[4], &curr_block[9], &curr_block[14]);
    }

    for(int i=0; i<16; i++) {
        out[i] = curr_block[i] + curr_state->state[i];
    }

    curr_state->state[12]++;
}

void process_chacha20(ChaCha20* state, uint8_t* data, size_t size) {
    uint32_t keystream_32[16];
    uint8_t* keystream_8 = (uint8_t*)keystream_32;

    while (size > 0) {
        blockFunction(keystream_32, state);

        size_t block_size = (size > 64) ? 64 : size;

        for (size_t i = 0; i < block_size; i++) {
            data[i] ^= keystream_8[i];
        }

        data += block_size;
        size -= block_size;
    }
}
