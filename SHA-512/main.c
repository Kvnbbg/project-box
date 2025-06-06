#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define ROTR(x, n) ((x >> n) | (x << (64 - n)))
#define Ch(x, y, z) ((x & y) ^ ((~x) & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define Sigma1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define sigma0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ (x >> 7))
#define sigma1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ (x >> 6))

uint64_t k[] = 
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};


uint64_t H[] = 
{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};


uint64_t W[80];
void sha512_compress(uint64_t *state, const uint8_t *block) 
{
    int t;
    uint64_t temp1, temp2, maj, ch;

    for (t = 0; t < 16; t++) 
	{
        W[t] = ((uint64_t)block[t * 8] << 56) | ((uint64_t)block[t * 8 + 1] << 48) |
               ((uint64_t)block[t * 8 + 2] << 40) | ((uint64_t)block[t * 8 + 3] << 32) |
               ((uint64_t)block[t * 8 + 4] << 24) | ((uint64_t)block[t * 8 + 5] << 16) |
               ((uint64_t)block[t * 8 + 6] << 8) | ((uint64_t)block[t * 8 + 7]);
    }

    for (t = 16; t < 80; t++)
	{
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    uint64_t a = state[0];
    uint64_t b = state[1];
    uint64_t c = state[2];
    uint64_t d = state[3];
    uint64_t e = state[4];
    uint64_t f = state[5];
    uint64_t g = state[6];
    uint64_t h = state[7];

    for (t = 0; t < 80; t++) 
	{
        temp1 = h + Sigma1(e) + Ch(e, f, g) + k[t] + W[t];
        temp2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha512(const char *message, int round) 
{
    uint8_t block[128];
    uint64_t bitlen = strlen(message) * 8;
    uint64_t state[8];
    int i, len, offset;

    for (i = 0; i < 8; i++) 
	{
        state[i] = H[i];
    }

    len = strlen(message);
    offset = 0;

    while (offset < len) 
	{
        int block_size = (len - offset < 128) ? len - offset : 128; 
        memset(block, 0, 128);
        memcpy(block, message + offset, block_size);

        if (block_size < 128) 
		{
            block[block_size] = 0x80;
            if (block_size < 112) 
			{
                for (i = 0; i < 8; i++)
				{
                    block[112 + i] = (bitlen >> ((7 - i) * 8)) & 0xFF;
                }
            }
        }

        sha512_compress(state, block);
        offset += block_size;
    }

    printf("values for round %d:\n", round);
    for (i = 0; i < round; i++) 
	{
        printf("H[%d] = %016lx\n", i, state[i]);
    }
    printf("Final hash value:\n");
    for (i = 0; i < round; i++) 
	{
        printf("%016lx", state[i]);
    }
    printf("\n");
}


int main() {
    char message[1024];
    int round;

    printf("Enter the text: ");
    fgets(message, sizeof(message), stdin);
    
    message[strcspn(message, "\n")] = '\0'; 

    printf("Enter the round number: ");
    scanf("%d", &round);

    if (round < 0 || round >= 80) 
	{
        printf("Invalid round number. It should be in the range [0, 79].\n");
        return 1; 
    }

    sha512(message, round);

    return 0;
}