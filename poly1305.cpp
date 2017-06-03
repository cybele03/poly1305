//LICENSE
//[MIT](http://www.opensource.org/licenses/mit-license.php) or PUBLIC DOMAIN

#include "poly1305.h"

#if defined(POLY1305_8BIT)
#include "poly1305-8.h"
#elif defined(POLY1305_16BIT)
#include "poly1305-16.h"
#elif defined(POLY1305_32BIT)
#include "poly1305-32.h"
#elif defined(POLY1305_64BIT)
#include "poly1305-64.h"
#else

/* auto detect between 32bit / 64bit */
#define HAS_SIZEOF_INT128_64BIT (defined(__SIZEOF_INT128__) && defined(__LP64__))
#define HAS_MSVC_64BIT (defined(_MSC_VER) && defined(_M_X64))
#define HAS_GCC_4_4_64BIT (defined(__GNUC__) && defined(__LP64__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4))))

#if (HAS_SIZEOF_INT128_64BIT || HAS_MSVC_64BIT || HAS_GCC_4_4_64BIT)
#include "poly1305-64.h"
#else
#include "poly1305-32.h"
#endif

#endif

//
// Poly1305 Constructor
poly1305::poly1305(const unsigned char *key,
                   unsigned int length) : m_ctx() {
    if (length != 32) {
        std::cerr << "In poly1305(), key length must be 32 but is " << length << std::endl;
    }
    else {
	    poly1305_init(&m_ctx, key);
    }
}

//
// Poly1305 Constructor
poly1305::poly1305(unsigned char *ctx) : m_ctx() {
    if (sizeof(ctx) != 144) {
        std::cerr << "In poly1305(), context length must be 144 but is " << sizeof(ctx) << std::endl;
    }
    else {
	    memcpy(&m_ctx, &ctx[0], 144);
    }
}

void poly1305::poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes) {
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	size_t i;

	/* handle leftover */
	if (st->leftover) {
		size_t want = (poly1305_block_size - st->leftover);
		if (want > bytes)
			want = bytes;
		for (i = 0; i < want; i++)
			st->buffer[st->leftover + i] = m[i];
		bytes -= want;
		m += want;
		st->leftover += want;
		if (st->leftover < poly1305_block_size)
			return;
		poly1305_blocks(st, st->buffer, poly1305_block_size);
		st->leftover = 0;
	}

	/* process full blocks */
	if (bytes >= poly1305_block_size) {
		size_t want = (bytes & ~(poly1305_block_size - 1));
		poly1305_blocks(st, m, want);
		m += want;
		bytes -= want;
	}

	/* store leftover */
	if (bytes) {
		for (i = 0; i < bytes; i++)
			st->buffer[st->leftover + i] = m[i];
		st->leftover += bytes;
	}
}

void poly1305::ProcessData(const unsigned char *input, unsigned int length) {
	size_t bytes = length;
	poly1305_update(&m_ctx, input, bytes);
}

void poly1305::context(unsigned char *ctx, unsigned int length) {
    if (length != 144) {
        std::cerr << "In poly1305::result(), length must be 144 but is " << length << std::endl;
    }
    else {
        memcpy(&ctx[0], &m_ctx, length);
    }
}

void poly1305::result(unsigned char *mac, unsigned int length) {
    if (length != 16) {
        std::cerr << "In poly1305::result(), length must be 16 but is " << length << std::endl;
    }
    else {
	    poly1305_finish(&m_ctx, mac);
    }
}
