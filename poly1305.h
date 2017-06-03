#ifndef POLY1305_H
#define POLY1305_H
#define POLY1305_64BIT
#include <stddef.h>
#include <iostream>
#include <cstring>

///
///\class poly1305 poly1305.h "include/poly1305.h"
///
/// See the license at:
/// 
/// * [MIT](http://www.opensource.org/licenses/mit-license.php) or PUBLIC DOMAIN
///
/// <center>Protocol++ Written by : John Peter Greninger &bull; June 26, 2016 &bull; &copy; John Peter Greninger 2015-2016</center>
/// <center><sub>All copyrights and trademarks are the property of their respective owners</sub></center>
///

class poly1305 {

    public:
    
        ////////////////////////////////////////////////////////
        /// Constructor for POLY1305 algorithm
        /// @param key - initialization key
        /// @param length - length of the key in bytes (32)
    	////////////////////////////////////////////////////////
        poly1305(const unsigned char *key, unsigned int length);
    
        ////////////////////////////////////////////////////////
        /// Constructor for POLY1305 algorithm with context
        /// @param ctx - context from previous session
    	////////////////////////////////////////////////////////
        poly1305(unsigned char *ctx);
    
    	////////////////////////////////////////////////////////
    	/// Standard Deconstructor for POLY1305 algorithm
    	////////////////////////////////////////////////////////
        virtual ~poly1305() {}
    
    	////////////////////////////////////////////////////////
    	/// Calculates the MAC using POLY1305
    	/// @param input - data to hash
    	/// @param length - length of the input data
    	////////////////////////////////////////////////////////
        void ProcessData(const unsigned char *input, unsigned int length);
    
    	////////////////////////////////////////////////////////
    	/// Returns the context of POLY1305
    	/// @param ctx - context of the engine
    	/// @param length - length of the context
    	////////////////////////////////////////////////////////
        void context(unsigned char *ctx, unsigned int length=144);
    
    	////////////////////////////////////////////////////////
    	/// Returns the MAC using POLY1305
    	/// @param mac - result of the hash calculation
    	/// @param length - length of the MAC data
    	////////////////////////////////////////////////////////
        void result(unsigned char *mac, unsigned int length=16);
    
    private:
  
        // don't allow these
        poly1305() = delete;
        poly1305(poly1305& rhs) = delete;
        poly1305(const poly1305& rhs) = delete;
    
        typedef struct poly1305_context {
    	    size_t aligner;
    	    unsigned char opaque[136];
        } poly1305_context;
    
    	poly1305_context m_ctx;
    
        void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);
    
        void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);
    
        void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);
};

#endif /* POLY1305_H */
