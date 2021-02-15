/*
 *  cxxutils/src/xsha256.h
 * 
 *  Copyleft (C) 2020  Sun Dro (f4tb0y@protonmail.com)
 *  SHA-256 computing implementation for C++ based on
 *  pseudocode for the SHA-256 algorithm from Wikipedia.
 */

#ifndef __XSHA256_H__
#define __XSHA256_H__

#include <stdio.h>
#include <stdint.h>
  
#define XSHA256_BLOCK_SIZE       64
#define XSHA256_DIGEST_SIZE      32

class XSHA256 
{
public:
    XSHA256();
    ~XSHA256(){};

    void Compute(const uint8_t *pData, size_t nLength, uint8_t *pDigest);
    void Update(const uint8_t *pData, size_t nLength);
    void FinalRaw(uint8_t *pDigest);
    void Final(uint8_t *pDigest);
    void ProcessBlock();

protected:
    const static uint32_t m_k[];
    const static uint8_t m_padding[];

private:
    size_t m_nTotalSize;
    size_t m_nSize;

    union
    {
       uint32_t m_h[8];
       uint8_t m_digest[32];
    };

    union
    {
       uint32_t m_w[16];
       uint8_t m_block[64];
    };
};

#endif /* __XSHA256_H__ */