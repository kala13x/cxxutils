/*
 *  cxxutils/src/xsha256.cpp
 * 
 *  Copyleft (C) 2020  Sun Dro (f4tb0y@protonmail.com)
 *  SHA-256 computing implementation for C++ based on
 *  pseudocode for the SHA-256 algorithm from Wikipedia.
 */

#include <endian.h>
#include <cstring>
#include <algorithm>
#include "xsha256.h"

#define XSHA_UPPER(x) w[(x) & 0x0F]
#define XSHA_CH(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define XSHA_MAJ(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define XSHA_ROR32(x, n) ((x >> n) | (x << ((sizeof(x) << 3) - n)))

#define XSHA_SIGMA1(x) (XSHA_ROR32(x, 2) ^ XSHA_ROR32(x, 13) ^ XSHA_ROR32(x, 22))
#define XSHA_SIGMA2(x) (XSHA_ROR32(x, 6) ^ XSHA_ROR32(x, 11) ^ XSHA_ROR32(x, 25))
#define XSHA_SIGMA3(x) (XSHA_ROR32(x, 7) ^ XSHA_ROR32(x, 18) ^ (x >> 3))
#define XSHA_SIGMA4(x) (XSHA_ROR32(x, 17) ^ XSHA_ROR32(x, 19) ^ (x >> 10))

const uint8_t XSHA256::m_padding[64] =
{
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const uint32_t XSHA256::m_k[64] =
{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

XSHA256::XSHA256()
{
    m_nSize = m_nTotalSize = 0;
	m_h[0] = 0x6A09E667;
	m_h[1] = 0xBB67AE85;
	m_h[2] = 0x3C6EF372;
	m_h[3] = 0xA54FF53A;
	m_h[4] = 0x510E527F;
	m_h[5] = 0x9B05688C;
	m_h[6] = 0x1F83D9AB;
	m_h[7] = 0x5BE0CD19;
}

void XSHA256::Compute(const uint8_t *pData, size_t nLength, uint8_t *pDigest)
{
    Update(pData, nLength);
    Final(pDigest);
}

void XSHA256::Update(const uint8_t *pData, size_t nLength)
{
    while(nLength > 0)
    {
        size_t nPart = std::min(nLength, XSHA256_BLOCK_SIZE - m_nSize);
        memcpy(m_block + m_nSize, pData, nPart);

        m_nSize += nPart;
        m_nTotalSize += nPart;
        pData = pData + nPart;
        nLength -= nPart;

        if (m_nSize == XSHA256_BLOCK_SIZE)
        {
            ProcessBlock();
            m_nSize = 0;
        }
    }
}

void XSHA256::Final(uint8_t *pDigest)
{
    size_t nPaddingSize = (m_nSize < 56) ? (56 - m_nSize) : (120 - m_nSize);
    size_t nTotalSize = m_nTotalSize * 8;

    Update(m_padding, nPaddingSize);
    m_w[14] = htobe32((uint32_t) (nTotalSize >> 32));
    m_w[15] = htobe32((uint32_t) nTotalSize);
    ProcessBlock();

    for (uint i = 0; i < 8; i++) m_h[i] = htobe32(m_h[i]);
    if (pDigest != NULL) memcpy(pDigest, m_digest, XSHA256_DIGEST_SIZE);
}

void XSHA256::FinalRaw(uint8_t *pDigest)
{
    for (uint i = 0; i < 8; i++) m_h[i] = htobe32(m_h[i]);
    memcpy(pDigest, m_digest, XSHA256_DIGEST_SIZE);
    for (uint i = 0; i < 8; i++) m_h[i] = be32toh(m_h[i]);
}

void XSHA256::ProcessBlock()
{
    uint32_t nReg[8];
    uint32_t *w = m_w;

    for (uint i = 0; i < 8; i++) nReg[i] = m_h[i];
    for (uint i = 0; i < 16; i++) w[i] = be32toh(w[i]);

    for (uint i = 0; i < 64; i++)
    {
        if (i >= 16) XSHA_UPPER(i) += XSHA_SIGMA4(XSHA_UPPER(i + 14)) + XSHA_UPPER(i + 9) + XSHA_SIGMA3(XSHA_UPPER(i + 1));
        uint32_t nT1 = nReg[7] + XSHA_SIGMA2(nReg[4]) + XSHA_CH(nReg[4], nReg[5], nReg[6]) + m_k[i] + XSHA_UPPER(i);
        uint32_t nT2 = XSHA_SIGMA1(nReg[0]) + XSHA_MAJ(nReg[0], nReg[1], nReg[2]);

        nReg[7] = nReg[6];
        nReg[6] = nReg[5];
        nReg[5] = nReg[4];
        nReg[4] = nReg[3] + nT1;
        nReg[3] = nReg[2];
        nReg[2] = nReg[1];
        nReg[1] = nReg[0];
        nReg[0] = nT1 + nT2;
    }

    for (uint i = 0; i < 8; i++) 
        m_h[i] += nReg[i];
}
