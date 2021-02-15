/*
 *  cxxutils/src/xssl.h
 * 
 *  Copyleft (C) 2020  Sun Dro (f4tb0y@protonmail.com)
 * 
 *  OpenSSL server/client implementation for C++
 */

#ifndef __CXXUTILS_XSSL_H__
#define __CXXUTILS_XSSL_H__

#include <stdio.h>
#include <unistd.h>
#include <string>

#include <openssl/x509.h>
#include <openssl/ssl.h>

class XSSL
{
public:
    XSSL()
    {
        m_pSSLCtx = nullptr;
        m_pSSL = nullptr;
        m_pCert = nullptr;
        m_pKey = nullptr;
        m_pCa = nullptr;
        m_nSock = -1;
    }

    ~XSSL()
    {
        Shutdown(); 
    }

    struct XSSLCert {
        int nVerifyFlags = SSL_VERIFY_PEER;
        const char *pCertPath = nullptr;
        const char *pKeyPath = nullptr;
        const char *pCAPath = nullptr;
        const char *p12Path = nullptr;
        const char *p12Pass = nullptr;
    };

    bool InitServer(const char *pAddr, uint16_t nPort, XSSLCert *pCert);
    bool InitClient(const char *pAddr, uint16_t nPort, XSSLCert *pCert);

    bool LoadPKCS12(const char *p12Path, const char *p12Pass);
    bool CheckCertificate();

    bool Read(uint8_t *pBuffer, int nSize);
    bool Write(uint8_t *pBuffer, int nLength);

    std::string GetError();
    XSSL* Accept();
    void Shutdown();

    inline SSL* GetSSL() { return m_pSSL; }
    inline void SetSSL(SSL *pSSL) { m_pSSL = pSSL; }
    inline void SetFD(int nFD) { SSL_set_fd(m_pSSL, nFD); m_nSock = nFD; }
    inline int GetFD() { return m_nSock; }

protected:
    SSL_CTX *m_pSSLCtx;
    SSL *m_pSSL;
    int m_nSock;

    STACK_OF(X509) *m_pCa;
    EVP_PKEY *m_pKey;
    X509 *m_pCert;
};

void XSSL_GlobalInit(int nVerbose);
void XSSL_GlobalDestroy();

#endif /* __CXXUTILS_XSSL_H__ */