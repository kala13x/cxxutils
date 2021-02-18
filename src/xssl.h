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
    struct Cert 
    {
        int nVerifyFlags = SSL_VERIFY_PEER;
        const char *pCertPath = nullptr;
        const char *pKeyPath = nullptr;
        const char *pCAPath = nullptr;
        const char *p12Path = nullptr;
        const char *p12Pass = nullptr;
    };

    enum class Type 
    {
        undef = 0,
        server,
        client
    };

    static void GlobalInit();
    static void GlobalDestroy();

    XSSL() {};
    ~XSSL() { Shutdown(); }

    XSSL(XSSL::Type eType, const char *pAddr, uint16_t nPort, XSSL::Cert *pCert);
    bool InitServer(const char *pAddr, uint16_t nPort, XSSL::Cert *pCert);
    bool InitClient(const char *pAddr, uint16_t nPort, XSSL::Cert *pCert);

    bool LoadPKCS12(const char *p12Path, const char *p12Pass);
    bool GetPeerCert(std::string &sSubject, std::string &sIssuer);

    int Read(uint8_t *pBuffer, int nSize, bool bExact);
    int Write(const uint8_t *pBuffer, int nLength);

    XSSL* Accept();
    void Shutdown();

    SSL* GetSSL() { return m_pSSL; }
    void SetSSL(SSL *pSSL) { m_pSSL = pSSL; }
    void SetFD(int nFD) { SSL_set_fd(m_pSSL, nFD); m_nSock = nFD; }
    int GetFD() { return m_nSock; }

    std::string GetLastError();
    std::string GetSSLError();

protected:
    std::string m_sError;
    SSL_CTX *m_pSSLCtx = nullptr;
    SSL *m_pSSL = nullptr;
    int m_nSock = -1;

    STACK_OF(X509) *m_pCa = nullptr;
    EVP_PKEY *m_pKey = nullptr;
    X509 *m_pCert = nullptr;
};

#endif /* __CXXUTILS_XSSL_H__ */