/*
 *  cxxutils/src/xssl.cpp
 * 
 *  Copyleft (C) 2020  Sun Dro (f4tb0y@protonmail.com)
 *  OpenSSL server/client implementation for C++
 */

#include "xssl.h"
#include <string.h>

#include <netinet/in.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <openssl/opensslv.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void XSSL::GlobalInit()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_ssl(0, NULL);
#endif
}

void XSSL::GlobalDestroy()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ENGINE_cleanup();
    ERR_free_strings();
#else
    EVP_PBE_cleanup();
#endif
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}

void XSSL::Shutdown()
{
    if (m_pSSL)
    {
        SSL_shutdown(m_pSSL);
        SSL_free(m_pSSL);
        m_pSSL = nullptr;
    }

    if (m_pSSLCtx)
    {
        SSL_CTX_free(m_pSSLCtx);
        m_pSSLCtx = nullptr;
    }

    if (m_nSock >= 0)
    {
        close(m_nSock);
        m_nSock = -1;
    }
}

int XSSL::Read(uint8_t *pBuffer, int nSize, bool bExact)
{
    if (m_pSSL == nullptr) return false;

    int nReceived = 0;
    int nLeft = nSize;

    while ((nLeft > 0 && bExact) || !nReceived)
    {	
        int nBytes = SSL_read(m_pSSL, &pBuffer[nReceived], nLeft);
        if (nBytes <= 0 && SSL_get_error(m_pSSL, nBytes) != SSL_ERROR_WANT_READ)
        {
            m_sError = "SSL_read failed (" + std::to_string(nBytes) + ")";
            Shutdown();
            return nBytes;
        }

        nReceived += nBytes;
        nLeft -= nBytes;
    }

    pBuffer[nReceived] = 0;
    return nReceived;
}

int XSSL::Write(const uint8_t *pBuffer, int nLength)
{
    if (m_pSSL == nullptr) return false;

    int nSent = 0;
    int nLeft = nLength;

    while (nLeft > 0)
    {
        int nBytes = SSL_write(m_pSSL, &pBuffer[nSent], nLeft);
        if (nBytes <= 0 && SSL_get_error(m_pSSL, nBytes) != SSL_ERROR_WANT_WRITE)
        {
            m_sError = "SSL_write failed (" + std::to_string(nBytes) + ")";
            Shutdown();
            return nBytes;
        }

        nSent += nBytes;
        nLeft -= nBytes;
    }

    return nSent;
}

std::string XSSL::GetSSLError()
{	
    BIO *pBIO = BIO_new(BIO_s_mem());
    ERR_print_errors(pBIO);

    char *pErrBuff = NULL;
    size_t nLen = BIO_get_mem_data(pBIO, &pErrBuff);
    if (!nLen) return std::string(strerror(errno));

    std::string sError = std::string("\n");
    sError.append(pErrBuff, nLen - 1);

    BIO_free(pBIO);
    return sError;
}

std::string XSSL::GetLastError()
{
    std::string sError = m_sError;
    sError.append(": " + GetSSLError());
    return sError;
}

bool XSSL::LoadPKCS12(const char *p12Path, const char *p12Pass)
{
    FILE *p12File = fopen(p12Path, "rb");
    if (p12File == NULL)
    {
        m_sError = "Can not open PKCS12 file";
        return false;
    }

    PKCS12 *p12 = d2i_PKCS12_fp(p12File, NULL);
    fclose(p12File);

    if (p12 == NULL)
    {
        m_sError = "Can not open PKCS12 file";
        return false;
    }

    if (!PKCS12_parse(p12, p12Pass, &m_pKey, &m_pCert, &m_pCa))
    {
        m_sError = "Can not parse PKCS12 file";
        PKCS12_free(p12);
        return false;
    }

    PKCS12_free(p12);
    return true;
}

XSSL::XSSL(XSSL::Type eType, const char *pAddr, uint16_t nPort, XSSL::Cert *pCert)
{
    if (eType == XSSL::Type::client) InitClient(pAddr, nPort, pCert);
    else if (eType == XSSL::Type::server) InitServer(pAddr, nPort, pCert);
    else m_sError = "Undefined SSL type, must be client or server";
}

bool XSSL::InitServer(const char *pAddr, uint16_t nPort, XSSL::Cert *pCert)
{
    m_nSock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (m_nSock < 0)
    {
        m_sError = "Can not create TCP socket for SSL listener";
        Shutdown();
        return false;
    }

    long nReuse = 1;
    if (setsockopt(m_nSock, SOL_SOCKET, SO_REUSEADDR, (char*) &nReuse, sizeof(nReuse)) < 0)
    {
        m_sError = "Set socket option SO_REUSEADDR failed on SSL socket";
        Shutdown();
        return false;
    }

    struct in_addr addr;
    inet_pton(AF_INET, pAddr, &addr);

    struct sockaddr_in inAddr;
    inAddr.sin_family = AF_INET;
    inAddr.sin_port = htons(nPort);
    inAddr.sin_addr.s_addr = addr.s_addr;

    if (bind(m_nSock, (sockaddr*) &inAddr, sizeof(inAddr)) < 0)
    {
        m_sError = "Can not bind the socket";
        Shutdown();
        return false;
    }

    if (listen(m_nSock, SOMAXCONN) < 0)
    {
        m_sError = "Can not listen to the socket";
        Shutdown();
        return false;
    }

    m_pSSLCtx = SSL_CTX_new(SSLv23_server_method());
    if (m_pSSLCtx == NULL)
    {
        m_sError = "Can not create server SSL contect";
        Shutdown();
        return false;
    }

    SSL_CTX_set_ecdh_auto(m_pSSLCtx, 1);
    if (pCert == NULL) return true; 

    /* Note: The client must send it's certificate */
    SSL_CTX_set_verify(m_pSSLCtx, pCert->nVerifyFlags, NULL);

    if (pCert->pCAPath != NULL)
    {
        /* Note: Tell the client what certificates to use for certificate verification */
        if (SSL_CTX_load_verify_locations(m_pSSLCtx, pCert->pCAPath, NULL) <= 0)
        {
            m_sError = "Can not load root ca file (" + std::string(pCert->pCAPath) + ")";
            Shutdown();
            return false;
        }

        SSL_CTX_set_client_CA_list(m_pSSLCtx, SSL_load_client_CA_file(pCert->pCAPath));
    }

    if (pCert->p12Path != NULL)
    {
        if (!LoadPKCS12(pCert->p12Path, pCert->p12Pass))
        {
            m_sError = "Failed to setup PKCS12 file (" + std::string(pCert->p12Path) + ")";
            Shutdown();
            return false;
        }

        if (SSL_CTX_use_certificate(m_pSSLCtx, m_pCert) <= 0 ||
            SSL_CTX_use_PrivateKey(m_pSSLCtx, m_pKey) <= 0)
        {
            m_sError = "Failed to setup SSL cert/key";
            Shutdown();
            return false;
        }
    }
    else if (pCert->pCertPath != NULL && pCert->pKeyPath != NULL)
    {
        if (SSL_CTX_use_certificate_file(m_pSSLCtx, pCert->pCertPath, SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(m_pSSLCtx, pCert->pKeyPath, SSL_FILETYPE_PEM) <= 0)
        {
            m_sError = "Failed to setup SSL cert/key";
            Shutdown();
            return false;
        }
    }

    return true;
}

bool XSSL::InitClient(const char *pAddr, uint16_t nPort, XSSL::Cert *pCert)
{
    m_nSock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (m_nSock < 0)
    {
        m_sError = "Can not create TCP socket for SSL connection";
        Shutdown();
        return false;
    }

    struct in_addr addr;
    inet_pton(AF_INET, pAddr, &addr);

    struct sockaddr_in inAddr;
    inAddr.sin_family = AF_INET;
    inAddr.sin_port = htons(nPort);
    inAddr.sin_addr.s_addr = addr.s_addr;

    if (connect(m_nSock, (struct sockaddr *)&inAddr, sizeof(inAddr)) < 0)
    {
        m_sError = "Can not connect to the SSL (TCP) socket";
        Shutdown();
        return false;
    }

    m_pSSLCtx = SSL_CTX_new(SSLv23_client_method());
    if (m_pSSLCtx == NULL)
    {
        m_sError = "Can not create client SSL context";
        Shutdown();
        return false;
    }

    if (pCert != NULL)
    {
        if (pCert->p12Path != NULL)
        {
            if (!LoadPKCS12(pCert->p12Path, pCert->p12Pass))
            {
                m_sError = "Failed to setup PKCS12 file (" + std::string(pCert->p12Path) + ")";
                Shutdown();
                return false;
            }

            if (SSL_CTX_use_cert_and_key(m_pSSLCtx, m_pCert, m_pKey, m_pCa, 1) != 1)
            {
                m_sError = "Failed to setup SSL cert/key";
                Shutdown();
                return false;
            }
        }
        else if (pCert->pCertPath != NULL && pCert->pKeyPath != NULL && pCert->pCAPath != NULL)
        {
            if (SSL_CTX_use_certificate_file(m_pSSLCtx, pCert->pCertPath, SSL_FILETYPE_PEM) <= 0 ||
                SSL_CTX_use_PrivateKey_file(m_pSSLCtx, pCert->pKeyPath, SSL_FILETYPE_PEM) <= 0 ||
                SSL_CTX_use_certificate_chain_file(m_pSSLCtx, pCert->pCAPath) <= 0)
            {
                m_sError = "Failed to setup SSL cert/key";
                Shutdown();
                return false;
            }
        }
    }

    m_pSSL = SSL_new(m_pSSLCtx);
    if (m_pSSL == NULL)
    {
        m_sError = "Can not create client SSL";
        Shutdown();
        return false;
    }

    SSL_set_fd(m_pSSL, m_nSock);
    if (SSL_connect(m_pSSL) < 0)
    {
        m_sError = "SSL_connect failed";
        Shutdown();
        return false;
    }

    return true;
}

XSSL* XSSL::Accept()
{
    XSSL *pClientSSL = new XSSL;
    struct sockaddr_in inAddr;
    socklen_t len = sizeof(inAddr);

    int nSock = accept(m_nSock, (struct sockaddr*)&inAddr, &len);
    if (nSock < 0)
    {
        m_sError = "Can not accept to the SSL (TCP) socket";
        delete pClientSSL;
        return nullptr;;
    }

    pClientSSL->SetSSL(SSL_new(m_pSSLCtx));
    pClientSSL->SetFD(nSock);

    if (SSL_accept(pClientSSL->GetSSL()) <= 0) 
    {
        m_sError = "SSL_accept failed";
        delete pClientSSL;
        return nullptr;
    }

    char sPeerAddr[64];
    inet_ntop(AF_INET, &inAddr.sin_addr, sPeerAddr, sizeof(sPeerAddr));

    return pClientSSL;
}

bool XSSL::GetPeerCert(std::string &sSubject, std::string &sIssuer)
{
    X509 *pCert = SSL_get_peer_certificate(m_pSSL);
    if (pCert == nullptr) return false;

    char *pLine = X509_NAME_oneline(X509_get_subject_name(pCert), 0, 0);
    sSubject = std::string(pLine);
    delete pLine;

    pLine = X509_NAME_oneline(X509_get_issuer_name(pCert), 0, 0);
    sIssuer = std::string(pLine);
    delete pLine;

    X509_free(pCert);
    return true;
}
