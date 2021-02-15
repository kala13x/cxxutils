/*
 *  cxxutils/src/xssl.cpp
 * 
 *  Copyleft (C) 2020  Sun Dro (f4tb0y@protonmail.com)
 *  OpenSSL server/client implementation for C++
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <slog.h>

#include <netinet/in.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <openssl/opensslv.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <string>
#include "xssl.h"

void XSSL_GlobalInit(int nVerbose)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_ssl(0, NULL);
#endif
    slog_init("XSSL", nVerbose, 1);
}

void XSSL_GlobalDestroy()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ENGINE_cleanup();
    ERR_free_strings();
#else
    EVP_PBE_cleanup();
#endif
    slog_destroy();
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

bool XSSL::Read(uint8_t *pBuffer, int nSize)
{
    if (m_pSSL == nullptr) return false;

    int nReceived = 0;
    int nLeft = nSize;

    while (nLeft > 0)
    {	
        int nBytes = SSL_read(m_pSSL, &pBuffer[nReceived], nLeft);
        if (nBytes <= 0 && SSL_get_error(m_pSSL, nBytes) != SSL_ERROR_WANT_READ)
        {
            slog_error("SSL_read failed: (%d) %s", nBytes, GetError().c_str());
            Shutdown();
            return false;
        }

        nReceived += nBytes;
        nLeft -= nBytes;
    }

    pBuffer[nReceived] = 0;
    return true;
}

bool XSSL::Write(uint8_t *pBuffer, int nLength)
{
    if (m_pSSL == nullptr) return false;

    int nSent = 0;
    int nLeft = nLength;

    while (nLeft > 0)
    {
        int nBytes = SSL_write(m_pSSL, &pBuffer[nSent], nLeft);
        if (nBytes <= 0 && SSL_get_error(m_pSSL, nBytes) != SSL_ERROR_WANT_WRITE)
        {
            slog_error("SSL_write failed: (%d) %s", nBytes, GetError().c_str());
            Shutdown();
            return false;
        }

        nSent += nBytes;
        nLeft -= nBytes;
    }

    return true;
}

std::string XSSL::GetError()
{	
    BIO *pBIO = BIO_new(BIO_s_mem());
    ERR_print_errors(pBIO);

    char *pErrBuff = NULL;
    size_t nLen = BIO_get_mem_data(pBIO, &pErrBuff);
    if (!nLen) return std::string("No SSL error");

    std::string sError = std::string("\n");
    sError.append(pErrBuff, nLen - 1);

    BIO_free(pBIO);
    return sError;
}

bool XSSL::LoadPKCS12(const char *p12Path, const char *p12Pass)
{
    FILE *p12File = fopen(p12Path, "rb");
    if (p12File == NULL)
    {
        slog_error("Can not open PKCS12 file: %s (%d)", p12Path, errno);
        return false;
    }

    PKCS12 *p12 = d2i_PKCS12_fp(p12File, NULL);
    fclose(p12File);

    if (p12 == NULL)
    {
        slog_error("Can not load PKCS12 file: %s", GetError().c_str());
        return false;
    }

    if (!PKCS12_parse(p12, p12Pass, &m_pKey, &m_pCert, &m_pCa))
    {
        slog_error("Can not parse PKCS12 file: %s", GetError().c_str());
        PKCS12_free(p12);
        return false;
    }

    PKCS12_free(p12);
    return true;
}

bool XSSL::InitServer(const char *pAddr, uint16_t nPort, XSSLCert *pCert)
{
    m_nSock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (m_nSock < 0)
    {
        slog_error("Can not create TCP socket for SSL listener: %d", errno);
        Shutdown();
        return false;
    }

    long nReuse = 1;
    if (setsockopt(m_nSock, SOL_SOCKET, SO_REUSEADDR, (char*) &nReuse, sizeof(nReuse)) < 0)
    {
        slog_error("Set socket option SO_REUSEADDR failed on SSL socket: %d", errno);
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
        slog_error("SSL socket bind error - Port: %d, Bind: %d", (uint32_t) nPort, errno);
        Shutdown();
        return false;
    }

    if (listen(m_nSock, SOMAXCONN) < 0)
    {
        slog_error("SSL socket listen error - Port: %d, Listen: %d", (uint32_t) nPort, errno);
        Shutdown();
        return false;
    }

    m_pSSLCtx = SSL_CTX_new(SSLv23_server_method());
    if (m_pSSLCtx == NULL)
    {
        slog_error("Can not create server SSL context: %s", GetError().c_str());
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
            slog_error("Can not load root ca file(%s): %s", pCert->pCAPath, GetError().c_str());
            Shutdown();
            return false;
        }

        SSL_CTX_set_client_CA_list(m_pSSLCtx, SSL_load_client_CA_file(pCert->pCAPath));
    }

    if (pCert->p12Path != NULL)
    {
        if (!LoadPKCS12(pCert->p12Path, pCert->p12Pass))
        {
            slog_error("Failed to setup PKCS12 file: %s", pCert->p12Path);
            Shutdown();
            return false;
        }

        if (SSL_CTX_use_certificate(m_pSSLCtx, m_pCert) <= 0 ||
            SSL_CTX_use_PrivateKey(m_pSSLCtx, m_pKey) <= 0)
        {
            slog_error("Failed to setup SSL cert/key: %s", GetError().c_str());
            Shutdown();
            return false;
        }
    }
    else if (pCert->pCertPath != NULL && pCert->pKeyPath != NULL)
    {
        if (SSL_CTX_use_certificate_file(m_pSSLCtx, pCert->pCertPath, SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(m_pSSLCtx, pCert->pKeyPath, SSL_FILETYPE_PEM) <= 0)
        {
            slog_error("Failed to setup SSL cert/key: %s", GetError().c_str());
            Shutdown();
            return false;
        }
    }

    return true;
}

bool XSSL::InitClient(const char *pAddr, uint16_t nPort, XSSLCert *pCert)
{
    m_nSock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (m_nSock < 0)
    {
        slog_error("Can not create TCP socket for SSL connection: %d", errno);
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
        slog_error("Can not connect to the SSL (TCP) socket: %d", errno);
        Shutdown();
        return false;
    }

    m_pSSLCtx = SSL_CTX_new(SSLv23_client_method());
    if (m_pSSLCtx == NULL)
    {
        slog_error("Can not create client SSL context: %s", GetError().c_str());
        Shutdown();
        return false;
    }

    if (pCert != NULL)
    {
        if (pCert->p12Path != NULL)
        {
            if (!LoadPKCS12(pCert->p12Path, pCert->p12Pass))
            {
                slog_error("Failed to setup PKCS12 file: %s", pCert->p12Path);
                Shutdown();
                return false;
            }

            if (SSL_CTX_use_cert_and_key(m_pSSLCtx, m_pCert, m_pKey, m_pCa, 1) != 1)
            {
                slog_error("Failed to setup SSL cert/key: %s", GetError().c_str());
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
                slog_error("Failed to setup SSL cert/key: %s", GetError().c_str());
                Shutdown();
                return false;
            }
        }
    }

    m_pSSL = SSL_new(m_pSSLCtx);
    if (m_pSSL == NULL)
    {
        slog_error("Can not create client SSL: %s", GetError().c_str());
        Shutdown();
        return false;
    }

    SSL_set_fd(m_pSSL, m_nSock);
    if (SSL_connect(m_pSSL) < 0)
    {
        slog_error("SSL_connect failed: %s", GetError().c_str());
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
        slog_error("Can not accept to the SSL (TCP) socket: %d", errno);
        delete pClientSSL;
        return nullptr;;
    }

    pClientSSL->SetSSL(SSL_new(m_pSSLCtx));
    pClientSSL->SetFD(nSock);

    if (SSL_accept(pClientSSL->GetSSL()) <= 0) 
    {
        slog_error("SSL_accept failed: %s", GetError().c_str());
        delete pClientSSL;
        return nullptr;
    }

    char sPeerAddr[64];
    inet_ntop(AF_INET, &inAddr.sin_addr, sPeerAddr, sizeof(sPeerAddr));
    slog_info("Accepted SSL peer: addr(%s), sock(%d)", sPeerAddr, nSock);

    return pClientSSL;
}

bool XSSL::CheckCertificate()
{
    X509 *pCert = SSL_get_peer_certificate(m_pSSL);
    if (pCert == nullptr)
    {
        slog_warn("No SSL certificates configured");
        return false;
    }

    char *pLine = X509_NAME_oneline(X509_get_subject_name(pCert), 0, 0);
    slog_info("Certificate subject: %s", pLine);
    delete pLine;

    pLine = X509_NAME_oneline(X509_get_issuer_name(pCert), 0, 0);
    slog_info("Certificate issuer: %s", pLine);
    delete pLine;

    X509_free(pCert);
    return true;
}
