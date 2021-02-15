/*
 *  cxxutils/src/xsock.cpp
 *
 *  This source is part of "libxutils" project
 *  2015-2020  Sun Dro (f4tb0y@protonmail.com)
 *
 * This source includes socket operations such as create,
 * bind, connect, listen, select and etc. Use GCC.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include <netinet/in.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

#ifdef XSOCK_USE_SSL
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#endif

#include "xsock.h"

#define XSOCK_MIN(a,b) (((a)<(b))?(a):(b))

const char* XSock::ErrorStr()
{
    switch(m_nStatus)
    {
        case XSOCK_ERR_NONE:
            return "No error";
        case XSOCK_ERR_BIND:
            return "Can not bind the socket";
        case XSOCK_ERR_JOIN:
            return "Can not join to the socket";
        case XSOCK_ERR_SEND:
            return "Can not send data with the socket";
        case XSOCK_ERR_RECV:
            return "Can not receive data from the socket";
        case XSOCK_ERR_READ:
            return "Can not read data from the socket";
        case XSOCK_ERR_WRITE:
            return "Can not write data fo the socket";
        case XSOCK_ERR_SETFL:
            return "Can not set flags to the socket";
        case XSOCK_ERR_GETFL:
            return "Can not get flags from the socket";
        case XSOCK_ERR_ACCEPT:
            return "Can not accept to the socket";
        case XSOCK_ERR_CONNECT:
            return "Can not connect to the socket";
        case XSOCK_ERR_LISTEN:
            return "Can not listen to the socket";
        case XSOCK_ERR_SETOPT:
            return "Can not set options to the socket";
        case XSOCK_ERR_CREATE:
            return "Can not create the socket";
        case XSOCK_ERR_INVALID:
            return "Socket is not open";
        case XSOCK_ERR_SUPPORT:
            return "Unsupported socket type";
        case XSOCK_ERR_SSLACC:
            return "Can not accept SSL connection";
        case XSOCK_ERR_SSLCNT:
            return "Can not connect SSL server";
        case XSOCK_ERR_NOSSL:
            return "No SSL (OpenSSL) support";
        case XSOCK_ERR_SSLCTX:
            return "Can not create SSL context";
        case XSOCK_ERR_SSLKEY:
            return "Can not set SSL key file";
        case XSOCK_ERR_SSLCRT:
            return "Can not set SSL sert file";
        case XSOCK_ERR_SSLCA:
            return "Can not set SSL CA file";
        case XSOCK_ERR_SSLREAD:
            return "Can not read from SSL socket";
        case XSOCK_ERR_SSLWRITE:
            return "Can not write to SSL socket";
        case XSOCK_FINISH:
            return "Received final packet (FIN)";
        case XSOCK_ERR_OTHER:
            return "Error not because of sockets";
        default:
            break;
    }

    return "Undefined error";
}

bool XSock::IsOpen()
{
    return (m_nFD != XSOCK_INVALID);
}

bool XSock::Check()
{
    if (m_nFD == XSOCK_INVALID)
    {
        if (m_nStatus == XSOCK_ERR_NONE)
            m_nStatus = XSOCK_ERR_INVALID;
        return false;
    }

    m_nStatus = XSOCK_ERR_NONE;
    return true;
}

int XSock::Create(Type eType, int nType, int nProto, int nMax, const char *pAddr, uint16_t nPort)
{
    m_nAddr = htonl(INADDR_ANY);
    m_nProto = nProto;
    m_eType = eType;
    m_nType = nType;
    m_nPort = nPort;

#ifdef XSOCK_USE_SSL
    m_pSSLCtx = NULL;
    m_pSSL = NULL;
#endif

    if (pAddr != NULL)
    {
        struct in_addr addr;
        inet_pton(AF_INET, pAddr, &addr);
        m_nAddr = addr.s_addr;
    }

    m_inAddr.sin_family = AF_INET;
    m_inAddr.sin_port = htons(nPort);
    m_inAddr.sin_addr.s_addr = m_nAddr;
    m_nFdMax = (nMax > 0) ? nMax : XSOCK_FD_MAX;

    m_nFD = socket(AF_INET, m_nType, m_nProto);
    if (m_nFD < 0)
    {
        m_nStatus = XSOCK_ERR_CREATE;
        return XSOCK_INVALID;
    }

    if (m_nType == SOCK_STREAM) SetupTCP();
    else if (m_nType == SOCK_DGRAM) SetupUDP();
    return m_nFD;
}

XSock::XSock(Type eType, const char *pAddr, uint16_t nPort)
{
    /* Handle socket type */
    switch(eType)
    {
        case Type::TCP_CLIENT:
        case Type::TCP_SERVER:
        case Type::SSL_SERVER:
        case Type::SSL_CLIENT:
            m_nType = SOCK_STREAM;
            m_nProto = IPPROTO_TCP;
            break;
        case Type::UDP_BCAST:
        case Type::UDP_MCAST:
        case Type::UDP_UCAST:
            m_nType = SOCK_DGRAM;
            m_nProto = IPPROTO_UDP;
            break;
        case Type::RAW:
            m_nType = SOCK_RAW;
            m_nProto = IPPROTO_TCP;
            break;
        default:
            m_nStatus = XSOCK_ERR_SUPPORT;
            m_nFD = XSOCK_INVALID;
    }

    Create(eType, m_nType, m_nProto, 0, pAddr, nPort);
}

void XSock::Set(int nFd, int nType)
{
#if XSOCK_USE_SSL
    m_pSSL = NULL;
    m_pSSLCtx = NULL;
#endif

    m_nStatus = XSOCK_ERR_NONE;
    m_nType = nType;
    m_nFD = nFd;
}

void XSock::Close()
{
    if (m_bSSL)
    {
 #if XSOCK_USE_SSL
        if (m_pSSL != NULL)
        {
            SSL_shutdown(m_pSSL);
            SSL_free(m_pSSL);
            m_pSSL = NULL;
        }

        if (m_pSSLCtx != NULL)
        {
            SSL_CTX_free(m_pSSLCtx);
            m_pSSLCtx = NULL;
        }
#endif
        m_bSSL = 0;
    }

    if (m_nFD != XSOCK_INVALID)
    {
        shutdown(m_nFD, SHUT_RDWR);
        close(m_nFD);
        m_nFD = XSOCK_INVALID;
    }
}

XSock::XSock(int nFD, int nType)
{
    Set(nFD, nType);
}

XSock::~XSock() 
{
    Close();
}

void XSock::InitSSL()
{
#ifdef XSOCK_USE_SSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_ssl(0, NULL);
#endif
#endif
}

void XSock::DeinitSSL()
{
#ifdef XSOCK_USE_SSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ENGINE_cleanup();
    ERR_free_strings();
#else
    EVP_PBE_cleanup();
#endif
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
#endif
}

int XSock::Recv(void* pData, size_t nSize) 
{
    if (!Check()) return XSOCK_INVALID;
    if (!nSize) return nSize;

    char* pBuff = (char*)pData;
    size_t nDone = 0;

    struct sockaddr_in client;
    socklen_t slen = sizeof(client);

    while(nDone < nSize)
    {
        int nRecvSize, nChunk = XSOCK_MIN(nSize - nDone, XSOCK_RXTX_SIZE);
        if (m_nType != SOCK_DGRAM) nRecvSize = recv(m_nFD, &pBuff[nDone], nChunk, MSG_NOSIGNAL);
        else nRecvSize = recvfrom(m_nFD, &pBuff[nDone], nChunk, 0, (struct sockaddr*)&client, &slen);

        if (nRecvSize <= 0)
        {
            m_nStatus = (nRecvSize < 0) ? XSOCK_ERR_RECV : XSOCK_FINISH;
            Close();
            return nRecvSize;
        }

        nDone += nRecvSize;
    }

    return nDone;
}

int XSock::RecvSimple(void* pData, size_t nSize) 
{
    if (!Check()) return XSOCK_INVALID;
    if (!nSize) return nSize;
    char* pBuff = (char*)pData;

    int nRecvSize = recv(m_nFD, pBuff, nSize, MSG_NOSIGNAL);
    if (nRecvSize <= 0)
    {
        m_nStatus = XSOCK_ERR_RECV;
        Close();
    }

    return nRecvSize;
}

int XSock::Send(void *pData, size_t nLength)
{
    if (!Check()) return XSOCK_INVALID;
    if (!nLength) return nLength;

    char* pBuff =(char*)pData;
    size_t nDone = 0;

    while(nDone < nLength)
    {
        int nSent, nChunk = XSOCK_MIN(nLength - nDone, XSOCK_RXTX_SIZE);
        if (m_nType != SOCK_DGRAM) nSent = send(m_nFD, &pBuff[nDone], nChunk, MSG_NOSIGNAL);
        else nSent = sendto(m_nFD, &pBuff[nDone], nChunk, MSG_NOSIGNAL, (struct sockaddr*)&m_inAddr, sizeof(m_inAddr));

        if (nSent <= 0)
        {
            m_nStatus = XSOCK_ERR_SEND;
            Close();
            return nSent;
        }

        nDone += nSent;
    }

    return nDone;
}

int XSock::SSLRead(void *pData, size_t nSize, bool bExact)
{
    if (!Check()) return XSOCK_INVALID;
    if (!nSize) return nSize;

#ifdef XSOCK_USE_SSL
    uint8_t *pBuff = (uint8_t*)pData;
    size_t nLeft = nSize;
    int nReceived = 0;

    while ((nLeft > 0 && bExact) || !nReceived)
    {
        int nBytes = SSL_read(m_pSSL, &pBuff[nReceived], nLeft);
        if (nBytes <= 0)
        {
            if (SSL_get_error(m_pSSL, nBytes) == SSL_ERROR_WANT_READ) continue;
            m_nStatus = XSOCK_ERR_SSLREAD;
            Close();
            return nBytes;
        }

        nReceived += nBytes;
        nLeft -= nBytes;
    }

    pBuff[nReceived] = 0;
    return nReceived;
#endif

    m_nStatus = XSOCK_ERR_NOSSL;
    Close();
    return XSOCK_INVALID;
}

int XSock::SSLWrite(void *pData, size_t nLength)
{
    if (!Check()) return XSOCK_INVALID;
    if (!nLength) return nLength;

#ifdef XSOCK_USE_SSL
    uint8_t *pBuff = (uint8_t*)pData;
    int nLeft = nLength;
    int nSent = 0;

    while (nLeft > 0)
    {
        int nBytes = SSL_write(m_pSSL, &pBuff[nSent], nLeft);
        if (nBytes <= 0)
        {
            if (SSL_get_error(m_pSSL, nBytes) == SSL_ERROR_WANT_WRITE) continue;
            m_nStatus = XSOCK_ERR_SSLWRITE;
            Close();
            return nBytes;
        }

        nSent += nBytes;
        nLeft -= nBytes;
    }

    return nSent;
#endif

    m_nStatus = XSOCK_ERR_NOSSL;
    Close();
    return XSOCK_INVALID;
}

int XSock::Read(void *pData, size_t nSize)
{
    if (m_bSSL) return SSLRead(pData, nSize, 0);
    if (!Check()) return XSOCK_INVALID;

    if (!nSize) return nSize;
    int nReadSize = 0;

#ifdef EINTR
    do nReadSize = read(m_nFD, pData, nLength);
    while (nReadSize < 0 && errno == EINTR);
#else
    nReadSize = read(m_nFD, pData, nSize);
#endif

    if (nReadSize <= 0)
    {
        m_nStatus = (nReadSize < 0) ? XSOCK_ERR_READ : XSOCK_FINISH;
        Close();
    }

    return nReadSize;
}

int XSock::Write(void *pData, size_t nLength)
{
    if (m_bSSL) return SSLWrite(pData, nLength);
    if (!Check()) return XSOCK_INVALID;
    if (!nLength) return nLength;

    int nBytes = write(m_nFD, pData, nLength);
    if (nBytes < 0)
    {
        m_nStatus = XSOCK_ERR_WRITE;
        Close();
    }

    return nBytes;
}

int XSock::Accept(XSock *pNewSock)
{
    if (!Check()) return XSOCK_INVALID;
    socklen_t len = sizeof(struct sockaddr);

    int nFD = accept(m_nFD, (struct sockaddr*)&pNewSock->m_inAddr, &len);
    if (nFD < 0) 
    {
        m_nStatus = XSOCK_ERR_ACCEPT;
        Close();
    }

#ifdef XSOCK_USE_SSL
    if (m_bSSL && m_pSSLCtx != NULL)
    {
        pNewSock->m_pSSL = SSL_new(m_pSSLCtx);
        pNewSock->m_bSSL = true;

        SSL_set_fd(pNewSock->m_pSSL, nFD);
        if (SSL_accept(pNewSock->m_pSSL) <= 0) 
        {
            if (pNewSock->m_pSSL != NULL)
            {
                SSL_shutdown(pNewSock->m_pSSL);
                SSL_free(pNewSock->m_pSSL);
                pNewSock->m_pSSL = NULL;
                pNewSock->m_bSSL = false;
            }

            m_nStatus = XSOCK_ERR_SSLACC;
            Close();
            return XSOCK_INVALID;
        }
    }
#endif

    pNewSock->Set(nFD, m_nType);
    return nFD;
}

#ifndef DARWIN
int XSock::AcceptNB() 
{
    if (!Check()) return XSOCK_INVALID;
    socklen_t len = sizeof(struct sockaddr);
    m_bNB = 1;

    int nFD = accept4(m_nFD, (struct sockaddr *) &m_inAddr, &len, m_bNB);
    if (nFD < 0) 
    {
        m_nStatus = XSOCK_ERR_ACCEPT;
        m_nFD = XSOCK_INVALID;
        m_bNB = 0;
    }

    return nFD;
}
#endif

int XSock::MsgPeek()
{
    if (!Check()) return XSOCK_INVALID;
    unsigned char buf;
    int nFlags = MSG_PEEK | MSG_DONTWAIT;
    int nByte = recv(m_nFD, &buf, 1, nFlags);
    return nByte < 0 ? 0 : 1;
}

int XSock::NonBlock(int nNonBlock)
{
    if (!Check()) return XSOCK_INVALID;

    /* Get flags */
    int fl = fcntl(m_nFD, F_GETFL);
    if (fl < 0) 
    {
        m_nStatus = XSOCK_ERR_GETFL;
        Close();
        return 0;
    }

    if (nNonBlock) 
    {
        /* Set flag */
        fl = fcntl(m_nFD, F_SETFL, fl | O_NONBLOCK);
        if (fl < 0)
        {
            m_nStatus = XSOCK_ERR_SETFL;
            Close();
            return 0;
        }
    }
    else 
    {
        fl = fcntl(m_nFD, F_SETFL, fl & (~O_NONBLOCK));
        if (fl < 0)
        {
            m_nStatus = XSOCK_ERR_SETFL;
            Close();
            return 0;
        }
    }

    m_bNB = nNonBlock;
    return 1;
}

void XSock::IPStr(const uint32_t nAddr, char *pStr, size_t nSize)
{
    snprintf(pStr, nSize, "%d.%d.%d.%d",
        (int)((nAddr & 0x000000FF)),
        (int)((nAddr & 0x0000FF00)>>8),
        (int)((nAddr & 0x00FF0000)>>16),
        (int)((nAddr & 0xFF000000)>>24));
}

void XSock::SinAddr(const struct in_addr inAddr, char *pAddr, size_t nSize)
{ 
    IPStr(inAddr.s_addr, pAddr, nSize);
}

void XSock::GetIPAddr(char *pAddr, size_t nSize)
{ 
    struct sockaddr_in *pInAddr = &m_inAddr;
    SinAddr(pInAddr->sin_addr, pAddr, nSize);
}

int XSock::AddrInfo(const char *pHost, Info *pInfo)
{
    struct addrinfo hints, *res = NULL;
    void *ptr = NULL;

    memset(&hints, 0, sizeof (hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags |= AI_CANONNAME;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    if (getaddrinfo(pHost, NULL, &hints, &res)) return 0;
    inet_ntop(res->ai_family, res->ai_addr->sa_data, pInfo->sAddr, sizeof(pInfo->sAddr));

    switch (res->ai_family)
    {
        case AF_INET:
            ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
            break;
        case AF_INET6:
            ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
            break;
    }

    inet_ntop(res->ai_family, ptr, pInfo->sAddr, sizeof(pInfo->sAddr));
    strncpy(pInfo->sName, res->ai_canonname, sizeof(pInfo->sName)-1);
    pInfo->nFamily = res->ai_family == PF_INET6 ? 6 : 4;
    freeaddrinfo(res);

    return 1;
}

int XSock::SockAddr(Info *pInfo, struct sockaddr_in *pAddr, size_t nSize)
{
    pInfo->sName[0] = 0;
    pInfo->sAddr[0] = 0;
    pInfo->nFamily = 4;

    struct hostent *hinfo = gethostbyaddr((char*)&pAddr->sin_addr.s_addr, nSize, AF_INET);
    if (hinfo != NULL) snprintf(pInfo->sName, (sizeof(pInfo->sName)-1), "%s", hinfo->h_name);
    IPStr(pAddr->sin_addr.s_addr, pInfo->sAddr, sizeof(pInfo->sAddr));

    return (hinfo != NULL) ? 1 : 0;
}

int XSock::TimeOutR(int nSec, int nUsec)
{
    if (!Check()) return XSOCK_INVALID;
    struct timeval tmout;
    tmout.tv_sec = nSec; 
    tmout.tv_usec = nUsec;

    if (setsockopt(m_nFD, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmout, sizeof(tmout)) < 0)
    {
        m_nStatus = XSOCK_ERR_SETOPT;
        Close();
    }

    return m_nFD;
}

int XSock::TimeOutS(int nSec, int nUsec)
{
    if (!Check()) return XSOCK_INVALID;
    struct timeval tmout;
    tmout.tv_sec = nSec; 
    tmout.tv_usec = nUsec;

    if (setsockopt(m_nFD, SOL_SOCKET, SO_SNDTIMEO, (char*)&tmout, sizeof(tmout)) < 0)
    {
        m_nStatus = XSOCK_ERR_SETOPT;
        Close();
    }

    return m_nFD;
}

int XSock::ReuseAddr(int nEnabled)
{
    if (!Check()) return XSOCK_INVALID;
    unsigned int nOpt = nEnabled;

    if (setsockopt(m_nFD, SOL_SOCKET, SO_REUSEADDR, (char*)&nOpt, sizeof(nOpt)) < 0)
    {
        m_nStatus = XSOCK_ERR_SETOPT;
        Close();
    }

    return m_nFD;
}

int XSock::Linger(int nSec)
{
    if (!Check()) return XSOCK_INVALID;
    struct linger lopt;
    lopt.l_linger = nSec;
    lopt.l_onoff = 1;

    if (setsockopt(m_nFD, SOL_SOCKET, SO_LINGER, (char*)&lopt, sizeof(lopt)) < 0)
    {
        m_nStatus = XSOCK_ERR_SETOPT;
        Close();
    }

    return m_nFD;
}

int XSock::Oobinline(int nEnabled)
{
    if (!Check()) return XSOCK_INVALID;
    int nOpt = nEnabled;

    if (setsockopt(m_nFD, SOL_SOCKET, SO_OOBINLINE, (char*)&nOpt, sizeof nOpt) < 0) 
    {
        m_nStatus = XSOCK_ERR_SETOPT;
        Close();
    }

    return m_nFD;
}

int XSock::NoDelay(int nEnabled)
{
    if (!Check()) return XSOCK_INVALID;
    int nOpt = nEnabled;

    if (setsockopt(m_nFD, IPPROTO_TCP, TCP_NODELAY, (char*)&nOpt, sizeof(nOpt)) < 0)
    {
        m_nStatus = XSOCK_ERR_SETOPT;
        Close();
    }

    return m_nFD;
}

int XSock::AddMembership(const char* pGroup)
{
    if (!Check()) return XSOCK_INVALID;
    int nAddr = htonl(INADDR_ANY);
    if (pGroup != NULL)
    {
        struct in_addr addr;
        inet_pton(AF_INET, pGroup, &addr);
        nAddr = addr.s_addr;
    }

    struct ip_mreq mreq;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    mreq.imr_multiaddr.s_addr = nAddr;

    /* Join to multicast group */
    if (setsockopt(m_nFD, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) < 0)
    {
        m_nStatus = XSOCK_ERR_SETOPT;
        Close();
        return XSOCK_INVALID;
    }

    return m_nFD;
}

int XSock::SetSSLCert(SSLCert *pCert)
{
#ifdef XSOCK_USE_SSL
    SSL_CTX_set_ecdh_auto(m_pSSLCtx, 1);

    if (pCert->nVerifyFlags > 0)
    {
        if (pCert->pCaPath != NULL && SSL_CTX_load_verify_locations(m_pSSLCtx, pCert->pCaPath, NULL) <= 0)
        {
            m_nStatus = XSOCK_ERR_SSLCA;
            Close();
            return XSOCK_INVALID;
        }

        SSL_CTX_set_verify(m_pSSLCtx, pCert->nVerifyFlags, NULL);
        SSL_CTX_set_client_CA_list(m_pSSLCtx, SSL_load_client_CA_file(pCert->pCaPath));
    }

    if (pCert->pCertPath != NULL && SSL_CTX_use_certificate_file(m_pSSLCtx, pCert->pCertPath, SSL_FILETYPE_PEM) <= 0) 
    {
        m_nStatus = XSOCK_ERR_SSLCRT;
        Close();
        return XSOCK_INVALID;
    }

    if (pCert->pKeyPath != NULL && SSL_CTX_use_PrivateKey_file(m_pSSLCtx, pCert->pKeyPath, SSL_FILETYPE_PEM) <= 0) 
    {
        m_nStatus = XSOCK_ERR_SSLKEY;
        Close();
        return XSOCK_INVALID;
    }

    if (pCert->pCaPath != NULL && SSL_CTX_use_certificate_chain_file(m_pSSLCtx, pCert->pCaPath) <= 0)
    {
        m_nStatus = XSOCK_ERR_SSLCA;
        Close();
        return XSOCK_INVALID;
    }

    return m_nFD;
#endif

    m_nStatus = XSOCK_ERR_NOSSL;
    Close();
    return XSOCK_INVALID;
}

int XSock::InitSSLServer()
{
#ifdef XSOCK_USE_SSL
    m_pSSLCtx = SSL_CTX_new(SSLv23_server_method());
    if (m_pSSLCtx == NULL) 
    {
        m_nStatus = XSOCK_ERR_SSLCTX;
        Close();
        return XSOCK_INVALID;
    }

    m_bSSL = 1;
    return m_nFD;
#endif

    m_nStatus = XSOCK_ERR_NOSSL;
    Close();
    return XSOCK_INVALID;
}

int XSock::InitSSLClient()
{
#ifdef XSOCK_USE_SSL
        m_pSSLCtx = SSL_CTX_new(SSLv23_client_method());
        if (m_pSSLCtx == NULL)
        {
            m_nStatus = XSOCK_ERR_SSLCTX;
            Close();
            return XSOCK_INVALID;
        }

        m_pSSL = SSL_new(m_pSSLCtx);
        SSL_set_fd(m_pSSL, m_nFD);
        if (SSL_connect(m_pSSL) < 0)
        {
            m_nStatus = XSOCK_ERR_SSLCNT;
            Close();
            return XSOCK_INVALID;
        }

        m_bSSL = 1;
        return m_nFD;
#endif

    m_nStatus = XSOCK_ERR_NOSSL;
    Close();
    return XSOCK_INVALID;
}

int XSock::SetupTCP() 
{
    if (!Check()) return XSOCK_INVALID;

    if (m_eType == Type::TCP_SERVER ||
        m_eType == Type::SSL_SERVER)
    {
        /* Bind socket */
        if (bind(m_nFD, (struct sockaddr*)&m_inAddr, sizeof(m_inAddr)) < 0)
        {
            m_nStatus = XSOCK_ERR_BIND;
            Close();
            return XSOCK_INVALID;
        }

        /* Listen to socket */
        if (listen(m_nFD, m_nFdMax) < 0) 
        {
            m_nStatus = XSOCK_ERR_LISTEN;
            Close();
            return XSOCK_INVALID;
        }

        if (m_eType == Type::SSL_SERVER) 
            return InitSSLServer();
    }
    else if (m_eType == Type::TCP_CLIENT ||
             m_eType == Type::SSL_CLIENT)
    {
        /* Client socket */
        if (connect(m_nFD, (struct sockaddr *)&m_inAddr, sizeof(m_inAddr)) < 0)
        {
            m_nStatus = XSOCK_ERR_CONNECT;
            Close();
            return XSOCK_INVALID;
        }

        if (m_eType == Type::SSL_CLIENT)
            return InitSSLClient();
    }

    return m_nFD;
}

int XSock::SetupUDP()
{
    if (!Check()) return XSOCK_INVALID;
    int nEnableFlag = 1;

    if (m_eType == Type::UDP_BCAST)
    {
        if (setsockopt(m_nFD, SOL_SOCKET, SO_BROADCAST, (char*)&nEnableFlag, sizeof nEnableFlag) < 0)
        {
            m_nStatus = XSOCK_ERR_SETOPT;
            Close();
            return XSOCK_INVALID;
        }
    }
    else if (m_eType == Type::UDP_MCAST)
    {
        if (setsockopt(m_nFD, SOL_SOCKET, SO_REUSEADDR, (char*)&nEnableFlag, sizeof nEnableFlag) < 0)
        {
            m_nStatus = XSOCK_ERR_SETOPT;
            Close();
            return XSOCK_INVALID;
        }

        if (bind(m_nFD, (struct sockaddr*)&(m_inAddr), sizeof(m_inAddr)) < 0)
        {
            m_nStatus = XSOCK_ERR_BIND;
            Close();
            return XSOCK_INVALID;
        }

        struct ip_mreq mreq;
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        mreq.imr_multiaddr.s_addr = m_nAddr;

        /* Join to multicast group */
        if (setsockopt(m_nFD, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) < 0)
        {
            m_nStatus = XSOCK_ERR_SETOPT;
            Close();
            return XSOCK_INVALID;
        }
    }

    return m_nFD;
}

int XSock::SetupRAW()
{
    m_nStatus = XSOCK_ERR_NONE;
    m_nFD = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (m_nFD < 0) m_nStatus = XSOCK_ERR_CREATE;
    return m_nFD;
}

