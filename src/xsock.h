/*
 *  cxxutils/src/xsock.h
 *
 *  This source is part of "libxutils" project
 *  2015-2020  Sun Dro (f4tb0y@protonmail.com)
 *
 * This source includes socket operations such as create,
 * bind, connect, listen, select and etc. Use GCC.
 */

#ifndef __CXXUTILS_XSOCK_H__
#define __CXXUTILS_XSOCK_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifdef _XSOCK_USE_SSL
#define XSOCK_USE_SSL _XSOCK_USE_SSL
#endif

#ifdef XSOCK_USE_SSL
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#endif

/* MacOS Compatibility */
#ifdef DARWIN
#include <fcntl.h>
#define MSG_NOSIGNAL SO_NOSIGPIPE
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#include <string>

/* Socket errors */
#define XSOCK_ERR_NONE      0
#define XSOCK_ERR_BIND      1
#define XSOCK_ERR_JOIN      2
#define XSOCK_ERR_SEND      3
#define XSOCK_ERR_RECV      4
#define XSOCK_ERR_READ      5
#define XSOCK_ERR_WRITE     6
#define XSOCK_ERR_SETFL     7
#define XSOCK_ERR_GETFL     8
#define XSOCK_ERR_ACCEPT    9
#define XSOCK_ERR_CONNECT   10
#define XSOCK_ERR_LISTEN    11
#define XSOCK_ERR_SETOPT    12
#define XSOCK_ERR_INVALID   13
#define XSOCK_ERR_SUPPORT   14
#define XSOCK_ERR_CREATE    15
#define XSOCK_ERR_SSLCNT    16
#define XSOCK_ERR_SSLACC    17
#define XSOCK_ERR_SSLCRT    18
#define XSOCK_ERR_SSLKEY    19
#define XSOCK_ERR_SSLCTX    20
#define XSOCK_ERR_SSLCA     21
#define XSOCK_ERR_NOSSL     22
#define XSOCK_ERR_SSLREAD   23
#define XSOCK_ERR_SSLWRITE  24
#define XSOCK_ERR_OTHER     25

#define XSOCK_FINISH        30
#define XSOCK_INVALID       -1
#define XSOCK_SUCCESS       XSOCK_ERR_NONE

/* Limits */
#define XSOCK_RXTX_SIZE     1024 * 32
#define XSOCK_INFO_MAX      256
#define XSOCK_FD_MAX        120000

/* X Socket */
class XSock 
{
public:
    /* Supported socket types */
    enum class Type
    {
        UNSET = 0,
        TCP_CLIENT,
        TCP_SERVER,
        SSL_CLIENT,
        SSL_SERVER,
        UDP_MCAST,
        UDP_BCAST,
        UDP_UCAST,
        RAW,
    };

    typedef struct 
    {
        std::string sAddr;
        std::string sName;
        int nFamily = 0; // 4: IPv4, 6: IPv6
    } Info;

    typedef struct 
    {
        int nVerifyFlags = 0;
        const char *pCertPath = nullptr;
        const char *pKeyPath = nullptr;
        const char *pCaPath = nullptr;
    } SSLCert;

    static void InitSSL();
    static void DeinitSSL();

    static void IPStr(const uint32_t nAddr, char *pStr, size_t nSize);
    static void SinAddr(const struct in_addr inAddr, char *pAddr, size_t nSize);
    static int SockAddr(XSock::Info *pInfo, struct sockaddr_in *pAddr, size_t nSize);
    static int AddrInfo(const char *pHost, XSock::Info *pInfo);

    XSock(XSock::Type eType, const char *pAddr, uint16_t nPort);
    XSock(int nFD, int nType);
    ~XSock();

    int Create(XSock::Type eType, int nType, int nProto, int nMax, const char *pAddr, uint16_t nPort);
    void Close();

    void Set(int nFd, int nType);
    int SetupTCP();
    int SetupUDP();
    int SetupRAW();

    int SetSSLCert(XSock::SSLCert *pCert);
    int InitSSLClient();
    int InitSSLServer();

    const char* ErrorStr();
    bool Check();
    bool IsOpen();
    int MsgPeek();
    void GetIPAddr(char *pAddr, size_t nSize);

    int Send(void *pData, size_t nLength);
    int Recv(void *pData, size_t nSize);
    int Read(void *pData, size_t nSize);
    int Write(void *pData, size_t nLength);
    int RecvSimple(void *pData, size_t nSize);

    int SSLRead(void *pData, size_t nSize, bool nExact);
    int SSLWrite(void *pData, size_t nLength);

    int Accept(XSock *pNewSock);
    int AcceptNB();

    int AddMembership(const char* pGroup);
    int TimeOutR(int nSec, int nUsec);
    int TimeOutS(int nSec, int nUsec);
    int ReuseAddr(int nEnabled);
    int Oobinline(int nEnabled);
    int NonBlock(int nNonBlock);
    int NoDelay(int nEnabled);
    int Linger(int nSec);

private:
    XSock::Type m_eType = Type::UNSET;
    struct sockaddr_in m_inAddr;

    uint32_t m_nAddr = 0;
    uint16_t m_nPort = 0;

    int m_nStatus = XSOCK_ERR_NONE;
    int m_nFdMax = 0;
    int m_nProto = 0;
    int m_nType = 0;
    int m_nFD = -1;

    bool m_bSSL = false;
    bool m_bNB = false;

#ifdef XSOCK_USE_SSL
    SSL_CTX *m_pSSLCtx = NULL;
    SSL *m_pSSL = NULL;
#endif
};

#endif /* __CXXUTILS_XSOCK_H__ */
