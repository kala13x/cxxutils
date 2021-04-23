/*
 *  cxxutils/src/xevent.h
 * 
 *  Copyleft (C) 2020  Sun Dro (f4tb0y@protonmail.com)
 *  Implementation of async event engine based on EPOLL
 */

#ifndef __CXXUTILS_XEVENT_H__
#define __CXXUTILS_XEVENT_H__

#include <sys/epoll.h>
#include <stdint.h>

#define XEVENT_ERROR             1
#define XEVENT_USER              2
#define XEVENT_READ              3
#define XEVENT_WRITE             4
#define XEVENT_HUNGED            5
#define XEVENT_CLOSED            6
#define XEVENT_CLEAR             7
#define XEVENT_DESTROY           8
#define XEVENT_EXCEPTION         9

typedef struct XEventData_ {
    void *ptr;      // Data pointer
    int events;     // Ready events
    int type;       // Event type
    int fd;         // Socket descriptor
} XEventData;

typedef int(*XEventCallback)(void *events, void* data, int reason);

class XEvents
{
public:
    ~XEvents();

    enum Status {
        NONE = 0,
        ECTL,
        EWAIT,
        ENOCB,
        EOMAX,
        EALLOC,
        ECREATE,
        SUCCESS
    };

    bool Create(size_t nMax, void *pUser, XEventCallback callBack);
    XEventData* Register(void *pCtx, int nFd, int nEvents, int nType);

    bool Add(XEventData* pData, int nEvents);
    bool Modify(XEventData *pData, int nEvents);
    bool Delete(XEventData *pData);
    bool Service(int nTimeoutMs);

    void ServiceCallback(XEventData *pData);
    void ClearCallback(XEventData *pEvData);

    const char* GetLastError();
    void *GetsUserData() { return m_pUserSpace; }

private:
    XEventCallback          m_eventCallback = NULL;  /* Service callback */
    struct epoll_event*     m_pEventArray = NULL;    /* EPOLL event array */
    void*                   m_pUserSpace = NULL;     /* User space pointer */
    uint32_t                m_nEventMax = 0;         /* Max allowed file descriptors */
    int                     m_nEventFd = -1;         /* EPOLL File decriptor */
    Status                  m_eStatus = NONE;        /* Status of the last call */
};

#endif /* __CXXUTILS_XEVENT_H__ */