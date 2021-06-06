/*
 *  cxxutils/src/xevent.cpp
 * 
 *  Copyleft (C) 2020  Sun Dro (f4tb0y@protonmail.com)
 *  Implementation of async event engine based on EPOLL
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "xevent.h"

XEvents::~XEvents()
{
    if (m_nEventFd >= 0)
    {
        close(m_nEventFd);
        m_nEventFd = -1;
    }

    if (m_pEventArray != NULL)
    {
        free(m_pEventArray);
        m_pEventArray = NULL;
    }

    m_eventCallback(this, NULL, XEVENT_DESTROY);
}

const char* XEvents::GetLastError()
{
    switch(m_eStatus)
    {
        case Status::ECTL:
            return "Failed to call epoll_ctl()";
        case Status::EWAIT:
            return "Failed to call epoll_wait()";
        case Status::ENOCB:
            return "Servise callback is not set up";
        case Status::EOMAX:
            return "Unable to detect max file descriptors";
        case Status::EALLOC:
            return "Can not allocate memory for event array";
        case Status::ECREATE:
            return "Can not create epoll event instance";
        case Status::SUCCESS:
            return "Success";
        default:
            break;
    }

    return "Undefined";
}

bool XEvents::Create(size_t nMax, void *pUser, XEventCallback callBack)
{
    if (callBack == NULL)
    {
        m_eStatus = Status::ENOCB;
        return false;
    }

    /* Init callback related data */
    m_eventCallback = callBack;
    m_pUserSpace = pUser;

    /* Get max allowed file descriptors by the system */
    uint32_t nSysMax = sysconf(_SC_OPEN_MAX);
    if (nSysMax <= 0)
    {
        m_eStatus = Status::EOMAX;
        return false;
    }

    /* Validate max number of events and allocate event array */
    m_nEventMax = (nMax || nMax < nSysMax) ? nMax : nSysMax;
    m_pEventArray = (struct epoll_event*)calloc(m_nEventMax, sizeof(struct epoll_event));

    /* Failed to allocate memory */
    if (m_pEventArray == NULL)
    {
        m_eStatus = Status::EALLOC;
        return false;
    }

    /* Create epoll event instance */
    m_nEventFd = epoll_create1(0);

    /* Failed to create epoll */
    if (m_nEventFd < 0)
    {
        free(m_pEventArray);
        m_pEventArray = NULL;
        m_eStatus = Status::ECREATE;
        return false;
    }

    m_eStatus = Status::SUCCESS;
    return true;
}

void XEvents::ServiceCallback(XEventData *pData)
{
    /* Check error condition */
    if (pData->events & EPOLLRDHUP) { m_eventCallback(this, pData, XEVENT_CLOSED); return; }
    if (pData->events & EPOLLHUP) { m_eventCallback(this, pData, XEVENT_HUNGED); return; }
    if (pData->events & EPOLLERR) { m_eventCallback(this, pData, XEVENT_ERROR); return; }
    if (pData->events & EPOLLPRI) { m_eventCallback(this, pData, XEVENT_EXCEPTION); return; }

    /* Callback on writeable */
    if (pData->events & EPOLLOUT && m_eventCallback(this, pData, XEVENT_WRITE) < 0)
        { m_eventCallback(this, pData, XEVENT_USER); return; } // User requested callback

    /* Callback on readable */
    if (pData->events & EPOLLIN && m_eventCallback(this, pData, XEVENT_READ) < 0)
        { m_eventCallback(this, pData, XEVENT_USER); return; } // User requested callback
}

void XEvents::ClearCallback(XEventData *pEvData)
{
    if (pEvData != NULL)
    {
        m_eventCallback(this, pEvData, XEVENT_CLEAR);
        free(pEvData);
    }
}

XEventData* XEvents::Register(void *pCtx, int nFd, int nEvents, int nType)
{
    /* Allocate memory for event data */
    XEventData* pData = (XEventData*)malloc(sizeof(XEventData));
    if (pData == NULL)
    {
        m_eStatus = Status::EALLOC;
        return NULL;
    }

    /* Initialize event */
    pData->events = 0;
    pData->type = nType;
    pData->ptr = pCtx;
    pData->fd = nFd;

    /* Add event to the instance */
    if (!this->Add(pData, nEvents))
    {
        free(pData);
        return NULL;
    }

    m_eStatus = Status::SUCCESS;
    return pData;
}

bool XEvents::Add(XEventData *pData, int nEvents)
{
    struct epoll_event event;
    event.data.ptr = pData;
    event.events = nEvents;

    if (epoll_ctl(m_nEventFd, EPOLL_CTL_ADD, pData->fd, &event) < 0)
    {
        m_eStatus = Status::ECTL;
        return false;
    }

    m_eStatus = Status::SUCCESS;
    return true;
}

bool XEvents::Modify(XEventData *pData, int nEvents)
{
    struct epoll_event event;
    event.data.ptr = pData;
    event.events = nEvents;

    if (epoll_ctl(m_nEventFd, EPOLL_CTL_MOD, pData->fd, &event) < 0)
    {
        m_eStatus = Status::ECTL;
        return false;
    }

    m_eStatus = Status::SUCCESS;
    return true;
}

bool XEvents::Delete(XEventData *pData)
{
    if (pData->fd >= 0 && epoll_ctl(m_nEventFd, EPOLL_CTL_DEL, pData->fd, NULL) < 0)
    {
        m_eStatus = Status::ECTL;
        return false;
    }

    this->ClearCallback(pData);
    m_eStatus = Status::SUCCESS;
    return true;
}

bool XEvents::Service(int nTimeoutMs)
{
    int nCount; /* Wait for ready events */
    do nCount = epoll_wait(m_nEventFd, m_pEventArray, m_nEventMax, nTimeoutMs);
    while (errno == EINTR);

    if (nCount < 0)
    {
        m_eStatus = Status::EWAIT;
        return false;
    }

    for (int i = 0; i < nCount; i++)
    {
        XEventData *pData = (XEventData*)m_pEventArray[i].data.ptr;
        pData->events = m_pEventArray[i].events;
        this->ServiceCallback(pData);
    }

    m_eStatus = Status::SUCCESS;
    return true;
}