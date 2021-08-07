#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <thread>

#include "xstats.h"
#include "xlog.h"

#define XSTATS_FILE_SELFSTATUS       "/proc/self/status"
#define XSTATS_FILE_SELFSTAT         "/proc/self/stat"
#define XSTATS_FILE_MEMINFO          "/proc/meminfo"
#define XSTATS_FILE_LOADAVG          "/proc/loadavg"
#define XSTATS_FILE_STAT             "/proc/stat"
#define XSTATS_FILE_MAX              8192

uint32_t XStats::FloatToU32(float fValue)
{
    uint16_t nIntegral = (uint16_t)floor(fValue);
    float fBalance = fValue - (float)nIntegral;
    uint16_t nDecimal = (uint16_t)(fBalance * 100);

    uint32_t nRetVal;
    nRetVal = (uint32_t)nIntegral;
    nRetVal <<= 16;
    nRetVal += (uint32_t)nDecimal;
    return nRetVal;
}

float XStats::U32ToFloat(uint32_t nValue)
{
    uint16_t nIntegral = (uint16_t)(nValue >> 16);
    uint16_t nDecimal = (uint16_t)(nValue & 0xFF);
    float fBalance = (float)nDecimal / (float)100;
    return (float)((float)nIntegral + fBalance);
}

int XStats::LoadFile(const char *pPath, char *pBuffer, size_t nSize)
{
    /* Open target file for reading only */
	int nFD = open(pPath, O_RDONLY, S_IRUSR | S_IRGRP | S_IROTH);
	if (nFD < 0) return 0;

    /* Read whole file buffer from descriptor */
	int nBytes = read(nFD, pBuffer, nSize);
    if (nBytes <= 0)
    {
        close(nFD);
        return 0;
    }

    /* Null terminate buffer */
	pBuffer[nBytes] = '\0';
	close(nFD);

	return nBytes;
}

uint64_t XStats::ParseInfo(char *pBuffer, size_t nSize, const char *pField)
{
    const char *pEnd = pBuffer + nSize;
    char *pOffset = strstr(pBuffer, pField);
    if (pOffset == NULL) return 0;
    pOffset += strlen(pField) + 1;
    if (pOffset >= pEnd) return 0;
    return atoll(pOffset);
}

void XStats::GetMemInfo(XStats::Memory *pMem)
{
    pMem->nResident = __sync_add_and_fetch(&_memory.nResident, 0);
    pMem->nVirt = __sync_add_and_fetch(&_memory.nVirt, 0);
    pMem->nAvail = __sync_add_and_fetch(&_memory.nAvail, 0);
    pMem->nTotal = __sync_add_and_fetch(&_memory.nTotal, 0);
    pMem->nFree = __sync_add_and_fetch(&_memory.nFree, 0);
    pMem->nSwap = __sync_add_and_fetch(&_memory.nSwap, 0);
    pMem->nBuff = __sync_add_and_fetch(&_memory.nBuff, 0);
}

bool XStats::UpdateMemInfo()
{
    char sBuffer[XSTATS_FILE_MAX]; /* Load /proc/meminfo file */
    int nLength = LoadFile(XSTATS_FILE_MEMINFO, sBuffer, sizeof(sBuffer));
    if (nLength <= 0) return false;

    /* Parse memory statistics */
    __sync_lock_test_and_set(&_memory.nTotal, ParseInfo(sBuffer, nLength, "MemTotal"));
    __sync_lock_test_and_set(&_memory.nFree, ParseInfo(sBuffer, nLength, "MemFree"));
    __sync_lock_test_and_set(&_memory.nAvail, ParseInfo(sBuffer, nLength, "MemAvailable"));
    __sync_lock_test_and_set(&_memory.nBuff, ParseInfo(sBuffer, nLength, "Buffers"));
    __sync_lock_test_and_set(&_memory.nSwap, ParseInfo(sBuffer, nLength, "SwapCached"));

    /* Load /proc/self/status file */
    nLength = LoadFile(XSTATS_FILE_SELFSTATUS, sBuffer, sizeof(sBuffer));
    if (nLength <= 0) return false;

    /* Parse memory statistics for current process */
    __sync_lock_test_and_set(&_memory.nResident, ParseInfo(sBuffer, nLength, "VmRSS"));
    __sync_lock_test_and_set(&_memory.nVirt, ParseInfo(sBuffer, nLength, "VmSize"));

    return true;
}

void XStats::GetProcUsage(XStats::CPU::Process *pProc)
{
    pProc->nUserChilds = __sync_add_and_fetch(&_cpu.proc.nUserChilds, 0);
    pProc->nKernelChilds = __sync_add_and_fetch(&_cpu.proc.nKernelChilds, 0);
    pProc->nUserSpace = __sync_add_and_fetch(&_cpu.proc.nUserSpace, 0);
    pProc->nKernelSpace = __sync_add_and_fetch(&_cpu.proc.nKernelSpace, 0);
    pProc->nTotalTime = __sync_add_and_fetch(&_cpu.proc.nTotalTime, 0);
    pProc->nUserSpaceUsg = __sync_add_and_fetch(&_cpu.proc.nUserSpaceUsg, 0);
    pProc->nKernelSpaceUsg = __sync_add_and_fetch(&_cpu.proc.nKernelSpaceUsg, 0);
}

void XStats::CopyCPUInfo(XStats::CPUInfo *pDst, XStats::CPUInfo *pSrc)
{
    pDst->nSoftIntsRaw = __sync_add_and_fetch(&pSrc->nSoftIntsRaw, 0);
    pDst->nHardIntsRaw = __sync_add_and_fetch(&pSrc->nHardIntsRaw, 0);
    pDst->nKernelSpaceRaw = __sync_add_and_fetch(&pSrc->nKernelSpaceRaw, 0);
    pDst->nUserNicedRaw = __sync_add_and_fetch(&pSrc->nUserNicedRaw, 0);
    pDst->nUserSpaceRaw = __sync_add_and_fetch(&pSrc->nUserSpaceRaw, 0);
    pDst->nIdleTimeRaw = __sync_add_and_fetch(&pSrc->nIdleTimeRaw, 0);
    pDst->nIOWaitRaw = __sync_add_and_fetch(&pSrc->nIOWaitRaw, 0);
    pDst->nTotalRaw = __sync_add_and_fetch(&pSrc->nTotalRaw, 0);
    pDst->nSoftIntsRaw = __sync_add_and_fetch(&pSrc->nSoftIntsRaw, 0);
    pDst->nHardIntsRaw = __sync_add_and_fetch(&pSrc->nHardIntsRaw, 0);
    pDst->nKernelSpace = __sync_add_and_fetch(&pSrc->nKernelSpace, 0);
    pDst->nUserNiced = __sync_add_and_fetch(&pSrc->nUserNiced, 0);
    pDst->nUserSpace = __sync_add_and_fetch(&pSrc->nUserSpace, 0);
    pDst->nIdleTime = __sync_add_and_fetch(&pSrc->nIdleTime, 0);
    pDst->nIOWait = __sync_add_and_fetch(&pSrc->nIOWait, 0);
    pDst->nCPUID = __sync_add_and_fetch(&pSrc->nCPUID, 0);
}

bool XStats::UpdateCPUInfo()
{
    char sBuffer[XSTATS_FILE_MAX]; /* Load /proc/stat file */
    if (LoadFile(XSTATS_FILE_STAT, sBuffer, sizeof(sBuffer)) <= 0) return false;

    /* Get last CPU usage by process */
    XStats::CPU::Process lastUsage;
    GetProcUsage(&lastUsage);

    int nCoreCount = __sync_add_and_fetch(&_cpu.nCoreCount, 0);
    char *save_ptr = NULL;
    int nCPUID = -1;

    char *ptr = strtok_r(sBuffer, "\n", &save_ptr);
    while (ptr != NULL && !strncmp(ptr, "cpu", 3))
    {
        XStats::CPUInfo info;

        sscanf(ptr, "%*s %u %u %u %u %u %u %u", &info.nUserSpaceRaw, 
            &info.nUserNicedRaw, &info.nKernelSpaceRaw, &info.nIdleTimeRaw, 
            &info.nIOWaitRaw, &info.nHardIntsRaw, &info.nSoftIntsRaw);

        info.nTotalRaw = info.nKernelSpaceRaw + info.nUserSpaceRaw + info.nUserNicedRaw;
        info.nTotalRaw += info.nHardIntsRaw + info.nSoftIntsRaw;
        info.nTotalRaw += info.nIdleTimeRaw + info.nIOWaitRaw;
        info.nCPUID = nCPUID++;

        if (!nCoreCount && info.nCPUID >= 0)
        {
            _cpu.cores.push_back(info);
        }
        else
        {
            XStats::CPUInfo lastInfo, *pCurrInfo;

            if (info.nCPUID < 0) pCurrInfo = &_cpu.sum;
            else pCurrInfo = &_cpu.cores[info.nCPUID];

            CopyCPUInfo(&lastInfo, pCurrInfo);
            uint32_t nTotalDiff = info.nTotalRaw - lastInfo.nTotalRaw;

            float fHardInterrupts = ((info.nHardIntsRaw - lastInfo.nHardIntsRaw) / (float)nTotalDiff) * 100;
            float fSoftInterrupts = ((info.nSoftIntsRaw - lastInfo.nSoftIntsRaw) / (float)nTotalDiff) * 100;
            float fKernelSpace = ((info.nKernelSpaceRaw - lastInfo.nKernelSpaceRaw) / (float)nTotalDiff) * 100;
            float fUserSpace = ((info.nUserSpaceRaw - lastInfo.nUserSpaceRaw) / (float)nTotalDiff) * 100;
            float fUserNiced = ((info.nUserNicedRaw - lastInfo.nUserNicedRaw) / (float)nTotalDiff) * 100;
            float fIdleTime = ((info.nIdleTimeRaw - lastInfo.nIdleTimeRaw) / (float)nTotalDiff) * 100;
            float fIOWait = ((info.nIOWaitRaw - lastInfo.nIOWaitRaw) / (float)nTotalDiff) * 100;

            __sync_lock_test_and_set(&pCurrInfo->nHardInts, FloatToU32(fHardInterrupts));
            __sync_lock_test_and_set(&pCurrInfo->nSoftInts, FloatToU32(fSoftInterrupts));
            __sync_lock_test_and_set(&pCurrInfo->nKernelSpace, FloatToU32(fKernelSpace));
            __sync_lock_test_and_set(&pCurrInfo->nUserSpace, FloatToU32(fUserSpace));
            __sync_lock_test_and_set(&pCurrInfo->nUserNiced, FloatToU32(fUserNiced));
            __sync_lock_test_and_set(&pCurrInfo->nIdleTime, FloatToU32(fIdleTime));
            __sync_lock_test_and_set(&pCurrInfo->nIOWait, FloatToU32(fIOWait));

            /* Raw information about CPU usage for later percentage calculations */
            __sync_lock_test_and_set(&pCurrInfo->nHardIntsRaw, info.nHardIntsRaw);
            __sync_lock_test_and_set(&pCurrInfo->nSoftIntsRaw, info.nSoftIntsRaw);
            __sync_lock_test_and_set(&pCurrInfo->nKernelSpaceRaw, info.nKernelSpaceRaw);
            __sync_lock_test_and_set(&pCurrInfo->nUserSpaceRaw, info.nUserSpaceRaw);
            __sync_lock_test_and_set(&pCurrInfo->nUserNicedRaw, info.nUserNicedRaw);
            __sync_lock_test_and_set(&pCurrInfo->nIdleTimeRaw, info.nIdleTimeRaw);
            __sync_lock_test_and_set(&pCurrInfo->nIOWaitRaw, info.nIOWaitRaw);
            __sync_lock_test_and_set(&pCurrInfo->nTotalRaw, info.nTotalRaw);
            __sync_lock_test_and_set(&pCurrInfo->nCPUID, info.nCPUID);
        }

        ptr = strtok_r(NULL, "\n", &save_ptr);
    }

    __sync_lock_test_and_set(&_cpu.nCoreCount, _cpu.cores.size());
    if (LoadFile(XSTATS_FILE_SELFSTAT, sBuffer, sizeof(sBuffer)) <= 0) return false;

    XStats::CPU::Process currUsage;
    sscanf(sBuffer, "%*u %*s %*c %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %lu %lu %ld %ld",
                    &currUsage.nUserSpace, &currUsage.nKernelSpace, 
                    &currUsage.nUserChilds, &currUsage.nKernelChilds);

    currUsage.nTotalTime = __sync_add_and_fetch(&_cpu.sum.nTotalRaw, 0);
    uint64_t nTotalDiff = currUsage.nTotalTime - lastUsage.nTotalTime;

    float nUserCPU = 100 * (((currUsage.nUserSpace + currUsage.nUserChilds) - 
        (lastUsage.nUserSpace + lastUsage.nUserChilds)) / (float)nTotalDiff);

    float nSystemCPU = 100 * (((currUsage.nKernelSpace + currUsage.nKernelChilds) - 
        (lastUsage.nKernelSpace + lastUsage.nKernelChilds)) / (float)nTotalDiff);

    __sync_lock_test_and_set(&_cpu.proc.nUserChilds, currUsage.nUserChilds);
    __sync_lock_test_and_set(&_cpu.proc.nKernelChilds, currUsage.nUserChilds);
    __sync_lock_test_and_set(&_cpu.proc.nUserSpace, currUsage.nUserSpace);
    __sync_lock_test_and_set(&_cpu.proc.nKernelSpace, currUsage.nKernelSpace);
    __sync_lock_test_and_set(&_cpu.proc.nTotalTime, currUsage.nTotalTime);
    __sync_lock_test_and_set(&_cpu.proc.nUserSpaceUsg, FloatToU32(nUserCPU));
    __sync_lock_test_and_set(&_cpu.proc.nKernelSpaceUsg, FloatToU32(nSystemCPU));

    float fOneMinInt, fFiveMinInt, fTenMinInt;
    if (LoadFile(XSTATS_FILE_LOADAVG, sBuffer, sizeof(sBuffer)) <= 0) return false;
    sscanf(sBuffer, "%f %f %f", &fOneMinInt, &fFiveMinInt, &fTenMinInt);

    __sync_lock_test_and_set(&_cpu.nLoadAvg[0], FloatToU32(fOneMinInt));
    __sync_lock_test_and_set(&_cpu.nLoadAvg[1], FloatToU32(fFiveMinInt));
    __sync_lock_test_and_set(&_cpu.nLoadAvg[2], FloatToU32(fTenMinInt));

    return true;
}

bool XStats::GetCPUInfo(XStats::CPU *pCPU)
{
    pCPU->nLoadAvg[0] = pCPU->nLoadAvg[1] = pCPU->nLoadAvg[2] = 0;
    int i, nCoreCount = __sync_add_and_fetch(&_cpu.nCoreCount, 0);
    if (nCoreCount <= 0) return false;

    GetProcUsage(&pCPU->proc);
    CopyCPUInfo(&pCPU->sum, &_cpu.sum);

    for (i = 0; i < nCoreCount; i++)
    {
        XStats::CPUInfo dstInfo;
        CopyCPUInfo(&dstInfo, &_cpu.cores[i]);
        pCPU->cores.push_back(dstInfo);
    }

    pCPU->nCoreCount = pCPU->cores.size();
    pCPU->nLoadAvg[0] = __sync_add_and_fetch(&_cpu.nLoadAvg[0], 0);
    pCPU->nLoadAvg[1] = __sync_add_and_fetch(&_cpu.nLoadAvg[1], 0);
    pCPU->nLoadAvg[2] = __sync_add_and_fetch(&_cpu.nLoadAvg[2], 0);
    return pCPU->nCoreCount ? true : false;
}

/*
void XStats::Display()
{
    XStats::memory mem;
    GetMemInfo(&mem);

    xlog::debug("memory: avail(%lu), total(%lu), free(%lu), swap(%lu), buff(%lu)",
        mem.nAvail, mem.nTotal, mem.nFree, mem.nSwap, mem.nBuff);

    XStats::CPU cpu;
    GetCPUInfo(&cpu);

    xlog::debug("process: mem-res(%lu), mem-virt(%lu), cpu-us(%.2f), cpu-ks(%.2f)", 
        mem.nResident, mem.nVirt,
        U32ToFloat(cpu.proc.nUserSpaceUsg), 
        U32ToFloat(cpu.proc.nKernelSpaceUsg));

    xlog::debug("loadavg: 5m(%.2f), 10m(%.2f), 15m(%.2f),\n", U32ToFloat(cpu.nLoadAvg[0]), 
        U32ToFloat(cpu.nLoadAvg[1]), U32ToFloat(cpu.nLoadAvg[2]));
    
    xlog::debug("core(s): us(%.2f), un(%.2f), ks(%.2f), idl(%.2f), si(%.2f), hi(%.2f), io(%.2f)", 
        U32ToFloat(cpu.sum.nUserSpace), U32ToFloat(cpu.sum.nUserNiced), 
        U32ToFloat(cpu.sum.nKernelSpace), U32ToFloat(cpu.sum.nIdleTime), 
        U32ToFloat(cpu.sum.nHardInts), U32ToFloat(cpu.sum.nSoftInts), 
        U32ToFloat(cpu.sum.nIOWait));

    for (uint i = 0; i < cpu.cores.size(); i++)
    {
        XStats::CPUInfo *core = &cpu.cores[i];
        xlog::debug("core(%d): us(%.2f), un(%.2f), ks(%.2f), idl(%.2f), si(%.2f), hi(%.2f), io(%.2f)", 
            core->nCPUID, U32ToFloat(core->nUserSpace), U32ToFloat(core->nUserNiced), 
            U32ToFloat(core->nKernelSpace), U32ToFloat(core->nIdleTime), 
            U32ToFloat(core->nHardInts), U32ToFloat(core->nSoftInts), 
            U32ToFloat(core->nIOWait));
    }
}
*/

void XStats::MonitoringThread()
{
    while (!__sync_add_and_fetch(&_nCancel, 0))
    {
        UpdateMemInfo();
        UpdateCPUInfo();

        //display();
        sleep(1);
    }

    __sync_lock_test_and_set(&_nActive, 0);
}

void XStats::StartMonitoring()
{
    __sync_lock_test_and_set(&_nActive, 1);
    std::thread thread_id(&XStats::MonitoringThread, this);
    thread_id.detach();
}

void XStats::StopMonitoring()
{
    /* Notify thread about finish processing */
    __sync_lock_test_and_set(&_nCancel, 1);

    while (__sync_add_and_fetch(&_nActive, 0)) 
        usleep(10000); // Wait for thread termination
}
