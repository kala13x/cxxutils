#ifndef __CXXUTILS_XSTATS_H__
#define __CXXUTILS_XSTATS_H__

#include <unordered_map>
#include <vector>

#include <inttypes.h>

#define _XALIGNED_ __attribute__((aligned))

class XStats 
{
public:
    struct Memory {
        uint64_t _XALIGNED_ nResident = 0;
        uint64_t _XALIGNED_ nVirt = 0;
        uint64_t _XALIGNED_ nAvail = 0;
        uint64_t _XALIGNED_ nTotal = 0;
        uint64_t _XALIGNED_ nFree = 0;
        uint64_t _XALIGNED_ nSwap = 0;
        uint64_t _XALIGNED_ nBuff = 0;
    };

    struct CPUInfo {
        int nCPUID = 0; // -1 for sum

        /* Calculated percents */
        uint32_t _XALIGNED_ nSoftInts = 0;
        uint32_t _XALIGNED_ nHardInts = 0;
        uint32_t _XALIGNED_ nUserNiced = 0;
        uint32_t _XALIGNED_ nKernelSpace = 0;
        uint32_t _XALIGNED_ nUserSpace = 0;
        uint32_t _XALIGNED_ nIdleTime = 0;
        uint32_t _XALIGNED_ nIOWait = 0;

        /* Raw information */
        uint32_t _XALIGNED_ nSoftIntsRaw = 0;
        uint32_t _XALIGNED_ nHardIntsRaw = 0;
        uint32_t _XALIGNED_ nUserNicedRaw = 0;
        uint32_t _XALIGNED_ nKernelSpaceRaw = 0;
        uint32_t _XALIGNED_ nUserSpaceRaw = 0;
        uint32_t _XALIGNED_ nIdleTimeRaw = 0;
        uint32_t _XALIGNED_ nIOWaitRaw = 0;
        uint64_t _XALIGNED_ nTotalRaw = 0;
    };

    static void CopyCPUInfo(XStats::CPUInfo *pDst, XStats::CPUInfo *pSrc);
    static uint64_t ParseInfo(char *pBuffer, size_t nSize, const char *pField);
    static int LoadFile(const char *pPath, char *pBuffer, size_t nSize);

    static uint32_t FloatToU32(float fValue);
    static float U32ToFloat(uint32_t nValue);

    typedef std::vector<CPUInfo> CPUInfos;

    struct CPU {
        struct Process {
            uint32_t _XALIGNED_ nKernelSpaceUsg = 0;
            uint32_t _XALIGNED_ nUserSpaceUsg = 0;
            uint64_t _XALIGNED_ nKernelSpace = 0;
            uint64_t _XALIGNED_ nUserSpace = 0;
            uint64_t _XALIGNED_ nTotalTime = 0;
            int64_t _XALIGNED_ nKernelChilds = 0;
            int64_t _XALIGNED_ nUserChilds = 0;
        } proc;

        uint32_t _XALIGNED_ nLoadAvg[3];
        uint16_t _XALIGNED_ nCoreCount;

        CPUInfos cores;
        CPUInfo sum;
    };

    void StartMonitoring();
    void StopMonitoring();
    void Display();

    void GetProcUsage(XStats::CPU::Process *pProc);
    void GetMemInfo(XStats::Memory *pMem);
    bool GetCPUInfo(XStats::CPU *pCPU);

private:
    void MonitoringThread();
    bool UpdateMemInfo();
    bool UpdateCPUInfo();

    uint8_t _XALIGNED_ _nActive = 0;
    uint8_t _XALIGNED_ _nCancel = 0;

    XStats::Memory    _memory;
    XStats::CPU       _cpu;
};

#endif /* __CXXUTILS_XSTATS_H__ */