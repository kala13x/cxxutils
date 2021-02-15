/*
 *  examples/statcov.c
 * 
 *  Copyleft (C) 2020  Sun Dro (a.k.a. kala13x)
 *
 * Parse COVID-19 case statistics from https://stopcov.ge/
 */

#include <cxxutils/xsock.h>
#include <cxxutils/xhttp.h>

#define STOPCOV_ADDR        "stopcov.ge"
#define STOPCOV_PORT        443
#define XSOCK_BUFF_SIZE     4098

typedef struct {
    int nQuarantined;
    int nSupervision;
    int nConfirmed;
    int nRecovered;
    int nDeaths;
} COVIDCases;

int COVID_ParseCase(const char *pSource, const char *pCase)
{
    const char *pCases = strstr(pSource, pCase);
    if (pCases != NULL)
    {
        const char *pOffset = strstr(pCases, "numver");
        if (pOffset != NULL)
        {
            pOffset += 8;
            return atoi(pOffset);
        }
    }

    return -1;
}

int COVID_GetCases(XSock *pSock, const char *pRequest, COVIDCases *pCovCases)
{
    char sResponse[XSOCK_BUFF_SIZE];
    int nBytes = 0;

    pSock->Write((void*)pRequest, strlen(pRequest));
    memset(pCovCases, 0, sizeof(COVIDCases));

    while ((nBytes = pSock->Read(sResponse, sizeof(sResponse))) > 0)
    {
        sResponse[nBytes] = '\0';

        if (pCovCases->nConfirmed <= 0)
            pCovCases->nConfirmed = COVID_ParseCase(sResponse, "დადასტურებული შემთხვევა");

        if (pCovCases->nRecovered <= 0)
            pCovCases->nRecovered = COVID_ParseCase(sResponse, "მათ შორის გამოჯანმრთელებული");

        if (pCovCases->nQuarantined <= 0)
            pCovCases->nQuarantined = COVID_ParseCase(sResponse, "კარანტინის რეჟიმში");

        if (pCovCases->nSupervision <= 0)
            pCovCases->nSupervision = COVID_ParseCase(sResponse, "მეთვალყურეობის ქვეშ");

        if (pCovCases->nDeaths <= 0)
            pCovCases->nDeaths = COVID_ParseCase(sResponse, "მათ შორის გარდაცვლილი");
    }

    return pCovCases->nConfirmed;
}

void COVID_PrintCases(COVIDCases *pCovCases)
{
    printf("=======================================\n");
    printf("Confirmed Cases: %d\n", pCovCases->nConfirmed);
    printf("Recovered Cases: %d\n", pCovCases->nRecovered);
    printf("Quarantined: %d\n", pCovCases->nQuarantined);
    printf("Supervision: %d\n", pCovCases->nSupervision);
    printf("Deaths: %d\n", pCovCases->nDeaths);
    printf("=======================================\n");
}

int main(int argc, char* argv[])
{
    int nVerbose = (argc > 1);
    if (nVerbose) printf("---> Creating HTTP/S GET request\n");

    XHTTP header;
    header.InitRequest(XHTTP::Method::GET, "/", NULL);
    header.AddHeader("Host", STOPCOV_ADDR);
    header.AddHeader("User-Agent", "cxxutils");
    header.FinishAssembly();

    if (!header.IsComplete()) 
    {
        printf("Can not create HTTP request\n");
        return 0;
    }

    XSock::Info info;
    if (!XSock::AddrInfo(STOPCOV_ADDR, &info))
    {
        printf("Can not resolve address: %s\n", STOPCOV_ADDR);
        return 0;
    }

    XSock::InitSSL();

    if (nVerbose) printf("---> Connecting to server: %s:%d\n", info.sAddr.c_str(), STOPCOV_PORT);

    XSock sock(XSock::Type::SSL_CLIENT, info.sAddr.c_str(), STOPCOV_PORT);
    if (!sock.IsOpen())
    {
        printf("%s (%s)\n", sock.ErrorStr(), strerror(errno));
        return 0;
    }

    if (nVerbose) printf("---> Sending request:\n\n%s\n", header.GetData());

    COVIDCases covCases;
    int nStatus = COVID_GetCases(&sock, header.GetData(), &covCases);

    if (nStatus) COVID_PrintCases(&covCases);
    else printf("%s\n", sock.ErrorStr());

    XSock::DeinitSSL();
    return 0;
}