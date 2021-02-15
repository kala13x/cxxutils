/*
 *  cxxutils/src/xhttp.h
 * 
 *  Copyleft (C) 2020  Sun Dro (f4tb0y@protonmail.com)
 *  HTTP request parser/assembler implementation in C++
 */

#ifndef __CXXUTILS_XHTTP_H__
#define __CXXUTILS_XHTTP_H__

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <string>
#include <vector>
#include <unordered_map>

#define XHTTP_REQUEST_MAX   4096
#define XHTTP_HEADER_MAX 	256

class XHTTP
{
public:
	enum class Method 
	{
		DUMMY = 0,
		PUT,
		GET,
		POST,
		DELETE,
		OPTIONS
	};

	enum class HeaderType 
	{
		dummy = 0,
		request,
		response
	};

	XHTTP()
	{
		m_eType = HeaderType::dummy;
		m_eMethod = Method::DUMMY;
		m_nContentLength = 0;
		m_nHeaderLength = 0;
		m_nStatusCode = 0;
		m_bComplete = false;
	}

	virtual ~XHTTP() {};

	typedef std::unordered_map<std::string, std::string> HeaderMap;
	typedef std::vector<std::string> URLTokens;

	void InitRequest(Method eMethod, const char *pUrl, const char *pVer);
	void InitResponse(int nStatusCode, const char *pVer);
	void AddHeader(const char *pField, const char *pStr, ...);
	void AddBody(const char *pData, size_t nLength);
	void FinishAssembly();

	void SetData(std::string sRequest);
	bool Parse(std::string sRequest);
	bool Parse();

	size_t TokenizeHeader(size_t nPosition, std::string &sHeader);
	size_t ParseURLToken(size_t nPosition, std::string &sToken);
	size_t TokenizeURL(size_t nPosition, URLTokens &tokens);
	std::string GetURL() { return m_sUrl; };

	bool GetHeader(const char* pHeader, std::string &sHeader);
	bool GetBody(std::string &sBody);

	int GetStatusCode() { return m_nStatusCode; }
	Method GetMethod() { return m_eMethod; }

	static const char* GetCodeStr(int nCode);
	const char* GetMethodStr();
	const char* GetCodeStr();

	const char* GetData() { return m_sHeaderRaw.c_str(); } 
	size_t GetContentLength() { return m_nContentLength; }
	size_t GetHeaderLength() { return m_nHeaderLength; }
	size_t GetDataSize() { return m_sHeaderRaw.length(); }
	bool IsComplete() { return m_bComplete; }

	void Append(const char *pData, size_t nLength);
	void Advance(size_t nSize);

protected:
	bool ParseStatusCode();
	bool ParseHeaders();
	bool ParseVersion();
	bool PatseLength();
	bool ParseMethod();
	bool ParseURL();

	HeaderMap			m_headerMap;	
	HeaderType			m_eType;
	Method				m_eMethod;

	std::string			m_sHeaderRaw;
	std::string			m_sVersion;
	std::string			m_sUrl;

	size_t				m_nContentLength;
	size_t				m_nHeaderLength;
	int					m_nStatusCode;
	bool				m_bComplete;
};

#endif /* __CXXUTILS_XHTTP_H__ */