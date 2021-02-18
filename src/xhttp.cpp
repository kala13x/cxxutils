/*
 *  cxxutils/src/xhttp.cpp
 * 
 *  Copyleft (C) 2020  Sun Dro (f4tb0y@protonmail.com)
 *  HTTP request parser/assembler implementation in C++
 */

#include <stdio.h>
#include <unistd.h>

#include <algorithm>
#include <cstdarg>
#include <sstream>
#include <string>
#include <cctype>

#include "xhttp.h"

const char* XHTTP::GetCodeStr(int nCode)
{
	switch(nCode)
	{
		case 100: return "Continue";
		case 101: return "Switching Protocol";
		case 102: return "Processing";
		case 103: return "Early Hints";
		case 200: return "OK";
		case 201: return "Created";
		case 202: return "Accepted";
		case 203: return "Non-Authoritative Information";
		case 204: return "No Content";
		case 205: return "Reset Content";
		case 206: return "Partial Content";
		case 300: return "Multiple Choice";
		case 301: return "Moved Permanently";
		case 302: return "Found";
		case 303: return "See Other";
		case 304: return "Not Modified";
		case 305: return "Use Proxy";
		case 306: return "Unused";
		case 307: return "Temporary Redirect";
		case 308: return "Permanent Redirect";
		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 402: return "Payment Required";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 405: return "Method Not Allowed";
		case 406: return "Not Acceptable";
		case 407: return "Proxy Authentication Required";
		case 408: return "Request Timeout";
		case 409: return "Conflict";
		case 410: return "Gone";
		case 411: return "Length Required";
		case 412: return "Precondition Failed";
		case 413: return "Payload Too Large";
		case 414: return "URI Too Long";
		case 415: return "Unsupported Media Type";
		case 416: return "Requested Range Not Satisfiable";
		case 417: return "Expectation Failed";
		case 418: return "I'm a teapot";
		case 500: return "Internal Server Error";
		case 501: return "Not Implemented";
		case 502: return "Bad Gateway";
		case 503: return "Service Unavailable";
		case 504: return "Gateway Timeout";
		case 505: return "HTTP Version Not Supported";
		case 506: return "Variant Also Negotiates";
		case 507: return "Insufficient Storage";
		case 508: return "Loop Detected";
		case 510: return "Not Extended";
		case 511: return "Network Authentication Required";
		default: break;
	}

	return "Unknown";
}

const char* XHTTP::GetCodeStr()
{
	return GetCodeStr(m_nStatusCode);
}

const char* XHTTP::GetMethodStr()
{
	switch(m_eMethod)
	{
		case Method::PUT: return "PUT";
		case Method::GET: return "GET";
		case Method::POST: return "POST";
		case Method::DELETE: return "DELETE";
		case Method::OPTIONS: return "OPTIONS";
		default: break;
	}

	return "DUMMY";
}

void XHTTP::Advance(size_t nSize)
{
	if (nSize <= m_sHeaderRaw.length()) m_sHeaderRaw.erase(0, nSize);
	else if (m_sHeaderRaw.length()) m_sHeaderRaw.clear();
}

void XHTTP::Append(const char *pData, size_t nLength)
{
	if (pData == NULL || !nLength) return;
	m_sHeaderRaw.append(pData, nLength);
}

void XHTTP::InitRequest(Method eMethod, const char *pUrl, const char *pVer)
{
	m_eMethod = eMethod;
	m_sVersion = pVer ? std::string(pVer) : std::string("1.0");
	m_sHeaderRaw = std::string(GetMethodStr()) + std::string(" ");
	AddHeader(NULL, "%s HTTP/%s", pUrl, m_sVersion.c_str());
}

void XHTTP::InitResponse(int nStatusCode, const char *pVer)
{
	m_nStatusCode = nStatusCode;
	m_sVersion = pVer ? std::string(pVer) : std::string("1.0");
	m_sHeaderRaw = std::string("HTTP/") + m_sVersion;
	AddHeader(NULL, " %d %s", m_nStatusCode, GetCodeStr(m_nStatusCode));
}

bool XHTTP::ParseMethod()
{
	if (!m_sHeaderRaw.compare(0, 3, "GET")) m_eMethod = Method::GET;
	else if (!m_sHeaderRaw.compare(0, 3, "PUT")) m_eMethod = Method::PUT;
	else if (!m_sHeaderRaw.compare(0, 4, "POST")) m_eMethod = Method::POST;
	else if (!m_sHeaderRaw.compare(0, 6, "DELETE")) m_eMethod = Method::DELETE;
	else if (!m_sHeaderRaw.compare(0, 7, "OPTIONS")) m_eMethod = Method::OPTIONS;
	else m_eMethod = Method::DUMMY;
	return (m_eMethod != Method::DUMMY);
}

bool XHTTP::ParseURL()
{
	size_t nStartPosit = m_sHeaderRaw.find("/");
	if (nStartPosit == std::string::npos) return false;

	size_t nEndPosit = m_sHeaderRaw.find(" ", nStartPosit);
	if (nStartPosit == std::string::npos) return false;

	size_t nUriLength = nEndPosit - nStartPosit;
	m_sUrl = m_sHeaderRaw.substr(nStartPosit, nUriLength);

	return true;
}

bool XHTTP::ParseStatusCode()
{
	size_t nStartPosit = m_sHeaderRaw.find("HTTP/");
	if (nStartPosit == std::string::npos) return false;

	nStartPosit += m_sVersion.length() + 6; // skip "HTTP/version and space
	size_t nEndPosit = m_sHeaderRaw.find(" ", nStartPosit);
	if (nEndPosit == std::string::npos) return false;

	size_t nCodeLength = nEndPosit - nStartPosit;
	m_nStatusCode = atoi(m_sHeaderRaw.substr(nStartPosit, nCodeLength).c_str());
	return true;
}

bool XHTTP::GetHeader(const char* pField, std::string &sHeader)
{
	std::string sField = std::string(pField);
	std::transform(sField.begin(), sField.end(), sField.begin(),
		[](unsigned char c){ return std::tolower(c); });

	auto it = m_headerMap.find(sField.c_str());
	if (it == m_headerMap.end()) return false;

	sHeader = it->second;
	return true;
}

bool XHTTP::GetBody(std::string &sBody)
{
	size_t nDataPartSize = m_sHeaderRaw.length() - m_nHeaderLength;
	if (!m_nContentLength || m_nContentLength > nDataPartSize) return false;

	sBody = m_sHeaderRaw.substr(m_nHeaderLength, m_nContentLength);
	return true;
}

size_t XHTTP::ParseURLToken(size_t nPosition, std::string &sToken)
{
	if (nPosition >= m_sUrl.size()) return std::string::npos;
	size_t nNextPosition = m_sUrl.find("/", nPosition);

	if (nNextPosition != std::string::npos && nPosition < nNextPosition)
	{
		size_t nTokenSize = nNextPosition - nPosition;
		sToken = m_sUrl.substr(nPosition, nTokenSize);
		return nNextPosition + 1;
	}

	sToken = m_sUrl.substr(nPosition, std::string::npos);
	return std::string::npos;
}

size_t XHTTP::TokenizeURL(size_t nPosition, URLTokens &tokens)
{
	while (nPosition != std::string::npos)
	{
		std::string sBuffer;
		nPosition = ParseURLToken(nPosition, sBuffer);
		if (sBuffer.length()) tokens.push_back(sBuffer);;
	}

	return tokens.size();
}

size_t XHTTP::TokenizeHeader(size_t nPosition, std::string &sHeader)
{
	if (nPosition >= m_nHeaderLength - 4) return std::string::npos;
	size_t nNextPosition = m_sHeaderRaw.find("\r\n", nPosition);

	if (nNextPosition != std::string::npos && nPosition < nNextPosition)
	{
		size_t nTokenSize = nNextPosition - nPosition;
		sHeader = m_sHeaderRaw.substr(nPosition, nTokenSize);
		return nNextPosition + 2;
	}

	sHeader = m_sHeaderRaw.substr(nPosition, std::string::npos);
	return std::string::npos;
}

bool XHTTP::ParseHeaders()
{
	size_t nPosition = m_sHeaderRaw.find("\r\n", 0);
	if (nPosition == std::string::npos) return false; 
	nPosition += 2;

	while (nPosition != std::string::npos)
	{
		std::string sHeader;
		nPosition = TokenizeHeader(nPosition, sHeader);

		if (sHeader.length())
		{
			std::stringstream strStream(sHeader);
			std::string sName, sField;

			if (std::getline(strStream, sName, ':') && (sName.length() + 1) < sHeader.length())
			{
				std::transform(sName.begin(), sName.end(), sName.begin(),
					[](unsigned char c){ return std::tolower(c); });

				size_t nFieldPosition = sName.length() + 1;
				size_t nFieldLength = sHeader.length() - nFieldPosition;

				sField = sHeader.substr(nFieldPosition, nFieldLength);
				if (sField[0] == ' ') sField.erase(0, 1);
			}

			if (sName.length() && sField.length())
				m_headerMap[sName] = sField;
		}
	}

	return m_headerMap.size() ? true : false;
}

bool XHTTP::PatseLength()
{
	size_t nPosit = m_sHeaderRaw.find("\r\n\r\n");
	if (nPosit == std::string::npos) return false;
	m_nHeaderLength = nPosit + 4;
	return true;
}

bool XHTTP::ParseVersion()
{
	size_t nStartPosit = m_sHeaderRaw.find("HTTP/");
	if (nStartPosit == std::string::npos) return false;
	nStartPosit += 5; // Skip "HTTP/"

	const char *pEndPosit = m_eType == HeaderType::request ? "\r" : " ";
	size_t nEndPosit = m_sHeaderRaw.find(pEndPosit, nStartPosit);
	if (nEndPosit == std::string::npos) return false;

	size_t nVersionLength = nEndPosit - nStartPosit;
	m_sVersion = m_sHeaderRaw.substr(nStartPosit, nVersionLength);

	return true;
}

bool XHTTP::Parse()
{
	/* Validate HTTP header and parse length */
	if (!m_sHeaderRaw.length()) return false;
	if (!PatseLength()) return false;

	/* Detect HTTP header type and parse URL in case of request*/
	if (!m_sHeaderRaw.compare(0, 4, "HTTP")) m_eType = HeaderType::response;
	else if (ParseURL()) m_eType = HeaderType::request;
	else return false;

	/* Parse HTTP version based on header type */
	if (!ParseVersion()) return false;

	/* Parse HTTP status code or method based on header type */
	if (m_eType == HeaderType::response && !ParseStatusCode()) return false;
	else if (m_eType == HeaderType::request && !ParseMethod()) return false;

	ParseHeaders();
	std::string sContentLength;

	/* Parse content length if available */
	if (GetHeader("Content-Length", sContentLength))
		m_nContentLength = atol(sContentLength.c_str());

	m_bComplete = true;
	return true;
}

void XHTTP::SetData(std::string sRequest)
{
	if (!sRequest.length()) return;
	m_sHeaderRaw = sRequest;
}

bool XHTTP::Parse(std::string sRequest)
{
	if (!sRequest.length()) return false;
	SetData(sRequest);
	return Parse();
}

void XHTTP::AddHeader(const char *pField, const char *pStr, ...)
{
	char sOption[XHTTP_HEADER_MAX];
	va_list args;

	va_start(args, pStr);
	vsnprintf(sOption, sizeof(sOption), pStr, args);
	va_end(args);

	if (pField != NULL)
	{
		m_sHeaderRaw.append(pField);
		m_sHeaderRaw.append(": ");
	}

	m_sHeaderRaw.append(sOption);
	m_sHeaderRaw.append("\r\n");
}

void XHTTP::AddBody(const char *pData, size_t nLength)
{
	AddHeader("Content-Length", "%lu", nLength);
	FinishAssembly();

	m_sHeaderRaw.append(pData, nLength);
}

void XHTTP::FinishAssembly()
{
	m_sHeaderRaw.append("\r\n");
	m_nHeaderLength = m_sHeaderRaw.length();
	m_bComplete = true;;
}
