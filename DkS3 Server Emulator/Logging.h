#ifndef LOGGING_HEADER_FILE
#define LOGGING_HEADER_FILE

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>

enum LoggingLevel
{
	Print, Warn, Error, Success
};
#define LOG_PRINT(format, ...) LogPrintf(LoggingLevel::Print, format, __VA_ARGS__);
#define LOG_ERROR(format, ...) LogPrintf(LoggingLevel::Error, format, __VA_ARGS__);
#define LOG_WARN(format, ...) LogPrintf(LoggingLevel::Warn, format, __VA_ARGS__);
#define LOG_SUCCESS(format, ...) LogPrintf(LoggingLevel::Success, format, __VA_ARGS__);

void LogPrintf(LoggingLevel loglevel, const char *format, ...);
void PrintBytes(const char* pBytes, const uint32_t nBytes);

#endif