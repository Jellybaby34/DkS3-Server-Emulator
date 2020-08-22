#include "Logging.h"

static std::string GetTimeStr()
{
	char strtime[256];
	auto timept = std::chrono::system_clock::now();
	auto timetp = std::chrono::system_clock::to_time_t(timept);
	strftime(strtime, sizeof(strtime), "%X", std::localtime(&timetp));

	return std::string(strtime);
}

void PrintBytes(const char* pBytes, const uint32_t nBytes) // should more properly be std::size_t
{
	for (uint32_t i = 0; i != nBytes; i++)
	{
		std::cout <<
			std::hex <<           // output in hex
			std::uppercase <<	  // output letters in uppercase
			std::setw(2) <<       // each byte prints as two characters
			std::setfill('0') <<  // fill with 0 if not enough characters
			static_cast<unsigned int>(static_cast<unsigned char>(pBytes[i])) <<
			" ";
	}

	std::cout << std::endl;
}

void LogPrintf(LoggingLevel loglevel, const char *format, ...)
{
	std::string CurTime = GetTimeStr();
	char buffer[256];

	va_list args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	switch (loglevel)
	{
		case LoggingLevel::Print:
		{
			auto h = GetStdHandle(STD_OUTPUT_HANDLE);
			SetConsoleTextAttribute(h, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			fprintf(stdout, "[LOGSTR %s] %s\n", CurTime.c_str(), buffer);
			return;
		}
		case LoggingLevel::Warn:
		{
			auto h = GetStdHandle(STD_OUTPUT_HANDLE);
			SetConsoleTextAttribute(h, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN);
			fprintf(stdout, "[LOGWRN %s] %s\n", CurTime.c_str(), buffer);
			SetConsoleTextAttribute(h, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			return;
		}
		case LoggingLevel::Error:
		{
			auto h = GetStdHandle(STD_ERROR_HANDLE);
			SetConsoleTextAttribute(h, FOREGROUND_INTENSITY | FOREGROUND_RED);
			fprintf(stderr, "[LOGERR %s] %s\n", CurTime.c_str(), buffer);
			SetConsoleTextAttribute(h, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			return;
		}
		case LoggingLevel::Success:
		{
			auto h = GetStdHandle(STD_OUTPUT_HANDLE);
			SetConsoleTextAttribute(h, FOREGROUND_INTENSITY | FOREGROUND_GREEN);
			fprintf(stdout, "[LOGSTR %s] %s\n", CurTime.c_str(), buffer);
			SetConsoleTextAttribute(h, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			return;
		}
		default:
		{
			fprintf(stdout, "[LOGSTR %s] %s\n", CurTime.c_str(), buffer);
			return;
		}
	}
}