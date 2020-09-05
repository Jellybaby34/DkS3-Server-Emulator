#include "main.h"

thread_pool threadPool;

int main()
{
	LOG_PRINT("[main] Starting Dark Souls 3 Server Emulator");
	LOG_PRINT("[main] Written by /u/TheSpicyChef");

	StartServer();
	LOG_PRINT("[main] Post StartServer()");
	Sleep(2000);

	do {
		std::cout << '\n' << "Press enter to terminate this program..." << std::endl;
	} while (std::cin.get() != '\n');

	return 0;
}

void StartServer()
{

	if (evthread_use_windows_threads() == FUNCTION_ERROR) {
		LOG_ERROR("[StartServer] Failed to initialise libevent in multithreaded mode");
		return;
	}

	if (HandleRSAKeyStartup() == FUNCTION_ERROR) {
		LOG_ERROR("[StartServer] RSA key failed to load");
		return;
	}

	if (EncryptRSAPublicKeyAndDNS("PublicRSAKey", SERVERIP) == FUNCTION_ERROR) {
		LOG_ERROR("[StartServer] Encrypting public key file and DNS failed");
		return;
	}

	// Init WinSock
	WSADATA wsData;
	WORD ver = MAKEWORD(2, 2);

	int wsOk = WSAStartup(ver, &wsData);
	if (wsOk != 0) {
		LOG_ERROR("[StartServer] Can't initialise winsock");
		return;
	}

	threadPool.enqueue_work(LoginServer::Initialise);
	Sleep(200);
	threadPool.enqueue_work(AuthServer::Initialise);
	Sleep(200);
	threadPool.enqueue_work(GameServer::Initialise);
	Sleep(200);
}