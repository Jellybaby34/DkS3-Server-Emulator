#include "Game.h"
#include "threadpool.h"
#include "stdafx.h"

namespace GameServer {

	bool isInitialised;
	struct event_base *gameEventBase;
	struct evconnlistener *gameListener;
	std::mutex mtxGameClientVector;
	std::vector<gameclient_t> gameClientVector;

	// This is probably one huge race condition
	// Please be gentle
	void ProcessUdpPacket(evutil_socket_t fd, short event2, void *arg) {
		unsigned char buf[2048] = {};
		socklen_t size = sizeof(struct sockaddr);
		struct sockaddr_in client_addr = { 0 };
		int len = recvfrom(fd, (char*)buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &size);
		if (len < 0) {
			LOG_ERROR("server recv message error...!");
			return;
		}
		if (len == 0) {
			LOG_ERROR("connection closed...!");
		}

		LOG_PRINT("Received UDP packet from %s:%i. len = %i", inet_ntoa(client_addr.sin_addr), client_addr.sin_port, len);
		PrintBytes((char*)buf, len);

		mtxGameClientVector.lock();
		unsigned long long receivedSessionToken = *(unsigned long long*)&buf;
		for (int i = 0; i < gameClientVector.size(); i++) {
			if (gameClientVector[i].sessionToken == receivedSessionToken) {
				LOG_PRINT("Token match");
				gameClientVector[i].timeSinceLastPacket = GetTickCount64();

			}
		};
		mtxGameClientVector.unlock();

//		LOG_PRINT("sever send back message now...!");
//		sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, size);
	}

	void UdpReadCb(evutil_socket_t fd, short event2, void *arg) {
		LOG_ERROR("UDP read callback triggered");
		threadPool.enqueue_work(ProcessUdpPacket, (evutil_socket_t)fd, (short)NULL, (void*)NULL);
	}

	void PruneDeadConnections(evutil_socket_t fd, short event2, void *arg) {
		mtxGameClientVector.lock();
		unsigned long long currentTime = GetTickCount64();
		for (int i = 0; i < gameClientVector.size(); i++) {
			if (currentTime - gameClientVector[i].timeSinceLastPacket >= 15000) {
				LOG_PRINT("Dead connection");
				if (gameClientVector[i].cwcInstance)
					free(gameClientVector[i].cwcInstance);
				gameClientVector.erase(gameClientVector.begin() + i);
			}
		};
		mtxGameClientVector.unlock();
	}

	void UdpTimeoutCb(evutil_socket_t fd, short event2, void *arg) {
		LOG_ERROR("Timeout callback triggered");
		threadPool.enqueue_work(PruneDeadConnections, (evutil_socket_t)fd, (short)NULL, (void*)NULL);
	}

	void Initialise() {

		if (isInitialised) {
			LOG_ERROR("[GameServer::Initialise] Tried to re-initialise the game server");
			return;
		}

		LOG_PRINT("[GameServer::Initialise] Starting GameServer instance");
		gameEventBase = event_base_new();
		if (gameEventBase == NULL) {
			LOG_ERROR("[GameServer::Initialise] Couldn't create new event base");
			return;
		}

		struct sockaddr_in sin;
		int sock = socket(AF_INET, SOCK_DGRAM, 0);

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = INADDR_ANY;
		sin.sin_port = htons(GAMEPORT);

		if (bind(sock, (struct sockaddr *) &sin, sizeof(sin))) {
			perror("bind()");
			exit(EXIT_FAILURE);
		}

		isInitialised = true;

		struct timeval tv;
		tv.tv_sec = 15;
		tv.tv_usec = 0;

		event *udpTimeout = event_new(gameEventBase, sock, EV_TIMEOUT | EV_PERSIST, UdpTimeoutCb, NULL);
		event_add(udpTimeout, &tv);
		event *udpReadEvent = event_new(gameEventBase, sock, EV_READ | EV_PERSIST, UdpReadCb, NULL);
		event_add(udpReadEvent, NULL);

		gameClientVector.reserve(10000);

		event_base_dispatch(gameEventBase);

	}
}