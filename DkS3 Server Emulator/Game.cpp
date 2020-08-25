#include "Game.h"
#include "threadpool.h"
#include "stdafx.h"

namespace GameServer {

	bool isInitialised;
	struct event_base *gameEventBase;
	struct evconnlistener *gameListener;

	void deal_with_udp(evutil_socket_t fd) {
		char buf[2048] = {};
		socklen_t size = sizeof(struct sockaddr);
		struct sockaddr_in client_addr = { 0 };
		int len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &size);
		if (len < 0) {
			LOG_ERROR("server recv message error...!");
			return;
		}
		if (0 == len) {
			LOG_ERROR("connection closed...!");
		}
		LOG_PRINT("connection port = %i", client_addr.sin_port);
		LOG_PRINT("connection ip = %s", inet_ntoa(client_addr.sin_addr));
		LOG_PRINT("server recv message len = %i", len);
		LOG_PRINT("sever send back message now...!");
		sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, size);
	}

	void udp_cb(evutil_socket_t fd, short event, void *arg) {
		LOG_ERROR("Test");
		threadPool.enqueue_work(deal_with_udp, fd);
	}

	void Initialise() {

		if (isInitialised) {
			LOG_ERROR("[LoginServer::Initialise] Tried to re-initialise the login server");
			return;
		}

		LOG_PRINT("[LoginServer::Initialise] Starting LoginServer instance");
		gameEventBase = event_base_new();
		if (gameEventBase == NULL) {
			LOG_ERROR("[LoginServer::Initialise] Couldn't create new event base");
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

//		event_base_dispatch(gameEventBase);

		
		/* Add the UDP event */
		event *testing = event_new(gameEventBase, sock, EV_READ | EV_PERSIST, udp_cb, NULL);
		event_add(testing, NULL);

		/* Enter the event loop; does not return. */
		event_base_dispatch(gameEventBase);
//		close(sock);
	}
}