#pragma once
#ifndef LOGINSERVER_HEADER_FILE
#define LOGINSERVER_HEADER_FILE

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#include "stdafx.h"
#include "Constants.h"
#include "Logging.h"
#include "RSA.h"
#include "Frpg2RequestMessage.pb.h"

namespace LoginServer {

	typedef struct loginclient_t {
		// Various libevent variables we use
		intptr_t fd;
		struct bufferevent *buf_ev;
		struct evbuffer *input_buffer;
		struct evbuffer *output_buffer;

		char steamidstring[17];
		uint64_t clientversion;
		int clientcounter; // counter used for replying
	} loginclient_t;

	extern void Initialise();
	void OnAcceptConnection(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx);
	void OnAcceptError(struct evconnlistener *listener, void *ctx);
	void OnBuffereventRead(struct bufferevent *bev, void *ctx);
	void OnBuffereventArrive(struct bufferevent *bev, short events, void *ctx);
	void ProcessPacket(loginclient_t *clientInstance);
	int ProcessPacketHeader(loginclient_t *clientInstance);
	int ProcessPacketPayload(loginclient_t *clientInstance);
	int SendGameServerInfo(loginclient_t *clientInstance);
	int SendPacket(loginclient_t *clientInstance, unsigned char *payloadBuffer, int payloadSize);
}


/*
typedef struct loginclient {
	// Various libevent variables we use
	intptr_t fd;
	struct bufferevent *buf_ev;
	struct evbuffer *input_buffer;
	struct evbuffer *output_buffer;

	char steamidstring[16];
	uint64_t clientversion;
	int clientcounter; // counter used for replying
} loginclient_t;

class LoginServer {
	public:
		static LoginServer &GetInstance();

	private:
		LoginServer();
		~LoginServer();

		//variables
		struct event_base *pLoginEventBase;
		struct evconnlistener *pLoginListener;

		static void OnAcceptConn(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx);
		static void OnAcceptError(struct evconnlistener *listener, void *ctx);
		static void OnBuffereventArrive(struct bufferevent *bev, short events, void *ctx);
		static void OnBuffereventRead(struct bufferevent *bev, void *ctx);

		static void ProcessPacket(loginclient_t *pClientInst);
		static int ProcessPacketHeader(loginclient_t *pClientInst);
		static int ProcessPacketPayload(loginclient_t *pClientInst);
		static int SendGameServerInfo(loginclient_t *pClientInst);
		static int SendPacket(loginclient_t *pClientInst, char *pPayloadBuffer, int iPayloadSize);
};
*/

#endif


