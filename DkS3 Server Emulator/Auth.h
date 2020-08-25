#pragma once
#ifndef AUTHSERVER_HEADER_FILE
#define AUTHSERVER_HEADER_FILE

#include <random>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <cwc.h>

#include "stdafx.h"
#include "Constants.h"
#include "Logging.h"
#include "RSA.h"
#include "Frpg2RequestMessage.pb.h"

namespace AuthServer {

	enum ConnectionStatus {
		INITIALISE_AESCWC = 1,
		AES_INITIALISED = 2,
		HANDSHAKE = 3,
		GET_SERVICE_STATUS = 4,
		EXCHANGE_STEAM_TICKET = 5,
	};

	typedef struct authclient_t {
		// Various libevent variables we use
		intptr_t fd;
		struct bufferevent *buf_ev;
		struct evbuffer *input_buffer;
		struct evbuffer *output_buffer;

		// Connection state
		enum ConnectionStatus connectionstatus;

		// Symmetrical encryption data
		unsigned char aescwckey[17]; // 128 bit key + null terminator
		cwc_ctx cwcctx;

		unsigned char unknown1[11]; // Unknown 11 bytes sent by server to client after receiving AES CWC. No fucking clue what they do or if they are even used.
		unsigned char unknown2[16]; // Some kind of key that gets negotiated between a connecting client and the server. Likely related to steam ticket authorisation
		unsigned char unknown3[9]; // 8 bytes used possibly as a token to connect the actual game server.

		// details sent by connecting clients
		char steamidstring[17];
		int clientversion;
		int clientcounter; 	// counter used for things
	} authclient_t;

	extern void Initialise();
	void OnAcceptConnection(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx);
	void OnAcceptError(struct evconnlistener *listener, void *ctx);
	void OnBuffereventRead(struct bufferevent *bev, void *ctx);
	void OnBuffereventArrive(struct bufferevent *bev, short events, void *ctx);
	void ProcessPacket(authclient_t *clientInstance);
	int ProcessPacketHeader(authclient_t *clientInstance);
//	int ProcessPacketPayload(authclient_t *clientInstance);
//	int SendGameServerInfo(authclient_t *clientInstance);
	int SendPacket(authclient_t *clientInstance, char *payloadBuffer, int payloadLength);
	int InitialiseCWCInstance(authclient_t *clientInstance);
	int EncryptCWCPacket(authclient_t *clientInstance, unsigned char *payloadBuffer, int payloadLength);
	int DecryptCWCPacket(authclient_t *clientInstance, unsigned char *decryptedPayloadBuffer);
	void GenerateRandomBytes(unsigned char *byteArray, int arrayLength);
	int GetServiceStatus(authclient_t *clientInstance);
	int BeginHandshake(authclient_t *clientInstance);
	int ValidateSteamSessionTicket(authclient_t *clientInstance);
}

/*
enum ConnectionStatus
{
	CONNECTING = 1,
	AESINITIALISED = 2,
	HANDSHAKE = 3,
	GETSERVICESTATUS = 4,
	TICKET = 5,

};

typedef struct authclient {
	// Various libevent variables we use
	intptr_t fd;
	struct bufferevent *buf_ev;
	struct evbuffer *input_buffer;
	struct evbuffer *output_buffer;

	// Connection state
	enum ConnectionStatus connectionstatus;

	// Symmetrical encryption data
	char aescwckey[16]; // 128 bit key
	cwc_ctx cwcctx;

	
	char unknown1[11]; // Unknown 11 bytes sent by server to client after receiving AES CWC. No fucking clue what they do or if they are even used.
	char unknown2[16]; // Some kind of key that gets negotiated between a connecting client and the server. Likely related to steam ticket authorisation

	// details sent by connecting clients
	char steamidstring[17];
	int clientversion;
	int clientcounter; 	// counter used for things

} authclient_t;

typedef struct steamauthsessionticket {
	// GCToken
	uint32_t gctokenlength;
	uint64_t token;
	uint64_t steamid;
	__time32_t time; // the timestamp is a 4byte value in the ticket

	// SessionHeader - this is only seen in GetAuthSession tickets
	uint32_t sessionheaderlength;
	uint32_t unknown1; //Always 1?
	uint32_t unknown2; //Always 2?
	uint32_t externalip;
	uint32_t unknown3; //
	__time32_t timestamp; // seems to be milliseconds since steam launched/connected to steam3
	uint32_t connectioncount; // number of times the client has connected to a server




};

class AuthServer
{
public:
	static AuthServer &GetInstance();

private:
	AuthServer();
	~AuthServer();

	//variables
	struct event_base *pAuthEventBase;
	struct evconnlistener *pAuthListener;

	static void OnAcceptConn(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx);
	static void OnAcceptError(struct evconnlistener *listener, void *ctx);
	static void OnBuffereventArrive(struct bufferevent *bev, short events, void *ctx);
	static void OnBuffereventRead(struct bufferevent *bev, void *ctx);

	static void ProcessPacket(authclient_t *pClientInst);
	static int ProcessPacketHeader(authclient_t *pClientInst);
	static int InitialiseCWCInstance(authclient_t *pClientInst);
	static int SendUnknown11Bytes(authclient_t *pClientInst);
	static int GetServiceStatus(authclient_t *pClientInst);
	static int BeginHandshake(authclient_t *pClientInst);
	static int ValidateAuthSessionTicket(authclient_t *pClientInst);
	static int EncryptCWCPacket(authclient_t *pClientInst, unsigned char *pPayload, int pPayloadLength);
	static int DecryptCWCPacket(authclient_t *pClientInst, unsigned char *pPayload);

	static int SendPacket(authclient_t *pClientInst, char *pPayloadBuffer, int iPayloadSize);
	static void GenerateRandomBytes(char *pArray, int iNumOfBytes);
};
*/
#endif