#include "Login.h"

namespace LoginServer {

	bool isInitialised;
	struct event_base *loginEventBase;
	struct evconnlistener *loginListener;

	void Initialise() {

		if (isInitialised) {
			LOG_ERROR("[LoginServer::Initialise] Tried to re-initialise the login server");
			return;
		}

		LOG_PRINT("[LoginServer::Initialise] Starting LoginServer instance");
		loginEventBase = event_base_new();
		if (loginEventBase == NULL) {
			LOG_ERROR("[LoginServer::Initialise] Couldn't create new event base");
			return;
		}

		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(0);
		sin.sin_port = htons(LOGINPORT);

		loginListener = evconnlistener_new_bind(loginEventBase, OnAcceptConnection, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin));
		if (loginListener == NULL) {
			LOG_ERROR("[LoginServer::Initialise] Couldn't create event connection listener");
			return;
		}
		isInitialised = true;

		evconnlistener_set_error_cb(loginListener, OnAcceptError);
		event_base_dispatch(loginEventBase);
	}

	void OnAcceptConnection(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx) {
		struct event_base *base = evconnlistener_get_base(listener);
		loginclient_t *clientInstance;
		sockaddr_in *clientInfo = (sockaddr_in*)address;

		clientInstance = (loginclient_t*)calloc(1, sizeof(loginclient_t));
		if (clientInstance == NULL) {
			LOG_ERROR("[LoginServer::OnAcceptConnection] Failed to create client instance for %s:%i. Abandoning connection", inet_ntoa(clientInfo->sin_addr), clientInfo->sin_port);
			return;
		}

		struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
		clientInstance->fd = fd;
		clientInstance->buf_ev = bev;
		clientInstance->input_buffer = bufferevent_get_input(bev);
		clientInstance->output_buffer = bufferevent_get_output(bev);

		bufferevent_setcb(bev, OnBuffereventRead, NULL, OnBuffereventArrive, clientInstance);
		bufferevent_enable(bev, EV_READ | EV_WRITE);

		LOG_SUCCESS("[LoginServer::OnAcceptConnection] Accepting connection from: %s:%i", inet_ntoa(clientInfo->sin_addr), clientInfo->sin_port);
	}

	void OnAcceptError(struct evconnlistener *listener, void *ctx) {
		struct event_base *base = evconnlistener_get_base(listener);
		int errorCode = EVUTIL_SOCKET_ERROR();

		LOG_ERROR("[LoginServer::OnAcceptError] Got error code: %i (%s), on the listener. Shutting down", errorCode, evutil_socket_error_to_string(errorCode));
		event_base_loopexit(base, NULL);
	}

	void OnBuffereventRead(struct bufferevent *bev, void *ctx) {
		threadPool.enqueue_work(ProcessPacket, (loginclient_t*)ctx);
	}

	void OnBuffereventArrive(struct bufferevent *bev, short events, void *ctx) {
		if (events & BEV_EVENT_ERROR)
			LOG_ERROR("[LoginServer::OnBuffereventArrive] Error from bufferevent");

		if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
			LOG_PRINT("[LoginServer::OnBuffereventArrive] Closing connection");
			if (ctx != NULL) {
				free((loginclient_t*)ctx);
				LOG_PRINT("[LoginServer::OnBuffereventArrive] Freed client data struct");
			}
			bufferevent_free(bev);
		}

		if (events & BEV_EVENT_CONNECTED) {
			LOG_SUCCESS("[LoginServer::OnBuffereventArrive] Client connected");
		}
		else if (events & BEV_EVENT_TIMEOUT) {
			LOG_ERROR("[LoginServer::OnBuffereventArrive] Client connect timed out");
		}
	}

	void ProcessPacket(loginclient_t *clientInstance) {
		if (ProcessPacketHeader(clientInstance) == FUNCTION_ERROR) {
			LOG_ERROR("[LoginServer::ProcessPacket] Received packet header was invalid");
			bufferevent_free(clientInstance->buf_ev);
			return;
		};

		if (ProcessPacketPayload(clientInstance) == FUNCTION_ERROR) {
			LOG_ERROR("[LoginServer::ProcessPacket] Received packet payload was invalid");
			bufferevent_free(clientInstance->buf_ev);
			return;
		};

		LOG_PRINT("[LoginServer::ProcessPacket] Steam ID: %s connected to login server with version: %i", clientInstance->steamidstring, clientInstance->clientversion);
		SendGameServerInfo(clientInstance);
	}

	int ProcessPacketHeader(loginclient_t *clientInstance) {
		LOG_PRINT("[LoginServer::ProcessPacketHeader] Processing packet header");

		loginclientpacketheader_t header = {};
		size_t totalPacketLength = evbuffer_get_length(clientInstance->input_buffer);
		int headerLength = sizeof(loginclientpacketheader_t);

		if (evbuffer_remove(clientInstance->input_buffer, &header, headerLength) != headerLength) {
			LOG_ERROR("[LoginServer::ProcessPacketHeader] Failed to parse header from input buffer");
			return FUNCTION_ERROR;
		}

		if (ntohs(header.packetLengthType1) != totalPacketLength - 2) {
			LOG_ERROR("[LoginServer::ProcessPacketHeader] Received length #1 in packet was not as expected. Expected: %i, received: %i", totalPacketLength - 2, ntohs(header.packetLengthType1));
			return FUNCTION_ERROR;
		}

		// Clientheader.sentpacketscounter is here which we can do something with if we want.

		if (ntohs(header.unknown1) != 0) {
			LOG_ERROR("[LoginServer::ProcessPacketHeader] Received unknown #1 in packet was not as expected. Expected: %i, received: %i", 0, ntohs(header.unknown1));
			return FUNCTION_ERROR;
		}

		if (ntohl(header.packetLengthType2A) != totalPacketLength - 14) {
			LOG_ERROR("[LoginServer::ProcessPacketHeader] Received length #2 in packet was not as expected. Expected: %i, received: %i", totalPacketLength - 14, ntohl(header.packetLengthType2A));
			return FUNCTION_ERROR;
		}

		if (ntohl(header.packetLengthType2B) != totalPacketLength - 14) {
			LOG_ERROR("[LoginServer::ProcessPacketHeader] Received length #3 in packet was not as expected. Expected: %i, received: %i", totalPacketLength - 14, ntohl(header.packetLengthType2B));
			return FUNCTION_ERROR;
		}

		if (ntohl(header.unknown2) != 0x0C) {
			LOG_ERROR("[LoginServer::ProcessPacketHeader] Received unknown #2 in packet was not as expected. Expected: %i, received: %i", 0x0C, ntohl(header.unknown2));
			return FUNCTION_ERROR;
		}

		if (ntohl(header.unknown3) != 5) {
			LOG_WARN("[LoginServer::ProcessPacketHeader] Received unknown #3 in packet was not as expected. Expected: %i, received: %i. Continuing", 5, ntohl(header.unknown3));
		}

		clientInstance->clientcounter = header.receivedCounter;
		return FUNCTION_SUCCESS;
	}

	int ProcessPacketPayload(loginclient_t *clientInstance) {
		LOG_PRINT("[LoginServer::ProcessPacketPayload] Processing packet payload");

		unsigned char payloadBuffer[1024];
		size_t receivedDataLength = evbuffer_get_length(clientInstance->input_buffer);
		unsigned char *receivedDataBuffer = evbuffer_pullup(clientInstance->input_buffer, -1);

		int payloadSize = RSADecrypt(receivedDataLength, receivedDataBuffer, payloadBuffer);
		if (payloadSize < 1) {
			LOG_ERROR("[LoginServer::ProcessPacketPayload] Failed to decrypt RSA payload.");
			return FUNCTION_ERROR;
		}
		evbuffer_drain(clientInstance->input_buffer, receivedDataLength);

		Frpg2RequestMessage::RequestQueryLoginServerInfo pbRequestQueryLoginServerInfo;
		if (!pbRequestQueryLoginServerInfo.ParseFromArray(payloadBuffer, payloadSize)) {
			LOG_ERROR("[LoginServer::ProcessPacketPayload] Failed to parse decrypted packet payload.");
			return FUNCTION_ERROR;
		}

		clientInstance->clientversion = pbRequestQueryLoginServerInfo.versionnum();
		strncpy(clientInstance->steamidstring, pbRequestQueryLoginServerInfo.steamid().c_str(), 16);

		return FUNCTION_SUCCESS;
	}

	int SendGameServerInfo(loginclient_t *clientInstance) {
		LOG_PRINT("[LoginServer::SendGameServerInfo] Sending game server info to Steam ID: %s", clientInstance->steamidstring);

		unsigned char protobufBuffer[64];
		unsigned char encryptedPayloadBuffer[1024];

		Frpg2RequestMessage::RequestQueryLoginServerInfoResponse pbRequestQueryLoginServerInfoResponse;
		pbRequestQueryLoginServerInfoResponse.set_port(AUTHPORT);
		pbRequestQueryLoginServerInfoResponse.set_serverip(SERVERIP);

		int size = pbRequestQueryLoginServerInfoResponse.ByteSize();
		pbRequestQueryLoginServerInfoResponse.SerializeToArray(protobufBuffer, size);
		int payloadSize = RSAEncrypt(size, protobufBuffer, encryptedPayloadBuffer);

		return SendPacket(clientInstance, encryptedPayloadBuffer, payloadSize);
	}

	int SendPacket(loginclient_t *clientInstance, unsigned char *payloadBuffer, int payloadSize) {
		char packetBuffer[2048];
		loginserverpacketheader_t packetHeader = {};

		int totalPacketLength = payloadSize + sizeof(loginserverpacketheader_t);

		packetHeader.packetlengthtype1 = htons(totalPacketLength - 2);
		packetHeader.packetlengthtype2A = htonl(totalPacketLength - 14);
		packetHeader.packetlengthtype2B = htonl(totalPacketLength - 14);
		packetHeader.unknown2 = htonl(0x0C);
		packetHeader.receivedcounter = clientInstance->clientcounter;
		packetHeader.unknown5 = htonl(0x01);

		memcpy(packetBuffer, &packetHeader, sizeof(loginserverpacketheader_t));
		memcpy(&packetBuffer[sizeof(loginserverpacketheader_t)], payloadBuffer, payloadSize);

		if (bufferevent_write(clientInstance->buf_ev, packetBuffer, totalPacketLength) == FUNCTION_ERROR) {
			LOG_ERROR("[LoginServer::SendPacket] Failed to send packet");
			return FUNCTION_ERROR;
		};

		return FUNCTION_SUCCESS;
	}
}


/*
LoginServer::LoginServer()
{
	LOG_PRINT("[LoginServer::LoginServer] Starting LoginServer instance");

	this->pLoginEventBase = event_base_new();
	if (this->pLoginEventBase == NULL)
	{
		LOG_ERROR("[LoginServer::LoginServer] Couldn't create new event base");
		return;
	}

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0);
	sin.sin_port = htons(LOGINPORT);

	this->pLoginListener = evconnlistener_new_bind(this->pLoginEventBase, OnAcceptConn, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin));
	if (this->pLoginListener == NULL)
	{
		LOG_ERROR("[LoginServer::LoginServer] Couldn't create event connection listener");
		return;
	}

	evconnlistener_set_error_cb(this->pLoginListener, OnAcceptError);
	event_base_dispatch(this->pLoginEventBase);
}

LoginServer::~LoginServer()
{

}

LoginServer &LoginServer::GetInstance()
{
	static LoginServer s_loginserver;
	return s_loginserver;
}

void LoginServer::OnAcceptError(struct evconnlistener *listener, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(listener);
	int iErr = EVUTIL_SOCKET_ERROR();

	LOG_ERROR("[LoginServer::OnAcceptError] Got error code: %i (%s), on the listener. Shutting down", iErr, evutil_socket_error_to_string(iErr));

	event_base_loopexit(base, NULL);
}

void LoginServer::OnAcceptConn(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(listener);
	loginclient_t *pClientInst;
	sockaddr_in* client_in = (sockaddr_in*)address;

	pClientInst = (loginclient_t*)calloc(1, sizeof(*pClientInst));
	if (pClientInst == NULL)
	{
		LOG_ERROR("[LoginServer::OnAcceptConn] Failed to create client instance for %s:%i. Abandoning connection", inet_ntoa(client_in->sin_addr), client_in->sin_port);
		return;
	}

	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	pClientInst->fd = fd;
	pClientInst->buf_ev = bev;
	pClientInst->input_buffer = bufferevent_get_input(bev);
	pClientInst->output_buffer = bufferevent_get_output(bev);

	bufferevent_setcb(bev, OnBuffereventRead, NULL, OnBuffereventArrive, pClientInst);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	LOG_SUCCESS("[LoginServer::OnAcceptConn] Accepting connection from: %s:%i", inet_ntoa(client_in->sin_addr), client_in->sin_port);
}

void LoginServer::OnBuffereventRead(struct bufferevent *bev, void *ctx)
{
	tpThreadPool.enqueue_work(LoginServer::ProcessPacket, (loginclient_t*)ctx);
}

void LoginServer::OnBuffereventArrive(struct bufferevent *bev, short events, void *ctx)
{
	if (events & BEV_EVENT_ERROR)
		LOG_ERROR("[LoginServer::OnBuffereventArrive] Error from bufferevent");

	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		LOG_PRINT("[LoginServer::OnBuffereventArrive] Closing connection");
		if (ctx != NULL)
		{
			free((loginclient_t*)ctx);
			LOG_PRINT("[LoginServer::OnBuffereventArrive] Freed client data struct");
		}
		bufferevent_free(bev);
	}

	if (events & BEV_EVENT_CONNECTED) {
		LOG_SUCCESS("[LoginServer::OnBuffereventArrive] Client connected");
	}
	else if (events & BEV_EVENT_TIMEOUT) {
		LOG_ERROR("[LoginServer::OnBuffereventArrive] Client connect timed out");
	}
}

void LoginServer::ProcessPacket(loginclient_t *pClientInst)
{
	if (LoginServer::ProcessPacketHeader(pClientInst) == FUNCTION_ERROR)
	{
		LOG_ERROR("[LoginServer::ProcessPacket] Received packet header was invalid");
		bufferevent_free(pClientInst->buf_ev);
		return;
	};

	if (LoginServer::ProcessPacketPayload(pClientInst) == FUNCTION_ERROR)
	{
		LOG_ERROR("[LoginServer::ProcessPacket] Received packet payload was invalid");
		bufferevent_free(pClientInst->buf_ev);
		return;
	};

	LOG_PRINT("[LoginServer::ProcessPacket] Steam ID: %s logged in with version: %i", pClientInst->steamidstring, pClientInst->clientversion);

	LoginServer::SendGameServerInfo(pClientInst);
}

int LoginServer::ProcessPacketHeader(loginclient_t *pClientInst)
{
	LOG_PRINT("[LoginServer::ProcessPacketHeader] Processing packet header");

	char pHeader[sizeof(loginclientpacketheader_t) + 1] = {};
	loginclientpacketheader_t *pClientHeader = (loginclientpacketheader_t*)pHeader;
	size_t iTotalPacketLength = evbuffer_get_length(pClientInst->input_buffer);
	int iHeaderLength = sizeof(loginclientpacketheader_t);

	if (evbuffer_remove(pClientInst->input_buffer, pHeader, iHeaderLength) != iHeaderLength)
	{
		LOG_ERROR("[LoginServer::ProcessPacketHeader] Failed to parse header from buffer");
		return FUNCTION_ERROR;
	}

	if (ntohs(pClientHeader->packetlengthtype1) != iTotalPacketLength - 2)
	{
		LOG_ERROR("[LoginServer::ProcessPacketHeader] Received length #1 in packet was not as expected. Expected: %i, received: %i", iTotalPacketLength - 2, ntohs(pClientHeader->packetlengthtype1));
		return FUNCTION_ERROR;
	}

	// ClientHeader->sentpacketscounter is here which we can do something with if we want.

	if (ntohs(pClientHeader->unknown1) != 0)
	{
		LOG_ERROR("[LoginServer::ProcessPacketHeader] Received unknown #1 in packet was not as expected. Expected: %i, received: %i", 0, ntohs(pClientHeader->unknown1));
		return FUNCTION_ERROR;
	}

	if (ntohl(pClientHeader->packetlengthtype2A) != iTotalPacketLength - 14)
	{
		LOG_ERROR("[LoginServer::ProcessPacketHeader] Received length #2 in packet was not as expected. Expected: %i, received: %i", iTotalPacketLength - 14, ntohl(pClientHeader->packetlengthtype2A));
		return FUNCTION_ERROR;
	}

	if (ntohl(pClientHeader->packetlengthtype2B) != iTotalPacketLength - 14)
	{
		LOG_ERROR("[LoginServer::ProcessPacketHeader] Received length #3 in packet was not as expected. Expected: %i, received: %i", iTotalPacketLength - 14, ntohl(pClientHeader->packetlengthtype2B));
		return FUNCTION_ERROR;
	}

	if (ntohl(pClientHeader->unknown2) != 0x0C)
	{
		LOG_ERROR("[LoginServer::ProcessPacketHeader] Received unknown #2 in packet was not as expected. Expected: %i, received: %i", 0x0C, ntohl(pClientHeader->unknown2));
		return FUNCTION_ERROR;
	}

	if (ntohl(pClientHeader->unknown3) != 5)
	{
		LOG_WARN("[LoginServer::ProcessPacketHeader] Received unknown #3 in packet was not as expected. Expected: %i, received: %i. Continuing", 5, ntohl(pClientHeader->unknown3));
	}

	pClientInst->clientcounter = pClientHeader->receivedcounter;

	return FUNCTION_SUCCESS;
}

int LoginServer::ProcessPacketPayload(loginclient_t *pClientInst)
{

	LOG_PRINT("[LoginServer::ProcessPacketPayload] Processing packet payload");
	char pPayload[1024];

	size_t iRecvDataLength = evbuffer_get_length(pClientInst->input_buffer);
	unsigned char *pRecvDataBuffer = evbuffer_pullup(pClientInst->input_buffer, -1);

	int iPayloadSize = RSAdecrypt((int)iRecvDataLength, (unsigned char*)pRecvDataBuffer, (unsigned char*)pPayload);
	if (iPayloadSize < 1)
	{
		LOG_ERROR("[LoginServer::ProcessPacketPayload] Failed to decrypt RSA payload.");
		return FUNCTION_ERROR;
	}

	evbuffer_drain(pClientInst->input_buffer, iRecvDataLength);

	Frpg2RequestMessage::RequestQueryLoginServerInfo pbRequestQueryLoginServerInfo;

	if (!pbRequestQueryLoginServerInfo.ParseFromArray(pPayload, iPayloadSize))
	{
		LOG_ERROR("[LoginServer::ProcessPacketPayload] Failed to parse decrypted packet payload.");
		return FUNCTION_ERROR;
	}

	pClientInst->clientversion = pbRequestQueryLoginServerInfo.versionnum();
	strncpy(pClientInst->steamidstring, pbRequestQueryLoginServerInfo.steamid().c_str(), 16);

	return FUNCTION_SUCCESS;
}

int LoginServer::SendGameServerInfo(loginclient_t *pClientInst)
{
	LOG_PRINT("[LoginServer::SendGameServerInfo] Sending game server info to Steam ID: %s", pClientInst->steamidstring);

	Frpg2RequestMessage::RequestQueryLoginServerInfoResponse pbRequestQueryLoginServerInfoResponse;
	char pProtobufBuffer[64];
	char pEncryptedPayloadBuffer[1024];

	pbRequestQueryLoginServerInfoResponse.set_port(AUTHPORT);
	pbRequestQueryLoginServerInfoResponse.set_serverip(SERVERIP);

	int iSize = pbRequestQueryLoginServerInfoResponse.ByteSize();
	pbRequestQueryLoginServerInfoResponse.SerializeToArray(pProtobufBuffer, iSize);
	int iPayloadSize = RSAencrypt(iSize, (unsigned char*)pProtobufBuffer, (unsigned char*)pEncryptedPayloadBuffer);

	return LoginServer::SendPacket(pClientInst, pEncryptedPayloadBuffer, iPayloadSize);
}

int LoginServer::SendPacket(loginclient_t *pClientInst, char *pPayloadBuffer, int iPayloadSize)
{
	char pPacketBuffer[2048];
	loginserverpacketheader_t pPacketHeader = {};

	int iTotalPacketLength = iPayloadSize + sizeof(loginserverpacketheader_t);

	pPacketHeader.packetlengthtype1 = htons(iTotalPacketLength - 2);
	pPacketHeader.packetlengthtype2A = htonl(iTotalPacketLength - 14);
	pPacketHeader.packetlengthtype2B = htonl(iTotalPacketLength - 14);
	pPacketHeader.unknown2 = htonl(0x0C);
	pPacketHeader.receivedcounter = pClientInst->clientcounter;
	pPacketHeader.unknown5 = htonl(0x01);

	memcpy(pPacketBuffer, &pPacketHeader, sizeof(loginserverpacketheader_t));
	memcpy(&pPacketBuffer[sizeof(loginserverpacketheader_t)], pPayloadBuffer, iPayloadSize);

	if (bufferevent_write(pClientInst->buf_ev, pPacketBuffer, iTotalPacketLength) == FUNCTION_ERROR)
	{
		LOG_ERROR("[LoginServer::SendPacket] Failed to send packet");
		return FUNCTION_ERROR;
	};

	return FUNCTION_SUCCESS;
}

*/