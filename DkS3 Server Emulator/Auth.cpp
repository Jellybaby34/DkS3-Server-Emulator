#include "Auth.h"

namespace AuthServer {

	bool isInitialised;
	struct event_base *authEventBase;
	struct evconnlistener *authListener;

	void Initialise() {

		if (isInitialised) {
			LOG_ERROR("[AuthServer::Initialise] Tried to re-initialise the login server");
			return;
		}

		LOG_PRINT("[AuthServer::Initialise] Starting LoginServer instance");
		authEventBase = event_base_new();
		if (authEventBase == NULL) {
			LOG_ERROR("[AuthServer::Initialise] Couldn't create new event base");
			return;
		}

		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(0);
		sin.sin_port = htons(LOGINPORT);

		authListener = evconnlistener_new_bind(authEventBase, OnAcceptConnection, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin));
		if (authListener == NULL) {
			LOG_ERROR("[AuthServer::Initialise] Couldn't create event connection listener");
			return;
		}
		isInitialised = true;

		evconnlistener_set_error_cb(authListener, OnAcceptError);
		event_base_dispatch(authEventBase);
	}

	void OnAcceptConnection(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx) {
		struct event_base *base = evconnlistener_get_base(listener);
		authclient_t *clientInstance;
		sockaddr_in *clientInfo = (sockaddr_in*)address;

		clientInstance = (authclient_t*)calloc(1, sizeof(authclient_t));
		if (clientInstance == NULL) {
			LOG_ERROR("[AuthServer::OnAcceptConnection] Failed to create client instance for %s:%i. Abandoning connection", inet_ntoa(clientInfo->sin_addr), clientInfo->sin_port);
			return;
		}

		struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
		clientInstance->fd = fd;
		clientInstance->buf_ev = bev;
		clientInstance->input_buffer = bufferevent_get_input(bev);
		clientInstance->output_buffer = bufferevent_get_output(bev);

		bufferevent_setcb(bev, OnBuffereventRead, NULL, OnBuffereventArrive, clientInstance);
		bufferevent_enable(bev, EV_READ | EV_WRITE);

		LOG_SUCCESS("[AuthServer::OnAcceptConnection] Accepting connection from: %s:%i", inet_ntoa(clientInfo->sin_addr), clientInfo->sin_port);
	}

	void OnAcceptError(struct evconnlistener *listener, void *ctx) {
		struct event_base *base = evconnlistener_get_base(listener);
		int errorCode = EVUTIL_SOCKET_ERROR();

		LOG_ERROR("[AuthServer::OnAcceptError] Got error code: %i (%s), on the listener. Shutting down", errorCode, evutil_socket_error_to_string(errorCode));
		event_base_loopexit(base, NULL);
	}

	void OnBuffereventRead(struct bufferevent *bev, void *ctx) {
		threadPool.enqueue_work(ProcessPacket, (authclient_t*)ctx);
	}
}


/*
AuthServer::AuthServer()
{
	LOG_PRINT("[AuthServer::AuthServer] Starting AuthServer instance");

	struct sockaddr_in sin;
	this->pAuthEventBase = event_base_new();

	if (this->pAuthEventBase == NULL)
	{
		LOG_ERROR("[AuthServer::AuthServer] Couldn't create new event base");
		return;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0);
	sin.sin_port = htons(AUTHPORT);

	this->pAuthListener = evconnlistener_new_bind(this->pAuthEventBase, OnAcceptConn, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin));
	if (this->pAuthListener == NULL)
	{
		LOG_ERROR("[AuthServer::AuthServer] Couldn't create listener");
		return;
	}

	evconnlistener_set_error_cb(this->pAuthListener, OnAcceptError);
	event_base_dispatch(this->pAuthEventBase);
}

AuthServer::~AuthServer()
{

}

AuthServer &AuthServer::GetInstance()
{
	static AuthServer s_Authserver;
	return s_Authserver;
}

void AuthServer::OnAcceptError(struct evconnlistener *listener, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(listener);
	int iErr = EVUTIL_SOCKET_ERROR();

	LOG_ERROR("[AuthServer::OnAcceptError] Got error code: %i (%s), on the listener. Shutting down", iErr, evutil_socket_error_to_string(iErr));

	event_base_loopexit(base, NULL);
}

void AuthServer::OnAcceptConn(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(listener);

	authclient_t *pClientInst = {};
	sockaddr_in* client_in = (sockaddr_in*)address;

	pClientInst = (authclient_t*)calloc(1, sizeof(*pClientInst));
	if (pClientInst == NULL)
	{
		LOG_ERROR("[AuthServer::OnAcceptConn] Failed to create client instance for %s:%i, abandoning connection", inet_ntoa(client_in->sin_addr), client_in->sin_port);
		return;
	}

	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
	pClientInst->fd = fd;
	pClientInst->buf_ev = bev;
	pClientInst->input_buffer = bufferevent_get_input(bev);
	pClientInst->output_buffer = bufferevent_get_output(bev);
	pClientInst->connectionstatus = ConnectionStatus::CONNECTING;

	bufferevent_setcb(bev, OnBuffereventRead, NULL, OnBuffereventArrive, pClientInst);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	LOG_SUCCESS("[AuthServer::OnAcceptConn] Accepting connection from: %s:%i", inet_ntoa(client_in->sin_addr), client_in->sin_port);
}

void AuthServer::OnBuffereventRead(struct bufferevent *bev, void *ctx)
{
//	tpThreadPool.enqueue_work(AuthServer::ProcessPacket, (authclient_t*)ctx);
	AuthServer::ProcessPacket((authclient_t*)ctx);
}

void AuthServer::OnBuffereventArrive(struct bufferevent *bev, short events, void *ctx)
{
	if (events & BEV_EVENT_ERROR)
		LOG_ERROR("[AuthServer::OnBuffereventArrive] Error from bufferevent");

	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		LOG_PRINT("[AuthServer::OnBuffereventArrive] Closing connection");
		if (ctx != NULL)
		{
			free((authclient_t*)ctx);
			LOG_PRINT("[AuthServer::OnBuffereventArrive] Freed client data struct");
		}
		bufferevent_free(bev);
	}

	if (events & BEV_EVENT_CONNECTED) {
		LOG_SUCCESS("[AuthServer::OnBuffereventArrive] Client connected");
	}
	else if (events & BEV_EVENT_TIMEOUT) {
		LOG_ERROR("[AuthServer::OnBuffereventArrive] Client connect timed out");
	}
}

void AuthServer::ProcessPacket(authclient_t *pClientInst)
{
	LOG_PRINT("Received new packet");
	evbuffer_pullup(pClientInst->input_buffer, -1);
	PrintBytes((char*)evbuffer_pullup(pClientInst->input_buffer, -1), evbuffer_get_length(pClientInst->input_buffer));

	if (AuthServer::ProcessPacketHeader(pClientInst) == FUNCTION_ERROR)
	{
		LOG_ERROR("[AuthServer::ProcessPacket] Received packet header was invalid");
		bufferevent_free(pClientInst->buf_ev);
		return;
	};

	switch (pClientInst->connectionstatus)
	{
		case ConnectionStatus::CONNECTING:
		{
			if (AuthServer::InitialiseCWCInstance(pClientInst) == FUNCTION_ERROR)
			{
				LOG_ERROR("[AuthServer::ProcessPacket] Failed to initialise client CWC instance");
				bufferevent_free(pClientInst->buf_ev);
				return;
			}

			if (AuthServer::SendUnknown11Bytes(pClientInst) == FUNCTION_ERROR)
			{
				LOG_ERROR("[AuthServer::ProcessPacket] Failed to send unknown 11 bytes");
				bufferevent_free(pClientInst->buf_ev);
				return;
			}

			pClientInst->connectionstatus = ConnectionStatus::AESINITIALISED;
			return;
		}

		case ConnectionStatus::AESINITIALISED:
		{
			if (AuthServer::GetServiceStatus(pClientInst) == FUNCTION_ERROR)
			{
				LOG_ERROR("[AuthServer::ProcessPacket] Failed to get service status");
				bufferevent_free(pClientInst->buf_ev);
				return;
			}

			pClientInst->connectionstatus = ConnectionStatus::HANDSHAKE;
			return;
		}

		case ConnectionStatus::HANDSHAKE:
		{
			if (AuthServer::BeginHandshake(pClientInst) == FUNCTION_ERROR)
			{
				LOG_ERROR("[AuthServer::ProcessPacket] Failed to handshake");
				bufferevent_free(pClientInst->buf_ev);
				return;
			}

			pClientInst->connectionstatus = ConnectionStatus::TICKET;
			return;
		}

		case ConnectionStatus::TICKET:
		{
			if (AuthServer::ValidateAuthSessionTicket(pClientInst) == FUNCTION_ERROR)
			{
				LOG_ERROR("[AuthServer::ProcessPacket] Failed to validate received AUthSession ticket");
				bufferevent_free(pClientInst->buf_ev);
				return;
			}
		}
	}

	LOG_PRINT("END PROCESS PACKET");
}

int AuthServer::ProcessPacketHeader(authclient_t *pClientInst)
{
	LOG_PRINT("[AuthServer::ProcessPacketHeader] Processing packet header");

	char pHeader[sizeof(loginclientpacketheader_t) + 1] = {};

	loginclientpacketheader_t *pClientHeader = (loginclientpacketheader_t*)pHeader;
	size_t iTotalPacketLength = evbuffer_get_length(pClientInst->input_buffer);
	int iHeaderLength = sizeof(loginclientpacketheader_t);

	if (evbuffer_remove(pClientInst->input_buffer, pHeader, iHeaderLength) != iHeaderLength)
	{
		LOG_ERROR("[AuthServer::ProcessPacketHeader] Failed to parse header from buffer");
		return FUNCTION_ERROR;
	}

	if (ntohs(pClientHeader->packetlengthtype1) != iTotalPacketLength - 2)
	{
		LOG_ERROR("[AuthServer::ProcessPacketHeader] Received length #1 in packet was not as expected. Expected: %i, received: %i", iTotalPacketLength - 2, ntohs(pClientHeader->packetlengthtype1));
		return FUNCTION_ERROR;
	}

	// ClientHeader->sentpacketscounter is here which we can do something with if we want.

	if (ntohs(pClientHeader->unknown1) != 0)
	{
		LOG_ERROR("[AuthServer::ProcessPacketHeader] Received unknown #1 in packet was not as expected. Expected: %i, received: %i", 0, ntohs(pClientHeader->unknown1));
		return FUNCTION_ERROR;
	}

	if (ntohl(pClientHeader->packetlengthtype2A) != iTotalPacketLength - 14)
	{
		LOG_ERROR("[AuthServer::ProcessPacketHeader] Received length #2 in packet was not as expected. Expected: %i, received: %i", iTotalPacketLength - 14, ntohl(pClientHeader->packetlengthtype2A));
		return FUNCTION_ERROR;
	}

	if (ntohl(pClientHeader->packetlengthtype2B) != iTotalPacketLength - 14)
	{
		LOG_ERROR("[AuthServer::ProcessPacketHeader] Received length #3 in packet was not as expected. Expected: %i, received: %i", iTotalPacketLength - 14, ntohl(pClientHeader->packetlengthtype2B));
		return FUNCTION_ERROR;
	}

	if (ntohl(pClientHeader->unknown2) != 0x0C)
	{
		LOG_ERROR("[AuthServer::ProcessPacketHeader] Received unknown #2 in packet was not as expected. Expected: %i, received: %i", 0x0C, ntohl(pClientHeader->unknown2));
		return FUNCTION_ERROR;
	}

	if (ntohl(pClientHeader->unknown3) != 5)
	{
		LOG_WARN("[AuthServer::ProcessPacketHeader] Received unknown #3 in packet was not as expected. Expected: %i, received: %i. Continuing", 5, ntohl(pClientHeader->unknown3));
	}

	pClientInst->clientcounter = pClientHeader->receivedcounter;

	return FUNCTION_SUCCESS;
}

int AuthServer::InitialiseCWCInstance(authclient_t *pClientInst)
{
	char pPayload[1024];
	char pRecvDataBuffer[1024];

	size_t iRecvDataLength = evbuffer_get_length(pClientInst->input_buffer);
	//	unsigned char *pRecvDataBuffer = evbuffer_pullup(input, -1);

	if (evbuffer_remove(pClientInst->input_buffer, pRecvDataBuffer, iRecvDataLength) != iRecvDataLength)
	{
		LOG_ERROR("[AuthServer::InitialiseCWCInstance] Failed to drain buffer.");
		return FUNCTION_ERROR;
	}

	int iPayloadSize = RSAdecrypt(iRecvDataLength, (unsigned char*)pRecvDataBuffer, (unsigned char*)pPayload);
	if (iPayloadSize < 1)
	{
		LOG_ERROR("[AuthServer::InitialiseCWCInstance] Failed to decrypt RSA payload.");
		return FUNCTION_ERROR;
	}

	Frpg2RequestMessage::RequestHandshake pbRequestHandshake;

	if (!pbRequestHandshake.ParseFromArray(pPayload, iPayloadSize))
	{
		LOG_ERROR("[AuthServer::InitialiseCWCInstance] Failed to parse decrypted packet payload.");
		return FUNCTION_ERROR;
	}

	strncpy(pClientInst->aescwckey, pbRequestHandshake.aescwckey().c_str(), 16);

	if (cwc_init_and_key((unsigned char*)pClientInst->aescwckey, 16, &pClientInst->cwcctx) == FUNCTION_ERROR)
	{
		LOG_ERROR("[AuthServer::InitialiseCWCInstance] Failed to initialise AES CWC context.");
		return FUNCTION_ERROR;
	}

	GenerateRandomBytes(pClientInst->unknown1, 11);

	return FUNCTION_SUCCESS;
}

void AuthServer::GenerateRandomBytes(char *pArray, int iNumOfBytes)
{
	std::random_device rd;
	static std::mt19937 g(rd());
	std::uniform_int_distribution<> dist(0, 255);

	for (int i = 0; i < iNumOfBytes; i++)
	{
		unsigned char iRand = dist(g);
		pArray[i] = iRand;
	}
}

int AuthServer::SendUnknown11Bytes(authclient_t *pClientInst)
{
	LOG_PRINT("[AuthServer::SendUnknown11Bytes] Sending unknown 11 bytes");

	char pEncryptedPayloadBuffer[32] = {};

	memcpy(pEncryptedPayloadBuffer, pClientInst->unknown1, 11);

	return AuthServer::SendPacket(pClientInst, pEncryptedPayloadBuffer, 27);
}

int AuthServer::GetServiceStatus(authclient_t *pClientInst)
{
	unsigned char pPayload[1024];
	int iPayloadLength = AuthServer::DecryptCWCPacket(pClientInst, pPayload);

	if (iPayloadLength < FUNCTION_SUCCESS)
	{
		LOG_ERROR("[AuthServer::GetServiceStatus] Failed to parse CWC payload");
		return FUNCTION_ERROR;
	}

	Frpg2RequestMessage::GetServiceStatus pbGetServiceStatus;

	if (!pbGetServiceStatus.ParseFromArray(pPayload, iPayloadLength))
	{
		LOG_ERROR("[AuthServer::GetServiceStatus] Failed to parse decrypted packet payload into protobuf format.");
		return FUNCTION_ERROR;
	}

	if (pbGetServiceStatus.id() != 1)
	{
		LOG_ERROR("[AuthServer::GetServiceStatus] Protobuf packet ID not expected value. Expected: 1, Got: %i", pbGetServiceStatus.id());
		return FUNCTION_ERROR;
	}

	strncpy(pClientInst->steamidstring, pbGetServiceStatus.steamid().c_str(), 16);
	pClientInst->clientversion = pbGetServiceStatus.versionnum();

	Frpg2RequestMessage::GetServiceStatusResponse pbGetServiceStatusResponse;
	pbGetServiceStatusResponse.set_id(2);
	pbGetServiceStatusResponse.set_steamid("\x00", 0);
	pbGetServiceStatusResponse.set_unknownfield(0);
	pbGetServiceStatusResponse.set_versionnum(0);

	int iProtobufMsgLength = pbGetServiceStatusResponse.ByteSize();
	pbGetServiceStatusResponse.SerializeToArray(pPayload, iProtobufMsgLength);

	PrintBytes((char*)pPayload, iProtobufMsgLength);

	AuthServer::EncryptCWCPacket(pClientInst, pPayload, iProtobufMsgLength);
}

int AuthServer::BeginHandshake(authclient_t *pClientInst)
{
	unsigned char pPayload[1024];
	int iPayloadLength = AuthServer::DecryptCWCPacket(pClientInst, pPayload);

	if (iPayloadLength < FUNCTION_SUCCESS)
	{
		LOG_ERROR("[AuthServer::BeginHandshake] Failed to parse CWC payload");
		return FUNCTION_ERROR;
	}

	memcpy(pClientInst->unknown2, pPayload, 8);
	GenerateRandomBytes(&pClientInst->unknown2[8], 8);

	return AuthServer::EncryptCWCPacket(pClientInst, (unsigned char*)pClientInst->unknown2, 16);
}

int AuthServer::ValidateAuthSessionTicket(authclient_t *pClientInst)
{
	LOG_PRINT("Auth Sesh");
	char *payload = "\x15\x1A\xCD\xAC\x48\xF6\xAB\x72\x31\x32\x37\x2E\x30\x2E\x30\x2E\x31\x00\x00\x00\xE0\x81\x02\xB8\x8D\x7F\x00\x00\x78\x3C\x2B\x01\x00\x00\x00\x00\x26\xE6\x57\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3E\xC6\x57\x00\x00\x00\x00\x00\x30\x03\x6F\x02\x00\x00\x00\x00\xA4\xBE\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\xC0\x89\xC4\x8D\x7F\x00\x00\x30\x03\x6F\x02\x00\x00\x00\x00\x67\x3B\x63\x00\x00\x00\x00\x00\x68\x03\x6F\x02\x00\x00\x00\x00\xE0\x81\x02\xB8\x8D\x7F\x00\x00\x30\x03\x6F\x02\x00\x00\x00\x00\xC3\x51\x00\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\xA0\x00\x00\x00\xA0\x00\x00\x00\x00\x80\x00\x00\x80\x00\x00\x00\xA0\x00\x00\x04\x93\xE0\x00\x00\x61\xA8\x00\x00\x00\x0C\x00\x00\x00\x00";
	unsigned char pPayload[1024] = {};

	memcpy(pPayload, payload, 184);

	PrintBytes((char*)pPayload, 184);
	return AuthServer::EncryptCWCPacket(pClientInst, pPayload, 184);
}

int AuthServer::EncryptCWCPacket(authclient_t *pClientInst, unsigned char *pPayload, int iPayloadLength)
{
	LOG_PRINT("[AuthServer::EncryptCWCPacket] Encrypting packet with CWC");

	unsigned char pPacketIV[11];
	unsigned char pPacketTag[17]; // 16 bytes at start are the tag
	unsigned char pEncryptedPayload[1024];

	GenerateRandomBytes((char*)pPacketIV, 11);

	if (cwc_encrypt_message(pPacketIV, 11, pPacketIV, 11, pPayload, iPayloadLength, pPacketTag, 16, &pClientInst->cwcctx) == FUNCTION_ERROR)
	{
		LOG_ERROR("[AuthServer::ProcessCWCPacket] Failed to encrypt packet");
		return FUNCTION_ERROR;
	}


	memcpy(pEncryptedPayload, pPacketIV, 11);
	memcpy(&pEncryptedPayload[11], pPacketTag, 16);
	memcpy(&pEncryptedPayload[27], pPayload, iPayloadLength);

	return AuthServer::SendPacket(pClientInst, (char*)pEncryptedPayload, iPayloadLength + 27);
}

int AuthServer::DecryptCWCPacket(authclient_t *pClientInst, unsigned char *pPayload)
{
	LOG_PRINT("[AuthServer::DecryptCWCPacket] Decrypting CWC encrypted packet");

	unsigned char pPacketIV[12]; // 11 bytes at the start are the IV
	unsigned char pPacketTag[17]; // 16 bytes at start are the tag computed after encryption but stuck at the front of the packet I think
	//	unsigned char pEncryptedPayload[1024];

	size_t iRecvDataLength = evbuffer_get_length(pClientInst->input_buffer);

	if (evbuffer_remove(pClientInst->input_buffer, pPacketIV, 11) != 11)
	{
		LOG_ERROR("[AuthServer::DecryptCWCPacket] Failed to drain IV");
		return FUNCTION_ERROR;
	}

	if (evbuffer_remove(pClientInst->input_buffer, pPacketTag, 16) != 16)
	{
		LOG_ERROR("[AuthServer::DecryptCWCPacket] Failed to drain tag");
		return FUNCTION_ERROR;
	}

	if (evbuffer_remove(pClientInst->input_buffer, pPayload, iRecvDataLength - 27) != iRecvDataLength - 27)
	{
		LOG_ERROR("[AuthServer::DecryptCWCPacket] Failed to drain payload");
		return FUNCTION_ERROR;
	}

	PrintBytes((char*)pPacketIV, 11);
	PrintBytes((char*)pPacketTag, 16);
	PrintBytes((char*)pPayload, iRecvDataLength - 27);

	if (cwc_decrypt_message(pPacketIV, 11, pPacketIV, 11, pPayload, iRecvDataLength - 27, pPacketTag, 16, &pClientInst->cwcctx) == FUNCTION_ERROR)
	{
		LOG_ERROR("[AuthServer::DecryptCWCPacket] Failed to decrypt packet");
		return FUNCTION_ERROR;
	}

	LOG_PRINT("Decrypted CWC payload");
	PrintBytes((char*)pPayload, iRecvDataLength - 27);

	return iRecvDataLength - 27;
}


int AuthServer::SendPacket(authclient_t *pClientInst, char *pPayloadBuffer, int iPayloadSize)
{
	LOG_PRINT("[GameServer::SendPacket] Sending packet");

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

	LOG_PRINT("Sending packet...");
	PrintBytes(pPacketBuffer, iTotalPacketLength);

	if (bufferevent_write(pClientInst->buf_ev, pPacketBuffer, iTotalPacketLength) == FUNCTION_ERROR)
	{
		LOG_ERROR("[GameServer::SendPacket] Failed to send packet");
		return FUNCTION_ERROR;
	};

	return FUNCTION_SUCCESS;
}
*/