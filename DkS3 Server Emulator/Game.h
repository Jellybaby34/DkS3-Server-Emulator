#pragma once
#ifndef GAMESERVER_HEADER_FILE
#define GAMESERVER_HEADER_FILE

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <cwc.h>

#include <vector>
#include "threadpool_queue.h"

#include "Constants.h"
#include "Logging.h"

namespace GameServer {

	typedef struct CwcInstance_t {
		// Symmetrical encryption data
		unsigned char aesCwcKey[17]; // 128 bit key + null terminator
		cwc_ctx cwcCtx;
	} CwcInstance_t;

	typedef struct gameclient_t {
		unsigned long long sessionToken; // 8 byte session token thats at the start of every UDP packet
		time_t timeSinceLastPacket;
		CwcInstance_t *cwcInstance;
	} gameclient_t;

	extern atomic_blocking_queue<gameclient_t> gameClientQueue;
	extern std::vector<gameclient_t> gameClientVector;
	extern void Initialise();
}

#endif