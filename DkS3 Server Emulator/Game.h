#pragma once
#ifndef GAMESERVER_HEADER_FILE
#define GAMESERVER_HEADER_FILE

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <cwc.h>

#include "Constants.h"
#include "Logging.h"

namespace GameServer {


	extern void Initialise();
}

#endif