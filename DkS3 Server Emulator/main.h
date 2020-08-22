#ifndef MAIN_HEADER_FILE
#define MAIN_HEADER_FILE

#include <iostream>

#include <event2/thread.h>
#include <openssl/applink.c>

#include "stdafx.h"
#include "Constants.h"
#include "Logging.h"
#include "RSA.h"
#include "Login.h"
#include "Auth.h"

#pragma comment (lib, "ws2_32.lib")

void StartServer();

#endif