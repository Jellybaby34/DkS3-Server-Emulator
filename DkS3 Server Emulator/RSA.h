#pragma once
#ifndef RSA_HEADER_FILE
#define RSA_HEADER_FILE

#include <fstream>

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "stdafx.h"
#include "Constants.h"
#include "Logging.h"

extern RSA* privateRSAKeyInstance;

int RSADecrypt(int length, const unsigned char* from, unsigned char* to);
int RSAEncrypt(int length, const unsigned char* from, unsigned char* to);
int HandleRSAKeyStartup();
int GenerateRSAKeyPair();
int CleanupLineEndings(char* fileName);
int EncryptRSAPublicKeyAndDNS(char* pubKeyFileName, char* ipAddress);
void TinyEncryptionAlgorithm(unsigned int *value);

#endif