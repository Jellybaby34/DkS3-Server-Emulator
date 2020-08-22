#include "RSA.h"

RSA *privateRSAKeyInstance;

int RSADecrypt(int length, const unsigned char* from, unsigned char* to) {

	if (length < 0 || length > 500) {
		LOG_ERROR("RSA decryption failed due to a weird length. Value: %i", length);
		return FUNCTION_ERROR;
	}

	int r;
	r = RSA_private_decrypt(length, from, to, privateRSAKeyInstance, RSA_PKCS1_OAEP_PADDING);
	if (r == -1) {
		LOG_ERROR("RSA decryption failed");
		long error_code = ERR_get_error();
		char* string = ERR_error_string(error_code, NULL);
		LOG_WARN("Error code: %li, %s", error_code, string);
		return FUNCTION_ERROR;
	}

	return r;
}

int RSAEncrypt(int length, const unsigned char* from, unsigned char* to) {

	if (length < 0 || length > 500) {
		LOG_ERROR("RSA encryption failed due to a weird length. Value: %i", length);
		return false;
	}

	int r;
	r = RSA_private_encrypt(length, from, to, privateRSAKeyInstance, RSA_X931_PADDING);
	if (r == -1) {
		LOG_ERROR("RSA encryption failed");
		long error_code = ERR_get_error();
		char* string = ERR_error_string(error_code, NULL);
		LOG_WARN("Error code: %li, %s", error_code, string);
		return FUNCTION_ERROR;
	}

	return r;
}

int HandleRSAKeyStartup()
{
	// Generate RSA key if not present
	FILE *privateRSAKeyFile = fopen("PrivateRSAKey", "r");

	if (privateRSAKeyFile == NULL)
	{
		LOG_WARN("[HandleRSAKeyStartup] No private RSA key file found. Generating new key pair");
		if (GenerateRSAKeyPair() == FUNCTION_ERROR)
		{
			LOG_ERROR("[HandleRSAKeyStartup] Generating key pair failed");
			return FUNCTION_ERROR;
		}
		privateRSAKeyFile = fopen("PrivateRSAKey", "r");

		if (privateRSAKeyFile == NULL)
		{
			LOG_ERROR("[HandleRSAKeyStartup] Opening new key pair failed");
			return FUNCTION_ERROR;
		};
	}

	privateRSAKeyInstance = RSA_new();
	PEM_read_RSAPrivateKey(privateRSAKeyFile, &privateRSAKeyInstance, NULL, NULL);

	return FUNCTION_SUCCESS;
}

int GenerateRSAKeyPair()
{
	int r;
	RSA *rsaInstance = RSA_new();
	BIGNUM *bignumInstance = BN_new();

	BIO *privateKeyFile = BIO_new_file("PrivateRSAKey", "w");
	BIO *publicKeyFile = BIO_new_file("PublicRSAKey", "w");

	r = BN_set_word(bignumInstance, RSA_F4);
	if (r != 1) {
		LOG_ERROR("[GenerateRSAKeyPair] Big number generation failed");
		return FUNCTION_ERROR;
	}

	r = RSA_generate_key_ex(rsaInstance, 2048, bignumInstance, NULL);
	if (r != 1) {
		LOG_ERROR("[GenerateRSAKeyPair] RSA key generation failed");
		return FUNCTION_ERROR;
	}

	// Convert RSA to PKEY
	EVP_PKEY* evpKey = EVP_PKEY_new();
	r = EVP_PKEY_set1_RSA(evpKey, rsaInstance);
	if (r != 1) {
		LOG_ERROR("[GenerateRSAKeyPair] Converting RSA key to PKEY failed");
		return FUNCTION_ERROR;
	}

	// Write public key in PKCS PEM
	r = PEM_write_bio_RSAPublicKey(publicKeyFile, rsaInstance);
	if (r != 1) {
		LOG_ERROR("[GenerateRSAKeyPair] Writing RSA public key to file failed");
		return FUNCTION_ERROR;
	}

	// Write private key in PKCS PEM.
	r = PEM_write_bio_PrivateKey(privateKeyFile, evpKey, NULL, NULL, 0, NULL, NULL);
	if (r != 1) {
		LOG_ERROR("[GenerateRSAKeyPair] Writing RSA private key to file failed");
		return FUNCTION_ERROR;
	}

	BIO_free(privateKeyFile);
	BIO_free(publicKeyFile);

	CleanupLineEndings("PrivateRSAKey");
	CleanupLineEndings("PublicRSAKey");

	return FUNCTION_SUCCESS;
}

int CleanupLineEndings(char* fileName)
{
	std::streamoff streamLength;
	std::ifstream ifStream(fileName, std::ifstream::in | std::ifstream::binary);
	LOG_PRINT("[CleanupLineEndings] Cleaning line endings for file: %s", fileName);

	if (!ifStream.bad()) {
		// get length
		ifStream.seekg(0, ifStream.end);
		streamLength = ifStream.tellg();
		ifStream.seekg(0, ifStream.beg);

		// our array to store the bytes we want to write to the file at the end
		char *array = new char[streamLength + 1];
		char c;
		int i = 0;
		while (ifStream.get(c)) {
			if (strncmp(&c, "\x0D", 1)) {
				memcpy(&array[i], &c, 1);
				i++;
			};
		};
		ifStream.close();

		std::ofstream outfile(fileName, std::ofstream::out | std::ofstream::binary);
		outfile.write(array, i);
		outfile.close();
	}
	else {
		LOG_ERROR("[CleanupLineEndings] Failed to cleanup line endings for file: %s", fileName);
		return FUNCTION_ERROR;
	}

	return FUNCTION_SUCCESS;
}

int EncryptRSAPublicKeyAndDNS(char* pubKeyFileName, char* ipAddress)
{
	LOG_PRINT("[EncryptRSAPublicKeyAndDNS] Encrypting RSA public key file named: %s, and DNS: %ls", pubKeyFileName, ipAddress);

	// Set up our data to be encrypted.
	std::streamoff length;
	char dataArray[520] = {}; // Length of pubkey and dns in DkS3 is 516 (0x204) including a null terminator.

	std::ifstream ifStream(pubKeyFileName, std::ifstream::in | std::ifstream::binary); // Open the pubkey file
	if (!ifStream.bad()) {
		// get length
		ifStream.seekg(0, ifStream.end);
		length = ifStream.tellg();
		ifStream.seekg(0, ifStream.beg);

		if (length != 426) {
			LOG_ERROR("[EncryptRSAPublicKeyAndDNS] Public key length invalid and cannot be injected. Should be 426 bytes. Length was: %i", length);
			return FUNCTION_ERROR;
		};

		// Copy pub key to start of array
		ifStream.read(dataArray, length);
		ifStream.close();
	}
	else {
		LOG_ERROR("[EncryptRSAPublicKeyAndDNS] Failed to open public key file for encrypting, file name: %s", pubKeyFileName);
		return FUNCTION_ERROR;
	}

	length = strlen(ipAddress);

	if (length > 20 || length < 1) {
		LOG_ERROR("[EncryptRSAPublicKeyAndDNS] IP Address length invalid and cannot be injected. Length was: %i", length);
		return FUNCTION_ERROR;
	};

	mbstowcs((LPWSTR)&dataArray[432], ipAddress, length + 1);

	// Time to encrypt our blob
	int dataArrayOffset;
	for (int i = 0; i < 65; i++) {
		dataArrayOffset = i * 8;
		TinyEncryptionAlgorithm((unsigned int*)&dataArray[dataArrayOffset]);
	}

	const char* outputFileName = "EncryptedPublicRSAKeyAndDNS";
	std::ofstream outfile(outputFileName, std::ofstream::out | std::ofstream::binary);
	outfile.write(dataArray, sizeof(dataArray));
	outfile.close();

	LOG_PRINT("[EncryptRSAPublicKeyAndDNS] Successfully encrypted RSA Public Key and DNS. Output file name: %s", outputFileName);

	return FUNCTION_SUCCESS;
}

// This is the "Tiny Encryption Algorithm"
// The keys are taken from DkS3
// https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
void TinyEncryptionAlgorithm(unsigned int *value)
{
	unsigned int v0, v1, delta, sum, k0, k1, k2, k3;
	v0 = value[0];
	v1 = value[1];

	delta = 0x9E3779B9;
	sum = 0;
	k0 = 0X4B694CD6, k1 = 0x96ADA235, k2 = 0xEC91D9D4, k3 = 0x23F562E5;
	for (int j = 0; j<32; j++) {
		sum += delta;
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
	}
	value[0] = v0;
	value[1] = v1;
}