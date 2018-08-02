#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <iostream>

#include <sstream>

#include <openssl/sha.h>

#include <conio.h>
#include "cpprest/http_client.h"
#include "cpprest/containerstream.h"
#include "cpprest/filestream.h"


#include "base64.cpp"

#ifdef _WIN32
#include <time.h>
#include <objbase.h>
#else
#include <sys/time.h>
#include <uuid/uuid.h>
#endif


utility::string_t SHA256hash(utility::string_t);
utility::string_t SHA384hash(utility::string_t);
utility::string_t SHA512hash(utility::string_t);

utility::string_t to_hex(unsigned char s) {
	utility::stringstream_t ss;
	ss << std::hex << (int)s;
	return ss.str();
}

#ifdef _WIN32
int wmain(int argc, wchar_t* argv[])
#else
int main(int argc, char* argv[])
#endif
{
	utility::string_t type = _XPLATSTR("RS256");
	utility::string_t string1 = _XPLATSTR("hello world");


	if (type == _XPLATSTR("RS256") || type == _XPLATSTR("ES256")) {
		std::wcout <<  SHA256hash(string1).c_str() << std::endl;
	}
	else if (type == _XPLATSTR("RS384") || type == _XPLATSTR("ES384")) {
		std::wcout << SHA384hash(string1).c_str() << std::endl;
	}
	else if (type == _XPLATSTR("RS512") || type == _XPLATSTR("ES512")) {
		std::wcout << SHA512hash(string1).c_str() << std::endl;
	}
	else
		std::wcout << _XPLATSTR("NOT A VALID ALGORITHM") << std::endl;


	return 0;

}


utility::string_t SHA256hash(utility::string_t line) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, line.c_str(), line.length());
	SHA256_Final(hash, &sha256);

	utility::string_t output = _XPLATSTR("");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		output += to_hex(hash[i]);
	}
	return output;

}


utility::string_t SHA384hash(utility::string_t line) {
	unsigned char hash[SHA512_DIGEST_LENGTH];

	SHA512_CTX sha384;
	SHA384_Init(&sha384);
	SHA384_Update(&sha384, line.c_str(), line.length());
	SHA384_Final(hash, &sha384);

	utility::string_t output = _XPLATSTR("");
	for (int i = 0; i < SHA384_DIGEST_LENGTH; i++) {
		output += to_hex(hash[i]);
	}
	return output;

}

utility::string_t SHA512hash(utility::string_t line) {
	unsigned char hash[SHA512_DIGEST_LENGTH];

	SHA512_CTX sha512;
	SHA512_Init(&sha512);
	SHA512_Update(&sha512, line.c_str(), line.length());
	SHA512_Final(hash, &sha512);

	utility::string_t output = _XPLATSTR("");
	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
		output += to_hex(hash[i]);
	}
	return output;

}
