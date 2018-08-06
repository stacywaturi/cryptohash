#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <openssl/sha.h>
#include <conio.h>
#include <iomanip>
#include "cpprest/http_client.h"
#include "cpprest/containerstream.h"
#include "cpprest/filestream.h"
#include <bitset>

#include "base64.cpp"


#ifdef _WIN32
#include <time.h>
#include <objbase.h>
#else
#include <sys/time.h>
#include <uuid/uuid.h>
#endif


std::string SHA256hash(std::string);
std::string SHA384hash(std::string);
std::string SHA512hash(std::string);


const char base64_url_alphabet1[] = {

	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',

	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',

	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',

	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',

	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'

};



std::string base64_encoder1(const std::string & in) {

	std::string out;

	int val = 0, valb = -6;

	size_t len = in.length();

	unsigned int i = 0;

	for (i = 0; i < len; i++) {

		unsigned char c = in[i];

		val = (val << 8) + c;

		valb += 8;

		while (valb >= 0) {

			out.push_back(base64_url_alphabet1[(val >> valb) & 0x3F]);

			valb -= 6;

		}

	}

	if (valb > -6) {

		out.push_back(base64_url_alphabet1[((val << 8) >> (valb + 8)) & 0x3F]);

	}

	return out;

}





#ifdef _WIN32
int wmain(int argc, wchar_t* argv[])
#else
int main(int argc, char* argv[])
#endif
{
	std::string type = "RS512";
	std::string string1 = "A Modern Security Solution For Modern Security Threats. Start Your Free Trial";


//	if (type == "RS256" || type =="ES256") {
		std::wcout << "256	" <<  SHA256hash(string1).c_str() << std::endl;
		std::wcout << SHA256hash(string1).length() << std::endl;
//	}
//	else if (type == "RS384" || type =="ES384") {
		std::wcout << "384	" << SHA384hash(string1).c_str() << std::endl;
		std::wcout << SHA384hash(string1).length() << std::endl;
//	}
//else if (type == "RS512" || type == "ES512") {
		std::wcout << "512	" << SHA512hash(string1).c_str() << std::endl;
		std::wcout << SHA512hash(string1).length() << std::endl;
//}
//	else
	//	std::wcout << "NOT A VALID ALGORITHM" << std::endl;


	return 0;

}


std::string SHA256hash(std::string line) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, line.c_str(), line.length());
	SHA256_Final(hash, &sha256);

	std::stringstream ss;
	std::string output = "";
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		ss << std::hex<< hash[i];
	}

	output = base64_encoder1(ss.str());
	

	std::cout << output << std::endl;
	return ss.str();
	

}


std::string SHA384hash(std::string line) {
	unsigned char hash[SHA512_DIGEST_LENGTH];

	SHA512_CTX sha384;
	SHA384_Init(&sha384);
	SHA384_Update(&sha384, line.c_str(), line.length());
	SHA384_Final(hash, &sha384);
	std::wcout << "384 hash	" << &sha384 << std::endl;

	std::string output = "";
	std::stringstream ss;
	for (int i = 0; i < SHA384_DIGEST_LENGTH; i++)
	{
		ss << std::bitset<8>(hash[i]);
	}

	output = base64_encoder1(ss.str());


	std::cout << output << std::endl;
	return ss.str();


}

std::string SHA512hash(std::string line) {
	unsigned char hash[SHA512_DIGEST_LENGTH];

	SHA512_CTX sha512;
	SHA512_Init(&sha512);
	SHA512_Update(&sha512, line.c_str(), line.length());
	SHA512_Final(hash, &sha512);
	std::wcout << "512 hash	" <<  &sha512 << std::endl;

	std::string output = "";
	std::stringstream ss;
	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
	{
		ss << hash[i];
	}

	output = base64_encoder1(ss.str());


	std::cout << output << std::endl;
	return ss.str();

}
