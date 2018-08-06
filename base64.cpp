#include <string>

#include <vector>




const char base64_url_alphabet[] = {

	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',

	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',

	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',

	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',

	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'

};



std::string base64_encoder(const std::string & in) {

	std::string out;

	int val = 0, valb = -6;

	size_t len = in.length();

	unsigned int i = 0;

	for (i = 0; i < len; i++) {

		unsigned char c = in[i];

		val = (val << 8) + c;

		valb += 8;

		while (valb >= 0) {

			out.push_back(base64_url_alphabet[(val >> valb) & 0x3F]);

			valb -= 6;

		}

	}

	if (valb > -6) {

		out.push_back(base64_url_alphabet[((val << 8) >> (valb + 8)) & 0x3F]);

	}

	return out;

}



std::string base64_decoder(const std::string & in) {

	std::string out;

	std::vector<int> T(256, -1);

	unsigned int i;

	for (i = 0; i < 64; i++) T[base64_url_alphabet[i]] = i;



	int val = 0, valb = -8;

	for (i = 0; i < in.length(); i++) {

		unsigned char c = in[i];

		if (T[c] == -1) break;

		val = (val << 6) + T[c];

		valb += 6;

		if (valb >= 0) {

			out.push_back(char((val >> valb) & 0xFF));

			valb -= 8;

		}

	}

	return out;

}