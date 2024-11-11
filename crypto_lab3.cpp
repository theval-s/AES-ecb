//
// Made by Val (GH: theval-s) 2024
//

#include "crypto_lab3.h"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <format>
#include <algorithm>

AES::AES(const std::string &key) {
	this->KeyExpansion(key);
}

bool g_is_running = true;
int main()
{
	while (g_is_running) {
		std::cout << "AES encryption/decryption.\n"
			"Your encryption key (hex string without spaces):\n>";
		std::string key;
		std::cin >> key;
		try {
			AES encryptor(key);
			bool needs_change = false;
			while (!needs_change) {
				std::cout << "1. Encrypt\n"
					"2. Decrypt\n"
					"3. Change key\n"
					"4. Exit\n>";
				char opt;
				std::cin >> opt;

				std::string input;
				switch (opt) {
				case '1':
					std::cout << "Enter the message you want to encrypt\n>";
					std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); //to clear the previous input if it had more than 1 symbol)
					std::getline(std::cin, input);
					std::cout << encryptor.encrypt_string(input) << std::endl;
					break;
				case '2':
					std::cout << "Enter the message you want to decrypt (hex string)\n>";
					std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); //to clear the previous input if it had more than 1 symbol)
					std::getline(std::cin, input);
					input.erase(remove_if(input.begin(), input.end(), isspace), input.end());
					std::cout << encryptor.decrypt_hexstring(input) << std::endl;
					break;
				case '3':
					needs_change = true;
					break;
				case '4':
					g_is_running = false;
					break;
				default:
					std::cout << "Invalid option\n";
					break;
				}


#ifdef WIN32
				if (!needs_change) system("pause");
				system("cls");
#elif defined(__linux__) || defined(__unix__)
				if (!needs_change) system("read");
				system("clear");
#endif			

			}
		}
		catch (const std::exception& e) {
			std::cout << "Error! Exception: " << e.what() << std::endl;
		}
	}
	return 0;
}


void AES::KeyExpansion(const std::string &key) {
	size_t len = key.length();
	switch (len) {
	case 32: //input is a hex string, so 1char is 4 bits. 32*4 = 128
		this->mode = 0;
		this->rounds = ROUNDS_128BIT;
		this->RoundKeys.resize(KEYLEN_128BIT * (ROUNDS_128BIT + 1));
		break;
	case 48:
		this->mode = 1;
		this->rounds = ROUNDS_192BIT;
		this->RoundKeys.resize(KEYLEN_192BIT * (ROUNDS_192BIT + 1));
		break;
	case 64:
		this->mode = 2;
		this->rounds = ROUNDS_256BIT;
		this->RoundKeys.resize(KEYLEN_256BIT * (ROUNDS_256BIT + 1));
		break;
	default:
		throw std::runtime_error("key must be of 128/192/256 bit in length and hex values");
	}

	//filling the RoundKeys array with starting key
	for (size_t i = 0; i < len; i += 8) {
		uint32_t key_part = 0;
		std::stringstream hex_stream;
		hex_stream << std::hex;
		for (int j = 0; j < 8; j++) hex_stream << key[i + j];
		if (!(hex_stream >> key_part)) throw std::invalid_argument("invalid hex number in decrypt_hexstring");
		//not doing memcpy so no need for endianess reverse/check

		RoundKeys[i / 8] = key_part;
	}

	//starting from 4/6/8 depending on the key size, fill all keys after the first one 
	for (size_t i = len / 8; i < RoundKeys.size(); i++) {
		if (i % (len / 8) == 0) {
			RoundKeys[i] = RoundKeys[i - (len / 8)] ^ SubWord(RotWord(RoundKeys[i - 1])) ^ rcon[i / (len / 8)];
		}//
		else if (mode == 2 && i % (len / 8) == 4) {
			RoundKeys[i] = RoundKeys[i - (len / 8)] ^ SubWord(RoundKeys[i - 1]);
		}
		else RoundKeys[i] = RoundKeys[i - (len / 8)] ^ RoundKeys[i - 1];
	}
	//DEBUG
	/*std::stringstream ss;
	for (size_t i = 0; i < RoundKeys.size(); i++) ss << std::format("{:02X}", RoundKeys[i]);
	std::cerr << "Expanded key: " << ss.str() << std::endl;*/
}
uint32_t AES::RotWord(uint32_t word) {
	uint32_t res = (word << 8) | (word >> 24);
	return res;
}
uint32_t AES::SubWord(uint32_t word) {
	uint32_t res = 0;
	//applying S box to each byte
	res |= S[(word >> 24) & 0xFF] << 24;
	res |= S[(word >> 16) & 0xFF] << 16;
	res |= S[(word >> 8) & 0xFF] << 8;
	res |= S[word & 0xFF];
	return res;
}

std::string AES::encrypt_string(const std::string &data) {
	std::string input = data;
	//must be divisible by 16 (128 bit blocks) so we add padding PKCS#7
	size_t len = input.length();
	size_t padding_len = 16 - (len + 16) % 16;
	input.append(padding_len, static_cast<unsigned char>(padding_len));
	std::stringstream ss;
	for (size_t l = 0; l < input.size(); l += 16) {
		for (size_t i = 0; i < 16; i++) {
			state[i % 4][i / 4] = static_cast<uint8_t>(input[l + i]);
		}
		//setting the state array
		AddRoundKey(0);

		for (int i = 1; i < this->rounds; i++) {
			SubBytes();
			ShiftRows();
			MixColumns();
			AddRoundKey(i);
		}
		SubBytes();
		ShiftRows();
		AddRoundKey(this->rounds);

		for (size_t i = 0; i < 16; i++) {
			ss << std::format("{:02X}", state[i % 4][i / 4]);
		}
	}
	state.fill({ 0,0,0,0 });
	return ss.str();
}
void AES::AddRoundKey(const uint8_t &round) {
	for (int i = 0; i < 4; i++) {
		uint32_t key = RoundKeys[round * 4 + i];
		state[0][i] ^= (key >> 24) & 0xFF;
		state[1][i] ^= (key >> 16) & 0xFF;
		state[2][i] ^= (key >> 8) & 0xFF;
		state[3][i] ^= key & 0xFF;
	}
}
void AES::SubBytes() {
	for (size_t i = 0; i < 16; i++) {
		state[i % 4][i / 4] = S[state[i % 4][i / 4]];
	}
}
void AES::ShiftRows() {
	//left by 1
	shift_row(state[1], 1);
	shift_row(state[2], 2);
	shift_row(state[3], 3);
}
void AES::MixColumns() {
	for (uint8_t c = 0; c < 4; c++) {
		uint8_t a[4];
		uint8_t b[4]; //will contain results of 2*byte in GF(2^8) 
		for (int i = 0; i < 4; i++) {
			a[i] = state[i][c];
			//mul by 2 in GF(2^8) is equivalent to left shift 1,
			//and if highest bit was 1, we also need to XOR with x^8 + x^4 + x^3 + x + 1
			b[i] = ((state[i][c] & 0x80) ? 0x1B : 0x00) ^ (state[i][c] << 1);
		}
		//columns are: each element of a is multiplied by the matrix 
		//like: s[0][c] = b[0] (result of a[0]*2 in GF) XOR a[1]XORb[1] (a[0]*3) XOR a[2] XOR a[3]
		/*
		* Matrix for multiplication
		2 3 1 1
		1 2 3 1
		1 1 2 3
		3 1 1 2
		*/
		state[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
		state[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
		state[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
		state[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
	}

}

std::string AES::decrypt_hexstring(const std::string &input) {
	std::string ans;
	if (input.size() % 32 != 0) throw std::invalid_argument("decrypt_hexstring input len is not divisible by 32");

	for (size_t l = 0; l < input.size(); l += 32) {

		for (int i = 0; i < 32; i += 2) {
			std::stringstream hex_stream;
			hex_stream << std::hex << input[l + i] << input[l + i + 1];
			int t = 0; //since uint8_t is uchar
			//we need to use int to convert correctly
			if (!(hex_stream >> t) /* && hex_stream.bad()*/) throw std::invalid_argument("invalid hex symbol in decrypt_hexstring");
			state[(i / 2) % 4][(i / 2) / 4] = t;
		}

		//Decryption
		AddRoundKey(this->rounds);
		for (int i = this->rounds - 1; i > 0; i--) {
			InvSubBytes();
			InvShiftRows();
			AddRoundKey(i);
			InvMixColumns();
		}
		InvSubBytes();
		InvShiftRows();
		AddRoundKey(0);

		for (size_t i = 0; i < 16; i++) {
			ans += static_cast<char>(state[i % 4][i / 4]);
		}
	}
	//Dealing with padding
	state.fill({ 0,0,0,0 });
	size_t padding_len = ans[ans.size() - 1];
	return ans.substr(0, ans.size() - padding_len); //PKCS#7
}
void AES::InvShiftRows() {
	shift_row(state[1], 3);
	shift_row(state[2], 2);
	shift_row(state[3], 1);
}
void AES::InvSubBytes() {
	for (size_t i = 0; i < 16; i++) {
		state[i % 4][i / 4] = rsbox[state[i % 4][i / 4]];
	}
}
void AES::InvMixColumns() {
	//Matrix for multiplication
	uint8_t matrix[4][4] = {
		{14, 11, 13, 9},
		{9,14,11,13},
		{13,9,14,11},
		{11,13,9,14}
	};

	for (int c = 0; c < 4; c++) {
		uint8_t tmp[4];
		for (int i = 0; i < 4; i++) tmp[i] = state[i][c];
		uint8_t res = 0;
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				res ^= gf_multiply(tmp[j], matrix[i][j]);
			}
			state[i][c] = res;
			res = 0;
		}
	}
}
void AES::shift_row(std::array<uint8_t, 4>& row, int shift) {
	for (int i = 0; i < shift; i++) {
		uint8_t temp = row[0];
		row[0] = row[1];
		row[1] = row[2];
		row[2] = row[3];
		row[3] = temp;
	}
}
uint8_t AES::gf_multiply(uint8_t a, uint8_t b) {
	uint8_t res = 0;
	for (int i = 0; i < 8; i++) {
		//evaluate all the bits
		if (b & 1) res ^= a;
		//if lowest bit in second num is 1, xor with a

		if ((a & 0x80) != 0) {
			a <<= 1;
			a ^= 0x1B;
			//factoring in reducing polinomial if it would overflow
		}
		else a <<= 1;
		b >>= 1;
		if (a == 0 || b == 0) break;
	}
	return res;
}
