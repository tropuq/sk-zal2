#include "message.h"

#include <cstring>
#include <endian.h>

using std::move;
using std::string;
using std::vector;

int Message::send_message(int sock, const sockaddr_in& address) {
	string str = prepare_message();
	if (sendto(sock, str.c_str(), str.size(), MSG_NOSIGNAL, (sockaddr*) &address, sizeof(address)) < 0)
		return -1;
	return 0;
}

string SimpleMessage::prepare_message() {
	string ret(get_message_size(), 0);
	string cmd_prep(cmd.begin(), cmd.end());
	cmd_prep.resize(cmd_size, 0);
	uint64_t cmd_seq_prep = htobe64(cmd_seq);
	std::memcpy(ret.data(), cmd_prep.data(), cmd_prep.size());
	std::memcpy(ret.data() + cmd_size, &cmd_seq_prep, sizeof(cmd_seq_prep));
	std::memcpy(ret.data() + cmd_size + sizeof(cmd_seq_prep), data.data(), data.size());
	return ret;
}

string ComplexMessage::prepare_message() {
	string ret(get_message_size(), 0);
	string cmd_prep(cmd.begin(), cmd.end());
	cmd_prep.resize(cmd_size, 0);
	uint64_t cmd_seq_prep = htobe64(cmd_seq);
	uint64_t param_prep = htobe64(param);
	std::memcpy(ret.data() + 0, cmd_prep.data(), cmd_prep.size());
	std::memcpy(ret.data() + cmd_size, &cmd_seq_prep, sizeof(cmd_seq_prep));
	std::memcpy(ret.data() + cmd_size + sizeof(cmd_seq_prep), &param_prep, sizeof(param_prep));
	std::memcpy(ret.data() + cmd_size + sizeof(cmd_seq_prep) + sizeof(param_prep), data.data(), data.size());
	return ret;
}
