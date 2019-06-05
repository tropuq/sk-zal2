#include "utils.h"

#include <arpa/inet.h>
#include <cstring>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

// https://stackoverflow.com/questions/1098897/what-is-the-largest-safe-udp-packet-size-on-the-internet
uint32_t get_mtu() noexcept {
	return 508;
}

bool my_is_regular_file(const std::filesystem::path& path) noexcept {
	struct stat st;
	std::memset(&st, 0, sizeof(st));
	if (stat(std::string(path).c_str(), &st) != 0)
		return 0;
	return S_ISREG(st.st_mode);
}

bool my_is_directory(const std::filesystem::path& path) noexcept {
	struct stat st;
	std::memset(&st, 0, sizeof(st));
	if (stat(std::string(path).c_str(), &st) != 0)
		return 0;
	return S_ISDIR(st.st_mode);
}

ComplexMessage MessageParser::parse_message(const std::string& message_str) {
	ComplexMessage message;
	// cmd too short
	if (message_str.size() < Message::cmd_size)
		throw std::runtime_error("Message too short.");

	message.cmd = std::string(&message_str[0], &message_str[Message::cmd_size]);
	while (!message.cmd.empty() && message.cmd.back() == '\0')
		message.cmd.pop_back();

	// simple
	if (simple_.find(message.cmd) != simple_.end()) {
		int size_cmd = sizeof(SimpleMessage::cmd_seq);

		// cmd too short
		if (message_str.size() < Message::cmd_size + size_cmd)
			throw std::runtime_error("Message too short.");

		std::memcpy(&message.cmd_seq, &message_str[Message::cmd_size], size_cmd);
		message.cmd_seq = be64toh(message.cmd_seq);
		message.data = std::string(&message_str[Message::cmd_size + size_cmd], &*message_str.end());
		message.param = 0;
	}
	// complex
	else if (complex_.find(message.cmd) != complex_.end()) {
		int size_cmd = sizeof(ComplexMessage::cmd_seq);
		int size_param = sizeof(ComplexMessage::param);

		// cmd too short
		if (message_str.size() < Message::cmd_size + size_cmd + size_param)
			throw std::runtime_error("Message too short.");

		std::memcpy(&message.cmd_seq, &message_str[Message::cmd_size], size_cmd);
		message.cmd_seq = be64toh(message.cmd_seq);
		std::memcpy(&message.param, &message_str[Message::cmd_size + size_cmd], size_param);
		message.param = be64toh(message.param);
		message.data = std::string(&message_str[Message::cmd_size + size_cmd + size_param], &*message_str.end());
	}
	// unknown
	else
		throw std::runtime_error("Unknown type of message " + message.cmd + ".");

	return message;
}

std::ostream& operator<<(std::ostream& ost, const sockaddr_in& addr) {
	return ost << inet_ntoa(addr.sin_addr) << ':' << ntohs(addr.sin_port);
}

int write_buff(int fd, char* buff, int len) {
	int curr = 0;
	while (curr != len) {
		ssize_t wrote = write(fd, buff + curr, len - curr);
		if (wrote < 0)
			return -1;
		if (wrote == 0)
			return -2;
		curr += wrote;
	}
	return 0;
}

int send_buff(int fd, char* buff, int len) {
	int curr = 0;
	while (curr != len) {
		ssize_t sent = send(fd, buff + curr, len - curr, MSG_NOSIGNAL);
		if (sent < 0)
			return -1;
		if (sent == 0)
			return -2;
		curr += sent;
	}
	return 0;
}

std::vector<std::string> tokenize(const std::string& str, char delim) {
	std::vector<std::string> ret(1, "");
	for (char i : str) {
		if (i == delim) {
			if (!ret.back().empty())
				ret.emplace_back("");
		}
		else
			ret.back() += i;
	}
	if (ret.back().empty())
		ret.pop_back();
	return ret;
}
