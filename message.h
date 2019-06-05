#pragma once

#include <string>
#include <vector>
#include <ostream>
#include <netinet/in.h>


class Message {
public:
	static constexpr size_t cmd_size = 10;
	virtual std::string prepare_message() = 0;
	int send_message(int sock, const sockaddr_in& client_address);
};

class SimpleMessage : public Message {
public:
	SimpleMessage() = default;
	SimpleMessage(std::string cmd_, uint64_t cmd_seq_, std::string data_)
		: cmd(std::move(cmd_)), cmd_seq(cmd_seq_), data(std::move(data_)) {}

	std::string cmd;
	uint64_t cmd_seq;
	std::string data;

	virtual std::string prepare_message() override;

	size_t get_message_size() {
		return cmd_size + sizeof(cmd_seq) + data.size();
	}

	friend std::ostream& operator<<(std::ostream& ost, const SimpleMessage& ms) {
		return ost << "(cmd=" << ms.cmd
		           << ", seq=" << ms.cmd_seq
		           << ", data=" << ms.data << ")";
	}
};

class ComplexMessage : public Message {
public:
	ComplexMessage() = default;
	ComplexMessage(std::string cmd_, uint64_t cmd_seq_, uint64_t param_, std::string data_)
		: cmd(std::move(cmd_)), cmd_seq(cmd_seq_), param(param_), data(std::move(data_)) {}

	std::string cmd;
	uint64_t cmd_seq;
	uint64_t param;
	std::string data;

	virtual std::string prepare_message() override;

	size_t get_message_size() {
		return cmd_size + sizeof(cmd_seq) + sizeof(param) + data.size();
	}

	friend std::ostream& operator<<(std::ostream& ost, const ComplexMessage& ms) {
		return ost << "(cmd=" << ms.cmd
		           << ", seq=" << ms.cmd_seq
		           << ", param=" << ms.param
		           << ", data=" << ms.data << ")";
	}
};
