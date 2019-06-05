#pragma once

#include "message.h"

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <set>

uint32_t get_mtu() noexcept;

bool my_is_regular_file(const std::filesystem::path& path) noexcept;

bool my_is_directory(const std::filesystem::path& path) noexcept;

std::ostream& operator<<(std::ostream& ost, const sockaddr_in& addr);

int write_buff(int fd, char* buff, int len);

int send_buff(int fd, char* buff, int len);

std::vector<std::string> tokenize(const std::string& str, char delim);

struct SockaddrComparator {
	bool operator()(const sockaddr_in& a, const sockaddr_in& b) const {
		return a.sin_addr.s_addr == b.sin_addr.s_addr
			? a.sin_port < b.sin_port
			: a.sin_addr.s_addr < b.sin_addr.s_addr;
	}
};

class MessageParser {
private:
	std::set<std::string> simple_;
	std::set<std::string> complex_;
public:
	MessageParser() = default;
	MessageParser(const std::vector<std::string>& simple, const std::vector<std::string>& complex)
		: simple_(simple.begin(), simple.end()), complex_(complex.begin(), complex.end()) {}

	ComplexMessage parse_message(const std::string& message_str);
};

class LogPrinter {
private:
	std::string prefix_;
	std::string connector_;
	bool active_;
	std::ostream &ost_;
public:
	LogPrinter(std::string prefix, std::string connector, bool active, std::ostream& ost = std::cerr)
		: prefix_(std::move(prefix)), connector_(std::move(connector)), active_(active), ost_(ost) {}

	void log(const std::string& info = "") {
		if (active_)
			ost_ << prefix_ << ". " << info << std::endl;
	}

	void log(const sockaddr_in& addr, const std::string& info = "") {
		if (active_)
			ost_ << prefix_ << " " << connector_ << " " << addr << ". " << info << std::endl;
	}
};
