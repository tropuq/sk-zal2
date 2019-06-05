#pragma once

#include "message.h"
#include "poll.h"

#include <any>
#include <chrono>
#include <filesystem>
#include <map>
#include <netinet/in.h>
#include <poll.h>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

class Client {
private:
	const std::string mcast_addr_;
	const uint16_t cmd_port_;
	const std::filesystem::path out_fldr_;
	const uint16_t timeout_;
	const uint16_t verbose_;

	class PackageError : public std::runtime_error {
	public:
		PackageError(const std::string& msg)
			: std::runtime_error(msg) {}
	};

	class CommandError : public std::runtime_error {
	public:
		CommandError(const std::string& msg)
			: std::runtime_error(msg) {}
	};

	class InternalError : public std::runtime_error {
	public:
		InternalError(const std::string& msg)
			: std::runtime_error(msg) {}
	};

	enum class EventList {
		stdin,
		udp,
		sigint,
		file_download,
		file_upload,
		upload_timer,
		download_timer,
		stdin_timer
	};

	struct ServerCompare {
		bool operator()(const std::pair<uintmax_t, sockaddr_in>& a,
		                const std::pair<uintmax_t, sockaddr_in>& b) const {
			return a.first > b.first;
		}
	};

	struct UploadingState {
		std::filesystem::path path_;
		// list of servers to send request, the first one is the server to which
		// the previous request was sent
		std::multiset<std::pair<uintmax_t, sockaddr_in>, ServerCompare> curr_server_list_;

		UploadingState() = default;
		UploadingState(std::filesystem::path path, std::multiset<std::pair<uintmax_t, sockaddr_in>,
		                                          ServerCompare> curr_server_list) :
			path_(std::move(path)), curr_server_list_(std::move(curr_server_list)) {}
	};

	// file descriptors for stdin, udp, tcp
	Poll<EventList> fds_;

	std::string last_command_;
	uint64_t cmd_seq_ = 0;
	// server list sorted by space left, added after search() call
	std::vector<std::pair<std::string, sockaddr_in>> last_file_list_;
	// server list sorted by space left, added after discover() call
	std::multiset<std::pair<uintmax_t, sockaddr_in>, ServerCompare> last_server_list_;

	// map cmd_seq to filename for files waiting to start downloading
	std::map<uint64_t, std::string> fetching_info_;
	std::set<std::string> fetching_filenames_;

	// map cmd_seq to info for files waiting to be uploaded
	std::map<uint64_t, UploadingState> uploading_info_;
	std::set<std::string> uploading_filenames_;

	// set of queries for which the client still waits for responses (cmd_seq, string of query)
	std::set<std::pair<uint64_t, std::string>> queries_;

	typedef void (Client::*MessageHandler)(const ComplexMessage&, const sockaddr_in&);
	std::map<std::string, MessageHandler> mess_handler_map_;

	typedef void (Client::*CommandHandler)(const std::string&);
	std::map<std::string, CommandHandler> comm_handler_map_;

	sockaddr_in remote_address_;

	void execute_command(const std::string& command, const std::string& param);

	void execute_message(const ComplexMessage& message, const sockaddr_in& server_address);

	void discover(const std::string&);

	void search(const std::string& s);

	void remove(const std::string& s);

	void fetch(const std::string& filename);

	void upload(const std::string& path);

	void print_server_info(const ComplexMessage& message, const sockaddr_in& server_address);

	// prints file list and adds it to last_file_list_
	void print_file_list(const ComplexMessage& message, const sockaddr_in& server_address);

	void start_downloading(const ComplexMessage& message, const sockaddr_in& server_address);

	void start_uploading(const ComplexMessage& message, const sockaddr_in& server_address);

	void upload_retry(const ComplexMessage& message, const sockaddr_in& server_address);

	void stop_listening();

	void start_listening();

public:
	class InitializationError : public std::runtime_error {
	public:
		InitializationError(const std::string& msg)
			: std::runtime_error(msg) {}
	};

	Client(std::string mcast_addr, uint16_t cmd_port, std::string out_fldr,
	       uint16_t timeout, uint16_t verbose);

	~Client();

	void start();
};
