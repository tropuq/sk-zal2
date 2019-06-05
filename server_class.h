#pragma once

#include "message.h"
#include "semaphore.h"
#include "utils.h"

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <set>
#include <string>
#include <vector>

class Server {
private:
	const std::string mcast_addr_;
	const uint16_t cmd_port_;
	const uintmax_t max_space_;
	const std::filesystem::path shrd_fldr_;
	const uint16_t timeout_;
	const bool sync_;
	const uint16_t verbose_;

	class PackageError : public std::runtime_error {
	public:
		PackageError(const std::string& msg)
			: std::runtime_error(msg) {}
	};

	class InfoError : public std::runtime_error {
	public:
		InfoError(const std::string& msg)
			: std::runtime_error(msg) {}
	};

	class InternalError : public std::runtime_error {
	public:
		InternalError(const std::string& msg)
			: std::runtime_error(msg) {}
	};

	struct Files {
		mutable std::mutex mutex_;
		std::vector<std::filesystem::path> paths_;
	};

	ip_mreq ip_mreq_;
	sockaddr_in remote_address_;

	// files ready to send
	Files files_;
	// files currently being uploaded
	Files dwn_files_;
	// files currently waiting
	Files wait_files_;
	std::atomic<uintmax_t> used_space_ = 0;

	int comm_sock_;

	typedef void (Server::*MessageHandler)(const ComplexMessage&, const sockaddr_in&);
	// map message to function
	std::map<std::string, MessageHandler> mess_handler_map_;

	// quit variables
	std::atomic<uintmax_t> active_threads_ = 0;
	std::condition_variable quit_cv_;
	std::mutex quit_m_;

	void index_files();

	// returns iterator to file, doesn't lock mutex
	std::vector<std::filesystem::path>::const_iterator
	find_file_by_filename(const std::string& filename, const Files& files) const noexcept;

	void execute_message(const ComplexMessage& message, const sockaddr_in& client_address);

	void send_server_info(const ComplexMessage& message, const sockaddr_in& client_address);

	void send_file_list(const ComplexMessage& message, const sockaddr_in& client_address);

	// deletes file if it is in vector files_
	void delete_file(const ComplexMessage& message, const sockaddr_in& client_address);

	void send_file_deamon(int sock, std::string filename);

	void send_file(const ComplexMessage& message, const sockaddr_in& client_address);

	void add_file_deamon(int sock, std::string filename, uintmax_t file_size);


	void add_file(const ComplexMessage& message, const sockaddr_in& client_address);

	// sync specyfic

	// servers currently in the network
	std::set<sockaddr_in, SockaddrComparator> servers_;
	// servers that gave permission
	std::set<sockaddr_in, SockaddrComparator> servers_permited_;
	// server that sent file list
	std::set<sockaddr_in, SockaddrComparator> servers_list_sent_;

	std::vector<sockaddr_in> deferred_;
	std::mutex deferred_m_;
	// files from servers that gave permission
	std::vector<std::pair<std::string, sockaddr_in>> servers_files_;
	std::mutex servers_files_m_;
	// timer
	uint64_t cmd_seq_ = 0;

	uint64_t server_id_;

	uint64_t permissions_ = 0;
	uint64_t file_lists_ = 0;

	Semaphore cs_sem_;
	Semaphore barrier_sem_;
	Semaphore send_permissions_sem_;
	volatile uint64_t let_inside_ = 0;
	volatile uint64_t in_cs_ = 0;
	volatile uint64_t wait_for_cs_ = 0;
	volatile bool have_cs_ = false;
	volatile bool have_all_file_lists_ = false;
	volatile bool want_cs_ = false;

	bool init_phase_ = true;

	// wait for cs permission, check if file can be added, send permissions, create tcp socket and add file
	void sync_add_file_deamon(std::string filename, uintmax_t file_size, uint64_t cmd_seq, sockaddr_in client_address);

	// delete his file list, check if threads can enter cs
	void handle_server_disconnect(const ComplexMessage& message, const sockaddr_in& client_address);

	// if waiting for cs send request, send HI_NEW
	void handle_new_server(const ComplexMessage& message, const sockaddr_in& client_address);

	// send OK with file list
	void handle_critical_section_request(const ComplexMessage& message, const sockaddr_in& client_address);

	// append file list to servers_files_ and wake threads up if they can
	void handle_critical_section_permission(const ComplexMessage& message, const sockaddr_in& client_address);

	void handle_server_welcome(const ComplexMessage& message, const sockaddr_in& client_address);

	void send_permission(const sockaddr_in& client_address);

	void send_whole_file_list(const ComplexMessage& message, const sockaddr_in& client_address);

	void add_new_file_list(const ComplexMessage& message, const sockaddr_in& client_address);

	void ready_to_add_files();

	void enter_critical_section();

	void leave_critical_section();

public:
	class InitializationError : public std::runtime_error {
	public:
		InitializationError(const std::string& msg)
			: std::runtime_error(msg) {}
	};

	Server(std::string mcast_addr, uint16_t cmd_port, uintmax_t max_space,
	       std::string shrd_fldr, uint16_t timeout, bool sync, uint16_t verbose);

	~Server();

	void start();

};
