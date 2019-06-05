#include "client_class.h"
#include "utils.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <netdb.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>

namespace filesystem = std::filesystem;

extern volatile int sigint_fd_read;

namespace {

class FileLogPrinter {
private:
	std::string form_succ_;
	std::string form_fail_;
public:
	FileLogPrinter(std::string form_succ, std::string form_fail)
		: form_succ_(std::move(form_succ)), form_fail_(std::move(form_fail)) {}

	void success(const sockaddr_in& addr, const std::string& filename, const std::string& info = "") {
		std::cout << "File " << filename << " " << form_succ_ << " (" << addr << ") " << info << std::endl;
	}

	void fail(const sockaddr_in& addr, const std::string& filename, const std::string& info = "") {
		std::cout << "File " << filename << " " << form_fail_ << " failed (" << addr << ") " << info << std::endl;
	}

	void fail(const std::string& filename, const std::string& info = "") {
		std::cout << "File " << filename << " " << form_fail_ << " failed (:) " << info << std::endl;
	}
};

std::string query_command(const std::string& command) noexcept {
	if (command == "GOOD_DAY")
		return "discover";
	else if (command == "MY_LIST")
		return "search";
	else if (command == "CONNECT_ME")
		return "fetch";
	else if (command == "CAN_ADD" || command == "NO_WAY")
		return "upload";
	else
		return "";
}

std::pair<std::string, std::string> parse_stdin(const std::string& command_str) {
	auto space = command_str.find(' ');
	if (space == std::string::npos) {
		std::string type = command_str;
		std::transform(type.begin(), type.end(), type.begin(), ::tolower);
		if (type == "discover" ||
		    type == "search" ||
		    type == "exit")
			return {type, ""};
	}
	else {
		std::string type = command_str.substr(0, space);
		std::transform(type.begin(), type.end(), type.begin(), ::tolower);
		if (type == "search" ||
		    type == "fetch"  ||
		    type == "upload" ||
		    type == "remove")
			return {type, command_str.substr(space + 1)};
	}
	throw std::runtime_error("Unknown type of command.");
}

template<class... Args>
void inline_log(bool verbose, Args... args) {
	if (verbose)
		(std::cerr << ... << args) << std::endl;
}

struct FileInfo {
	std::filesystem::path path_;
	int fd_ = -1;
	sockaddr_in addr_;
	FileInfo() = default;
	FileInfo(std::filesystem::path path, int fd, sockaddr_in addr)
		: path_(std::move(path)), fd_(fd), addr_(std::move(addr)) {}
};

struct ServerAnswerInfo {
	uint64_t cmd_seq_;
	std::filesystem::path path_;
	sockaddr_in addr_;
	ServerAnswerInfo() = default;
	ServerAnswerInfo(uint64_t cmd_seq, std::filesystem::path path, sockaddr_in addr)
		: cmd_seq_(cmd_seq), path_(std::move(path)), addr_(std::move(addr)) {}
	ServerAnswerInfo(uint64_t cmd_seq, std::filesystem::path path)
		: cmd_seq_(cmd_seq), path_(std::move(path)) {}
};

} // namespace



void Client::execute_message(const ComplexMessage& message, const sockaddr_in& server_address) {
	if (queries_.find({message.cmd_seq, query_command(message.cmd)}) == queries_.end())
		throw PackageError("Invalid cmd_seq or cmd.");

	auto it = mess_handler_map_.find(message.cmd);
	if (it != mess_handler_map_.end())
		(this->*(it->second))(message, server_address);
	else
		throw PackageError("Message not recognized.");
}

void Client::execute_command(const std::string& command, const std::string& param) {
	auto it = comm_handler_map_.find(command);
	if (it != comm_handler_map_.end())
		(this->*(it->second))(param);
	else
		throw CommandError("Command not recognized.");
}



// GOOD_DAY
void Client::print_server_info(const ComplexMessage& message, const sockaddr_in& server_address) {
	last_server_list_.emplace(message.param, server_address);
	std::cout << "Found " << inet_ntoa(server_address.sin_addr)
	     << " (" << message.data
	     << ") with free space "
	     << message.param << std::endl;
}

// MY_LIST
void Client::print_file_list(const ComplexMessage& message, const sockaddr_in& server_address) {
	auto tokens = tokenize(message.data, '\n');
	for (const auto& i : tokens) {
		last_file_list_.emplace_back(i, server_address);
		std::cout << i << " (" << inet_ntoa(server_address.sin_addr) << ")" << std::endl;
	}
}

// CONNECT_ME
void Client::start_downloading(const ComplexMessage& message, const sockaddr_in& server_address) {
	// check and update list of active queries
	auto it = fetching_info_.find(message.cmd_seq);
	if (it->second != message.data)
		throw PackageError("Invalid filename.");
	fetching_filenames_.erase(it->second);
	fetching_info_.erase(it);
	queries_.erase({message.cmd_seq, query_command(message.cmd)});

	// create tcp socket
	int sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		throw InternalError("Error while initializing TCP connection.");

	sockaddr_in server_tcp_address = server_address;
	server_tcp_address.sin_port = htons(message.param);
	// connect socket to the server
	if (connect(sock, (sockaddr*) &server_tcp_address, sizeof(sockaddr_in)) < 0)
		close(sock), throw InternalError("Error while initializing TCP connection.");

	// open file
	std::string path(std::string(out_fldr_) + "/" + message.data);
	int fd = open(path.c_str(), O_WRONLY | O_CREAT, 0644);
	if (fd < 0)
		close(sock), throw InternalError("Error while opening the file.");

	fds_.add_fd(sock, POLLIN, FileInfo{path, fd, server_tcp_address}, EventList::file_download);
}

// CAN_ADD
void Client::start_uploading(const ComplexMessage& message, const sockaddr_in& server_address) {
	// check and update list of active queries
	auto it = uploading_info_.find(message.cmd_seq);
	auto path = it->second.path_;
	uploading_filenames_.erase(path.filename());
	uploading_info_.erase(it);
	queries_.erase({message.cmd_seq, query_command(message.cmd)});

	if (message.data.empty() == false)
		throw PackageError("message.data should be empty.");

	if (filesystem::exists(path) == false)
		throw CommandError("File " + path.filename().string() + " does not exist");

	// create tcp socket
	int sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		throw InternalError("Error while initializing TCP connection.");

	sockaddr_in server_tcp_address = server_address;
	server_tcp_address.sin_port = htons(message.param);
	// connect socket to the server
	if (connect(sock, (sockaddr*) &server_tcp_address, sizeof(sockaddr_in)) < 0)
		close(sock), throw InternalError("Error while initializing TCP connection.");

	// open file
	int fd = open(path.c_str(), O_RDONLY);
	if (fd < 0)
		close(sock), throw InternalError("Error while opening the file.");

	fds_.add_fd(sock, POLLOUT, FileInfo{path, fd, server_tcp_address}, EventList::file_upload);
}

// NO_WAY
void Client::upload_retry(const ComplexMessage& message, const sockaddr_in&) {
	// check and update list of active queries
	auto it = uploading_info_.find(message.cmd_seq);
	if (it->second.path_.filename() != message.data)
		throw PackageError("Invalid filename.");
	queries_.erase({message.cmd_seq, query_command(message.cmd)});

	auto& state = it->second;
	auto& ls = state.curr_server_list_;
	auto path = it->second.path_;
	ls.erase(ls.begin());

	auto clean = [&]() {
		uploading_filenames_.erase(path.filename());
		uploading_info_.erase(it);
	};

	// that was the last server
	if (ls.empty()) {
		clean();
		throw CommandError("File " + path.filename().string() + " rejected by all servers");
	}
	// ask next server
	else {
		if (filesystem::exists(path) == false) {
			clean();
			throw CommandError("File " + path.filename().string() + " does not exist");
		}
		try {
			cmd_seq_++;
			if (ComplexMessage("ADD", cmd_seq_, filesystem::file_size(path), path.filename())
				.send_message(fds_.get_pollfd(1).fd, ls.begin()->second) < 0) {
				clean();
				throw InternalError("Could not send message to the client.");
			}
			fds_.add_timer(timeout_, ServerAnswerInfo{cmd_seq_, path, ls.begin()->second},
				EventList::upload_timer);
			uploading_info_[cmd_seq_] = std::move(state);
			uploading_info_.erase(it);
			queries_.emplace(cmd_seq_, "upload");
		}
		catch (filesystem::filesystem_error& ex) {
			clean();
			throw InternalError("Could not get information about file " + path.filename().string() + ".");
		}
	}
}



void Client::discover(const std::string&) {
	cmd_seq_++;
	if (SimpleMessage("HELLO", cmd_seq_, "").send_message(fds_.get_pollfd(1).fd, remote_address_) < 0)
		throw InternalError("Could not send message to the client.");
	last_server_list_.clear();
	queries_.emplace(cmd_seq_, "discover");
	start_listening();
}

void Client::search(const std::string& s) {
	cmd_seq_++;
	last_file_list_.clear();
	if (SimpleMessage("LIST", cmd_seq_, s).send_message(fds_.get_pollfd(1).fd, remote_address_) < 0)
		throw InternalError("Could not send message to the client.");
	queries_.emplace(cmd_seq_, "search");
	start_listening();
}

void Client::remove(const std::string& s) {
	cmd_seq_++;
	if (SimpleMessage("DEL", cmd_seq_, s).send_message(fds_.get_pollfd(1).fd, remote_address_) < 0)
		throw InternalError("Could not send message to the client.");
}

void Client::fetch(const std::string& filename) {
	if (fetching_filenames_.find(filename) != fetching_filenames_.end())
		throw CommandError("File with this filename (" + filename +
			") is currently being downloaded or waiting for a connection with server.");
	for (const auto& file : last_file_list_) {
		if (file.first == filename) {
			cmd_seq_++;
			if (SimpleMessage("GET", cmd_seq_, filename).send_message(fds_.get_pollfd(1).fd, file.second) < 0)
				throw InternalError("Could not send message to the client.");
			fetching_info_[cmd_seq_] = filename;
			fetching_filenames_.emplace(filename);
			queries_.emplace(cmd_seq_, "fetch");
			fds_.add_timer(timeout_, ServerAnswerInfo{cmd_seq_, filename}, EventList::download_timer);
			return;
		}
	}
	throw CommandError("Could not find a file with the given name in the previous 'search' results.");
}

void Client::upload(const std::string& path_str) {
	filesystem::path path(path_str);
	if (last_server_list_.empty())
		throw CommandError("Uploading allowed after first non-empty 'discover' call.");
	else if (filesystem::exists(path) == false)
		throw CommandError("File " + path.filename().string() + " does not exist");
	else if (uploading_filenames_.find(path.filename()) != uploading_filenames_.end())
		throw CommandError("File with this filename (" + std::string(path.filename()) +
			") is currently being uploaded.");
	else if (filesystem::file_size(path) > last_server_list_.begin()->first)
		throw CommandError("File " + path.filename().string() + " too big");
	try {
		cmd_seq_++;
		if (ComplexMessage("ADD", cmd_seq_, filesystem::file_size(path), path.filename())
			.send_message(fds_.get_pollfd(1).fd, last_server_list_.begin()->second) < 0)
			throw InternalError("Could not send message to the client.");
		fds_.add_timer(timeout_, ServerAnswerInfo{cmd_seq_, path, last_server_list_.begin()->second},
			EventList::upload_timer);
		uploading_info_[cmd_seq_] = UploadingState(path, last_server_list_);
		queries_.emplace(cmd_seq_, "upload");
		uploading_filenames_.emplace(path.filename());
	}
	catch (filesystem::filesystem_error& ex) {
		throw InternalError("Could not get information about file " + path.filename().string() + ".");
	}
}

void Client::start_listening() {
	fds_.add_timer(timeout_, EventList::stdin_timer);
	// turn off stdin
	fds_.get_pollfd(0).fd = -1;
	inline_log(verbose_ >= 1, "Start listening.");
}

void Client::stop_listening() {
	// erase last added query
	queries_.erase({cmd_seq_, last_command_});
	// turn on stdin
	fds_.get_pollfd(0).fd = 0;
	cmd_seq_++;
	inline_log(verbose_ >= 1, "Stop listening.");
}

Client::~Client() {
}

Client::Client(std::string mcast_addr, uint16_t cmd_port, std::string out_fldr,  uint16_t timeout, uint16_t verbose)
	: mcast_addr_(std::move(mcast_addr)), cmd_port_(cmd_port), out_fldr_(std::move(out_fldr)),
	  timeout_(timeout), verbose_(verbose) {

	if (filesystem::exists(out_fldr_) == false || my_is_directory(out_fldr_) == false)
		throw InitializationError("Directory " + out_fldr_.string() + " does not exist");

	// create socket
	int comm_sock;
	if ((comm_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		throw InitializationError("Error while creating socket.");

	// broadcast
	int optval = 1;
	if (setsockopt(comm_sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0)
		close(comm_sock), throw InitializationError("Error while Initializing Client.");

	// TTL
	optval = 4;
	if (setsockopt(comm_sock, IPPROTO_IP, IP_MULTICAST_TTL, &optval, sizeof(optval)) < 0)
		close(comm_sock), throw InitializationError("Error while Initializing Client.");

	// local
	sockaddr_in local_address;
	local_address.sin_family = AF_INET;
	local_address.sin_addr.s_addr = htonl(INADDR_ANY);
	local_address.sin_port = htons(0);
	if (bind(comm_sock, (sockaddr*)&local_address, sizeof(local_address)) < 0)
		close(comm_sock), throw InitializationError("Error while binding socket.");

	// get port number
	socklen_t len = sizeof(local_address);
	if (getsockname(comm_sock, (sockaddr*)&local_address, &len) < 0)
		close(comm_sock), throw InitializationError("Error while Initializing Client.");

	inline_log(verbose_ >= 1, "UDP Port: ", ntohs(local_address.sin_port));

	remote_address_.sin_family = AF_INET;
	remote_address_.sin_port = htons(cmd_port_);
	if (inet_aton(mcast_addr_.c_str(), &remote_address_.sin_addr) == 0)
		close(comm_sock), throw InitializationError("Error while Initializing Client.");

	// prepare poll structure
	fds_.add_fd(0, POLLIN, EventList::stdin);
	fds_.add_fd(comm_sock, POLLIN, EventList::udp);
	fds_.add_fd(sigint_fd_read, POLLIN, EventList::sigint);

	// prepare functions mapping
	mess_handler_map_.emplace("GOOD_DAY", &Client::print_server_info);
	mess_handler_map_.emplace("MY_LIST", &Client::print_file_list);
	mess_handler_map_.emplace("CONNECT_ME", &Client::start_downloading);
	mess_handler_map_.emplace("NO_WAY", &Client::upload_retry);
	mess_handler_map_.emplace("CAN_ADD", &Client::start_uploading);

	comm_handler_map_.emplace("discover", &Client::discover);
	comm_handler_map_.emplace("fetch", &Client::fetch);
	comm_handler_map_.emplace("upload", &Client::upload);
	comm_handler_map_.emplace("remove", &Client::remove);
	comm_handler_map_.emplace("search", &Client::search);
}

void Client::start() {
	constexpr size_t BUFF_SIZE = 512000;
	char buff[BUFF_SIZE];

	LogPrinter pckg_err("[PCKG ERROR] Skipping invalid package", "from", true);
	LogPrinter comm_err("[COMMAND ERROR] Error while handling command from the user", "", true);
	LogPrinter input_err("[INPUT ERROR] Error while handling input from the user", "", verbose_ >= 1);
	LogPrinter internal_err("[INTERNAL ERROR] An internal error occurred", "while handling message with",
		verbose_ >= 1);
	LogPrinter other_err("[OTHER ERROR] Unknown error occurred", "while handling message with", verbose_ >= 1);
	LogPrinter fd_err("[FD ERROR] Error while managing file desciptors", "", verbose_ >= 1);

	FileLogPrinter dwn_log("downloaded", "downloading");
	FileLogPrinter up_log("uploaded", "uploading");

	MessageParser parser({"MY_LIST", "NO_WAY"}, {"GOOD_DAY", "CONNECT_ME", "CAN_ADD"});

	auto leave = [&] {
		for (size_t i = 0; i < fds_.size(); i++) {
			auto& info = fds_.get_info(i);
			auto type = fds_.get_type(i);
			if (type == EventList::file_download || type == EventList::file_upload)
				close(std::any_cast<FileInfo>(&info)->fd_);
		}
		fds_.clear();
	};

	auto handle_stdin = [&] {
		if (std::getline(std::cin, last_command_).bad()) {
			comm_err.log("Error while reading from stdin.");
			return 0;
		}

		if (std::cin.eof())
			return 1;

		std::string command, param;
		try {
			tie(command, param) = parse_stdin(last_command_);
		}
		catch (std::exception& ex) {
			input_err.log(ex.what());
			return 0;
		}

		last_command_ = command;

		if (command == "exit")
			return 1;

		try {
			execute_command(command, param);
		}
		catch (CommandError& ex) {
			if (verbose_ >= 1)
				comm_err.log(ex.what());
			else
				std::cout << ex.what() << std::endl;
			return 0;
		}
		catch (InternalError& ex) {
			internal_err.log(ex.what());
			return 0;
		}
		catch (std::exception& ex) {
			other_err.log(ex.what());
			return 0;
		}
		return 0;
	};

	auto handle_udp = [&](int fd) {
		sockaddr_in server_address;
		socklen_t rcva_len = sizeof(server_address);
		ssize_t rcv_len = recvfrom(fd, buff, BUFF_SIZE, 0, (sockaddr*) &server_address, &rcva_len);

		if (rcv_len < 0) {
			pckg_err.log("An error occurred while receiving a new message.");
			return;
		}

		std::string message_str(buff, buff + rcv_len);

		ComplexMessage message;
		try {
			message = parser.parse_message(message_str);
		}
		catch (std::exception& error) {
			pckg_err.log(server_address, error.what());
			return;
		}

		if (verbose_ >= 2)
			inline_log(true, "Received message: ", message, " from ", server_address);
		else if (verbose_ >= 1)
			inline_log(true, "Received message of type: ", message.cmd, " from ", server_address);

		try {
			execute_message(message, server_address);
		}
		catch (PackageError& ex) {
			pckg_err.log(server_address, ex.what());
			return;
		}
		catch (CommandError& ex) {
			if (verbose_ >= 1)
				comm_err.log(ex.what());
			else
				std::cout << ex.what() << std::endl;
			return;
		}
		catch (InternalError& ex) {
			internal_err.log(server_address, ex.what());
			return;
		}
		catch (std::exception& ex) {
			other_err.log(server_address, ex.what());
			return;
		}
	};

	auto handle_download = [&](int fd, FileInfo* info) {
		ssize_t len = 0;
		len = read(fd, buff, BUFF_SIZE);
		// would block
		if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return 0;
		try {
			if (len > 0) {
				int code = write_buff(info->fd_, buff, len);
				// would block
				if (code == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
					return 0;
				if (code < 0)
					throw InternalError("Error while writing to the file.");
			}
			else {
				if (len < 0)
					throw InternalError("Error while reading from socket.");
				dwn_log.success(info->addr_, info->path_.filename());
				close(info->fd_);
				return 1;
			}
		}
		catch (std::exception& ex) {
			dwn_log.fail(info->addr_, info->path_.filename(), ex.what());
			try {
				if (filesystem::remove(info->path_) == false)
					throw InternalError("Could not remove the file.");
			}
			catch (std::exception& ex2) {
				if (verbose_ >= 1)
					dwn_log.fail(info->addr_, info->path_.filename(), ex.what());
			}
			close(info->fd_);
			return -1;
		}
		return 0;
	};

	auto handle_upload = [&](int fd, FileInfo* info) {
		ssize_t len = 0;
		len = read(info->fd_, buff, 10);
		try {
			if (len > 0) {
				int code = send_buff(fd, buff, len);
				// would block
				if (code == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
					lseek(info->fd_, -len, SEEK_CUR);
					return 0;
				}
				if (code < 0)
					throw InternalError("Error while sending file.");
			}
			else {
				if (len < 0)
					throw InternalError("Error while reading from file.");
				up_log.success(info->addr_, info->path_);
				close(info->fd_);
				return 1;
			}
		}
		catch (std::exception& ex) {
			up_log.fail(info->addr_, info->path_, ex.what());
			close(info->fd_);
			return -1;
		}
		return 0;
	};

	auto handle_download_timeout = [&](ServerAnswerInfo* info) {
		auto it = fetching_info_.find(info->cmd_seq_);
		// query has already been answered
		if (it == fetching_info_.end())
			return;
		// update list of active queries
		fetching_filenames_.erase(it->second);
		fetching_info_.erase(it);
		queries_.erase({info->cmd_seq_, "fetch"});
		dwn_log.fail(info->path_, "Server answer timeout.");
	};

	auto handle_upload_timeout = [&](ServerAnswerInfo* info) {
		auto it = uploading_info_.find(info->cmd_seq_);
		// query has already been answered
		if (it == uploading_info_.end())
			return 0;

		sockaddr_in dummy;
		up_log.fail(info->addr_, info->path_, "Server answer timeout, trying next server.");
		try {
			upload_retry(ComplexMessage("NO_WAY", info->cmd_seq_, 0, info->path_.filename()), dummy);
		}
		catch (CommandError& ex) {
			if (verbose_ >= 1)
				comm_err.log(ex.what());
			else
				std::cout << ex.what() << std::endl;
			return -1;
		}
		catch (InternalError& ex) {
			internal_err.log(ex.what());
			return -1;
		}
		catch (PackageError& ex) {
			pckg_err.log(ex.what());
			return -1;
		}
		catch (std::exception& ex) {
			other_err.log(ex.what());
			return -1;
		}
		return 0;
	};

	// main loop
	while (true) {
		int code = fds_.mypoll();
		// error
		if (code < -1) {
			fd_err.log("Error in poll.");
			continue;
		}
		for (size_t i = 0; i < fds_.size(); i++) {
			auto& info = fds_.get_info(i);
			auto& revents = fds_.get_pollfd(i).revents;
			auto fd = fds_.get_pollfd(i).fd;
			auto type = fds_.get_type(i);

			if (type == EventList::stdin) {
				if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
					fd_err.log("An error occurred while handling stdin file descriptor.");
					return leave();
				}
				if (revents & POLLIN) {
					revents = 0;
					if (handle_stdin() != 0)
						return leave();
				}
			}
			else if (type == EventList::udp) {
				if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
					fd_err.log("An error occurred while handling udp file descriptor.");
					return leave();
				}
				if (revents & POLLIN) {
					revents = 0;
					handle_udp(fd);
				}
			}
			else if (type == EventList::file_download) {
				auto* casted_info = std::any_cast<FileInfo>(&info);
				if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
					fd_err.log("An error occurred while handling TCP socket.");
					try {
						if (filesystem::remove(casted_info->path_) == false)
							throw InternalError("Could not remove the file.");
					}
					catch (std::exception& ex) {
						if (verbose_ >= 1)
							dwn_log.fail("Could not remove the file.");
					}
					fds_.remove_fd(i--);
				}
				if (revents & POLLIN) {
					revents = 0;
					code = handle_download(fd, casted_info);
					if (code != 0) {
						// error while downloading
						if (code == -1) {
							try {
								if (filesystem::remove(casted_info->path_) == false)
									throw InternalError("Could not remove the file.");
							}
							catch (std::exception& ex) {
								if (verbose_ >= 1)
									dwn_log.fail("Could not remove the file.");
							}
						}
						fds_.remove_fd(i--);
					}
				}
			}
			else if (type == EventList::file_upload) {
				if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
					fd_err.log("An error occurred while handling TCP socket.");
					fds_.remove_fd(i--);
				}
				if (revents & POLLOUT) {
					revents = 0;
					code = handle_upload(fd, std::any_cast<FileInfo>(&info));
					if (code != 0)
						fds_.remove_fd(i--);
				}
			}
			else if (type == EventList::download_timer) {
				if (revents & (POLLERR | POLLHUP | POLLNVAL))
					fd_err.log("An error occurred while handling an download timer.");
				if (revents & POLLIN) {
					handle_download_timeout(std::any_cast<ServerAnswerInfo>(&info));
					fds_.remove_fd(i--);
				}
			}
			else if (type == EventList::upload_timer) {
				if (revents & (POLLERR | POLLHUP | POLLNVAL))
					fd_err.log("An error occurred while handling an upload timer.");
				if (revents & POLLIN) {
					handle_upload_timeout(std::any_cast<ServerAnswerInfo>(&info));
					fds_.remove_fd(i--);
				}
			}
			else if (type == EventList::stdin_timer) {
				if (revents & (POLLERR | POLLHUP | POLLNVAL))
					fd_err.log("An error occurred while handling an stdin timer.");
				if (revents & POLLIN) {
					fds_.remove_fd(i--);
					stop_listening();
				}
			}
			else if (type == EventList::sigint) {
				if (revents & (POLLERR | POLLHUP | POLLNVAL))
					fd_err.log("An error occurred while handling a singnal notifier.");
				if (revents & POLLIN)
					return leave();
			}
		}
	}
}
