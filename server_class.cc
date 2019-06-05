#include "server_class.h"
#include "utils.h"
#include "timer.h"
#include "debug.h"

#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

namespace filesystem = std::filesystem;

extern volatile sig_atomic_t sigint;
extern volatile int sigint_fd_read;
extern volatile int sigint_fd_write;

namespace {

// return pair (socket, port)
std::pair<int, int> create_tcp_socket() noexcept {
	int sock;
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		return {-1, -1};

	// bind
	sockaddr_in server_address;
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = 0; // any port
	if (bind(sock, (sockaddr*) &server_address, sizeof(server_address)) < 0)
		return close(sock), std::pair<int, int>{-1, -1};

	// get port number
	socklen_t len = sizeof(server_address);
	if (getsockname(sock, (sockaddr*)&server_address, &len) < 0)
		return close(sock), std::pair<int, int>{-1, -1};

	if (listen(sock, 1) < 0)
		return close(sock), std::pair<int, int>{-1, -1};

	return {sock, ntohs(server_address.sin_port)};
}

int signal_poll(int fd, int events, int timeout = -1) {
	if (sigint)
		return -1;
	pollfd t[2];
	t[0].fd = sigint_fd_read;
	t[0].events = POLLIN;
	t[1].fd = fd;
	t[1].events = events;
	t[0].revents = t[1].revents = 0;
	int code = poll(t, 2, timeout);
	if (t[0].revents) {
		write(sigint_fd_write, "sigint", 6);
		return -2;
	}
	if (code < 0)
		return -1;
	return code;
}

template<class... Args>
void inline_log(bool verbose_, Args... args) {
	if (verbose_)
		(std::cerr << ... << args) << std::endl;
}

} // namespace



// HELLO
void Server::send_server_info(const ComplexMessage& message, const sockaddr_in& client_address) {
	if (message.data.empty() == false)
		throw PackageError("message.data should be empty.");
	if (ComplexMessage("GOOD_DAY", message.cmd_seq, max_space_ - used_space_, mcast_addr_)
		.send_message(comm_sock_, client_address) < 0)
		throw InternalError("Could not send message to the client.");
}

// LIST
void Server::send_file_list(const ComplexMessage& message, const sockaddr_in& client_address) {
	SimpleMessage mes("MY_LIST", message.cmd_seq, "");
	uint32_t mtu = get_mtu();

	auto send_vector = [&](const std::vector<std::filesystem::path>& paths) {
		for (size_t i = 0; i < paths.size(); i++) {
			std::string filename = paths[i].filename().string();
			if (filename.find(message.data) == std::string::npos)
				continue;

			bool first = mes.data.empty();

			// adding next filename exceeds mtu so we need to send message now
			if (filename.size() + mes.get_message_size() + !first > mtu) {
				if (mes.send_message(comm_sock_, client_address) < 0)
					throw InternalError("Could not send message to the client.");
				mes.data = filename;
			}
			else {
				if (!first)
					mes.data += "\n";
				mes.data += filename;
			}
		}
		if (!mes.data.empty() && mes.send_message(comm_sock_, client_address) < 0)
			throw InternalError("Could not send message to the client.");
	};

	std::lock_guard<std::mutex> lock_files(files_.mutex_);
	send_vector(files_.paths_);
}

std::vector<filesystem::path>::const_iterator
Server::find_file_by_filename(const std::string& filename, const Files& files) const noexcept {
	for (auto it = files.paths_.begin(); it != files.paths_.end(); ++it)
		if ((*it).filename() == filename)
			return it;
	return files.paths_.end();
}

// DEL
void Server::delete_file(const ComplexMessage& message, const sockaddr_in&) {
	std::lock_guard<std::mutex> lock(files_.mutex_);
	auto it = find_file_by_filename(message.data, files_);
	if (it != files_.paths_.end()) {
		uintmax_t file_size = filesystem::file_size(*it);
		bool code = filesystem::remove(*it);
		if (code == true) {
			files_.paths_.erase(it);
			used_space_ -= file_size;
		}
		else
			throw InternalError("Could not remove the file.");
	}
	else
		throw InfoError("Could not find the file.");
}

void Server::send_file_deamon(int sock, std::string filename) {
	int msg_sock = -1;
	int f = -1;

	LogPrinter err("[SEND FILE ERROR] Error while sending the file", "to", verbose_ >= 1);
	LogPrinter succ("[SEND FILE] The file was successfully sent", "to", verbose_ >= 1);

	auto clean = [&]() {
		// close file descriptors
		if (msg_sock != -1)
			close(msg_sock);
		if (sock != -1)
			close(sock);
		if (f != -1)
			close(f);

		active_threads_--;
		if (active_threads_ == 0)
			quit_cv_.notify_all();
	};

	sockaddr_in client_address;
	socklen_t client_address_len = sizeof(client_address);

	int code = signal_poll(sock, POLLIN, 1000 * timeout_);
	if (sigint)
		return clean();

	// timeout
	if (code == 0) {
		err.log("Timeout while connecting with the client.");
		return clean();
	}

	msg_sock = accept(sock, (sockaddr*) &client_address, &client_address_len);
	if (sigint)
		return clean();

	if (msg_sock < 0) {
		err.log("Error while connecting with the client.");
		return clean();
	}

	std::string path = std::string(shrd_fldr_) + "/" + filename;
	f = open(path.c_str(), O_RDONLY);
	if (f < 0) {
		err.log(client_address, "Error while opening the file.");
		return clean();
	}

	constexpr size_t SEND_SIZE = 512000;
	char buff[SEND_SIZE];
	ssize_t len = 0;
	do {
		signal_poll(f, POLLIN);
		if (sigint)
			return clean();

		len = read(f, buff, SEND_SIZE);
		if (sigint)
			return clean();

		if (len < 0) {
			err.log(client_address, "Error while reading the file.");
			return clean();;
		}
		ssize_t send_pos = 0;
		do {
			signal_poll(msg_sock, POLLOUT);
			if (sigint)
				return clean();

			ssize_t curr_len = send(msg_sock, buff + send_pos, len - send_pos, MSG_NOSIGNAL);
			if (sigint)
				return clean();

			if (curr_len < 0) {
				err.log(client_address, "Error while sending the file.");
				return clean();;
			}
			send_pos += curr_len;
		} while (send_pos < len);
	} while (len > 0);

	close(f);
	close(msg_sock);
	close(sock);
	succ.log(client_address);

	active_threads_--;
	if (active_threads_ == 0)
		quit_cv_.notify_all();
}

// GET
void Server::send_file(const ComplexMessage& message, const sockaddr_in& client_address) {
	std::lock_guard<std::mutex> lock(files_.mutex_);

	auto it = find_file_by_filename(message.data, files_);

	if (it == files_.paths_.end())
		throw InfoError("Could not find the file.");
	else {
		// create new TCP socket
		auto [sock, port] = create_tcp_socket();
		if (sock < 0)
			throw InternalError("Could not create a TCP socket.");

		// send info to the client
		if (ComplexMessage("CONNECT_ME", message.cmd_seq, port, message.data)
				.send_message(comm_sock_, client_address) < 0)
			close(sock), throw InternalError("Could not send message to the client.");

		inline_log(verbose_ >= 1, "TCP Port ", port);

		// start a deamon process
		active_threads_++;
		std::thread th(&Server::send_file_deamon, this, sock, message.data);
		th.detach();
	}
}

void Server::add_file_deamon(int sock, std::string filename, uintmax_t file_size) {
	int msg_sock = -1;
	int fd = -1;

	LogPrinter err("[ADD FILE ERROR] Error while adding " + filename, "from", verbose_ >= 1);
	LogPrinter warn("[ADD FILE WARINNG] Warning while adding " + filename, "from", verbose_ >= 1);
	LogPrinter succ("[ADD FILE] " + filename + " was successfully added", "from", verbose_ >= 1);

	auto clean = [&]() {
		// close file descriptors
		if (msg_sock != -1)
			close(msg_sock);
		if (sock != -1)
			close(sock);

		std::lock_guard<std::mutex> lock(dwn_files_.mutex_);
		auto it = find_file_by_filename(filename, dwn_files_);
		// remove file
		if (fd != -1) {
			try {
				bool code = filesystem::remove(*it);
				if (code == false)
					throw std::runtime_error("Could not remove the file.");
			}
			catch (std::exception& ex) {
				warn.log(ex.what());
			}
		}
		// remove file from dwn_files and fix space usage
		dwn_files_.paths_.erase(it);
		used_space_ -= file_size;
		active_threads_--;
		if (active_threads_ == 0)
			quit_cv_.notify_all();
	};

	sockaddr_in client_address;
	socklen_t client_address_len = sizeof(client_address);

	int code = signal_poll(sock, POLLIN, 1000 * timeout_);
	if (sigint)
		return clean();

	// timeout
	if (code == 0) {
		err.log("Timeout while connecting with the client.");
		return clean();
	}

	msg_sock = accept(sock, (sockaddr*) &client_address, &client_address_len);
	if (sigint)
		return clean();

	if (msg_sock < 0) {
		err.log("Error while connecting with the client.");
		return clean();
	}

	std::string path = std::string(shrd_fldr_) + "/" + filename;
	fd = open(path.c_str(), O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		err.log(client_address, "Error while opening the file.");
		return clean();
	}

	constexpr size_t RECV_SIZE = 512000;
	char buff[RECV_SIZE];
	ssize_t len = 0;
	uintmax_t curr_size = 0;
	do {
		signal_poll(msg_sock, POLLIN);
		if (sigint)
			return clean();

		len = read(msg_sock, buff, RECV_SIZE);
		if (sigint)
			return clean();

		if (len < 0) {
			err.log(client_address, "Error while reading from the client.");
			return clean();
		}
		if (curr_size + len > file_size) {
			len = file_size - curr_size;
			warn.log(client_address, "Attempted to save more bytes than was allowed.");
		}
		curr_size += len;

		signal_poll(fd, POLLOUT);
		if (sigint)
			return clean();

		code = write_buff(fd, buff, len);
		if (sigint)
			return clean();

		if (code < 0) {
			err.log(client_address, "Error while writing to the file.");
			return clean();
		}
	} while (len > 0 && curr_size < file_size);

	if (curr_size < file_size)
		warn.log(client_address, "Saved fewer bytes then declared.");

	close(msg_sock);
	close(sock);
	close(fd);
	// move file from dwn_files_ to files_
	std::lock_guard<std::mutex> lock(dwn_files_.mutex_);
	auto it = find_file_by_filename(filename, dwn_files_);
	files_.paths_.emplace_back(*it);
	dwn_files_.paths_.erase(it);
	used_space_ -= file_size - curr_size;

	succ.log(client_address);

	active_threads_--;
	if (active_threads_ == 0)
		quit_cv_.notify_all();
}

// ADD
void Server::add_file(const ComplexMessage& message, const sockaddr_in& client_address) {
	auto filename = message.data;
	auto cmd_seq = message.cmd_seq;
	auto file_size = message.param;
	std::lock_guard<std::mutex> lock_files(files_.mutex_);
	std::lock_guard<std::mutex> lock_dwn_files(dwn_files_.mutex_);
	std::unique_lock<std::mutex> lock_wait_files(wait_files_.mutex_, std::defer_lock);
	if (sync_)
		lock_wait_files.lock();

	// not enough space
	if (file_size + used_space_ > max_space_) {
		SimpleMessage("NO_WAY", cmd_seq, filename).send_message(comm_sock_, client_address);
		throw InfoError("Not enough space.");
	}
	// invalid filename
	else if (filename.empty() || filename.find('/') != std::string::npos) {
		SimpleMessage("NO_WAY", cmd_seq, filename).send_message(comm_sock_, client_address);
		throw InfoError("Invalid filename " + filename + ".");
	}
	// file already exists
	else if (find_file_by_filename(filename, files_) != files_.paths_.end()) {
		SimpleMessage("NO_WAY", cmd_seq, filename).send_message(comm_sock_, client_address);
		throw InfoError("File " + filename + " already exists.");
	}
	// file is being downloadad
	else if (find_file_by_filename(filename, dwn_files_) != dwn_files_.paths_.end()) {
		SimpleMessage("NO_WAY", cmd_seq, filename).send_message(comm_sock_, client_address);
		throw InfoError("The file is not uploaded yet.");
	}
	// file is waiting
	else if (sync_ && find_file_by_filename(filename, wait_files_) != wait_files_.paths_.end()) {
		SimpleMessage("NO_WAY", cmd_seq, filename).send_message(comm_sock_, client_address);
		throw InfoError("The file is not uploaded yet.");
	}

	if (sync_) {
		send_permissions_sem_.wait();
		if (!want_cs_ && !have_cs_) {
			// ask for critical section
			if (ComplexMessage("CAN_I?", cmd_seq_, server_id_, "").send_message(comm_sock_, remote_address_) < 0) {
				send_permissions_sem_.post();
				throw InternalError("Could not send message to other servers.");
			}
			want_cs_ = true;
			servers_files_.clear();
		}
		wait_for_cs_++;
		send_permissions_sem_.post();

		used_space_ += file_size;
		wait_files_.paths_.emplace_back(std::string(shrd_fldr_) + "/" + filename);

		// start a deamon process
		active_threads_++;
		std::thread th(&Server::sync_add_file_deamon, this, filename, file_size, cmd_seq, client_address);
		th.detach();
	}
	else {
		auto [sock, port] = create_tcp_socket();
		if (sock < 0)
			throw InternalError("Could not create a TCP socket.");

		if (ComplexMessage("CAN_ADD", cmd_seq, port, "").send_message(comm_sock_, client_address) < 0)
			throw InternalError("Could not send message to the client.");

		inline_log(verbose_ >= 1, "TCP Port ", port);

		used_space_ += file_size;
		dwn_files_.paths_.emplace_back(std::string(shrd_fldr_) + "/" + filename);

		// start a deamon process
		active_threads_++;
		std::thread th(&Server::add_file_deamon, this, sock, filename, file_size);
		th.detach();
	}
}



void Server::sync_add_file_deamon(std::string filename, uintmax_t file_size, uint64_t cmd_seq,
	sockaddr_in client_address) {

	LogPrinter err("[SYNC ADD FILE ERROR] Error while adding " + filename, "", verbose_ >= 1);
	LogPrinter info("[SYNC ADD INFO] Sync add info about " + filename, "", verbose_ >= 1);

	auto clean = [&]() {
		if (SimpleMessage("NO_WAY", cmd_seq, filename).send_message(comm_sock_, client_address) < 0)
			err.log("Could not send message to the client.");
		std::lock_guard<std::mutex> lock_wait_files(wait_files_.mutex_);
		wait_files_.paths_.erase(find_file_by_filename(filename, wait_files_));
		used_space_ -= file_size;
		active_threads_--;
		if (active_threads_ == 0)
			quit_cv_.notify_all();
	};

	if (sigint)
		return clean();

	barrier_sem_.wait();
	let_inside_--;
	if (let_inside_ > 0)
		barrier_sem_.post();

	if (sigint)
		return clean();

	cs_sem_.wait();

	bool can_add = true;
	{
		std::lock_guard<std::mutex> lock(servers_files_m_);
		for (auto &file : servers_files_)
			if (filename == file.first) {
				can_add = false;
				break;
			}
	}

	in_cs_--;
	if (in_cs_ == 0) {
		leave_critical_section();
		send_permissions_sem_.wait();
		if (wait_for_cs_ > 0) {
			want_cs_ = true;
			servers_files_.clear();
			// ask for critical section
			if (ComplexMessage("CAN_I?", cmd_seq_, server_id_, "").send_message(comm_sock_, remote_address_) < 0)
				err.log("Could not send message to other servers with a request for the critical section.");
		}
		send_permissions_sem_.post();
	}

	cs_sem_.post();

	if (sigint)
		return clean();

	if (can_add) {
		info.log("Can add file " + filename + ".");
		auto [sock, port] = create_tcp_socket();
		if (sock < 0) {
			err.log("Could not create a TCP socket.");
			return clean();
		}

		if (ComplexMessage("CAN_ADD", cmd_seq, port, "").send_message(comm_sock_, client_address) < 0) {
			err.log("Could not send message to the client.");
			return clean();
		}

		inline_log(verbose_ >= 1, "TCP Port ", port);

		{
			std::lock_guard<std::mutex> lock_dwn_files(dwn_files_.mutex_);
			std::lock_guard<std::mutex> lock_wait_files(wait_files_.mutex_);
			auto it = find_file_by_filename(filename, wait_files_);
			dwn_files_.paths_.emplace_back(*it);
			wait_files_.paths_.erase(it);
		}

		add_file_deamon(sock, filename, file_size);
	}
	else {
		info.log("Could not add file " + filename + ".");
		clean();
	}
}

void Server::ready_to_add_files() {
	inline_log(verbose_ >= 1, "----------ready to add files-----------");
	servers_list_sent_.clear();
	let_inside_ = wait_for_cs_;
	file_lists_ = 0;
	in_cs_ = wait_for_cs_;
	wait_for_cs_ = 0;
	have_all_file_lists_ = true;
	if (init_phase_ == false)
		barrier_sem_.post();
}

void Server::enter_critical_section() {
	inline_log(verbose_ >= 1, "----------entering critical section-----------");
	servers_permited_.clear();
	permissions_ = 0;
	have_cs_ = true;
	want_cs_ = false;
	// send requests for file lists
	if (SimpleMessage("YOUR_LIST", 0, "").send_message(comm_sock_, remote_address_) < 0)
		throw InternalError("Could not send message to other servers.");
}

void Server::leave_critical_section() {
	std::lock_guard<std::mutex> lock_queue(deferred_m_);
	have_cs_ = false;
	have_all_file_lists_ = false;
	try {
		for (const auto& i : deferred_)
			send_permission(i);
	}
	catch (...) {
		inline_log(verbose_ >= 1, "Could not send permissions to requesting servers.");
	}
	deferred_.clear();
}

// IM_NEW
void Server::handle_new_server(const ComplexMessage&, const sockaddr_in& client_address) {
	bool added = servers_.emplace(client_address).second;
	// if im waiting for critical section send request
	if (added) {
		if (SimpleMessage("HI_NEW", 0, "").send_message(comm_sock_, client_address) < 0)
			throw InternalError("Could not send message to the new server.");
		if (want_cs_) {
			if (ComplexMessage("CAN_I?", cmd_seq_, server_id_, "").send_message(comm_sock_, client_address) < 0)
				throw InternalError("Could not send message to the new server.");
		}
		if (have_cs_ && have_all_file_lists_ == false) {
			if (SimpleMessage("YOUR_LIST", 0, "").send_message(comm_sock_, client_address) < 0)
				throw InternalError("Could not send message to the new server.");
		}
	}
}

// IM_OUT
void Server::handle_server_disconnect(const ComplexMessage&, const sockaddr_in& client_address) {
	{
		std::lock_guard<std::mutex> lock(servers_files_m_);
		for (size_t i = 0; i < servers_files_.size(); i++)
			if (servers_files_[i].second.sin_port == client_address.sin_port &&
				 servers_files_[i].second.sin_addr.s_addr == client_address.sin_addr.s_addr) {
				std::swap(servers_files_[i], servers_files_.back());
				servers_files_.pop_back();
				i--;
			}
	}
	servers_.erase(client_address);
	{
		auto it = servers_permited_.find(client_address);
		if (it != servers_permited_.end()) {
			permissions_--;
			servers_permited_.erase(it);
		}
		else if (permissions_ == servers_.size())
			enter_critical_section();
	}
	{
		auto it = servers_list_sent_.find(client_address);
		if (it != servers_list_sent_.end()) {
			file_lists_--;
			servers_list_sent_.erase(it);
		}
		else if (file_lists_ == servers_.size())
			ready_to_add_files();
	}
}

void Server::send_permission(const sockaddr_in& client_address) {
	if (SimpleMessage("OK", 0, "").send_message(comm_sock_, client_address) < 0)
		throw InternalError("Could not send message to the other server.");
}

// CAN_I?
void Server::handle_critical_section_request(const ComplexMessage& message, const sockaddr_in& client_address) {
	auto cmd_seq = message.cmd_seq;
	auto server_id = message.param;
	// permit
	if (server_id == server_id_ || wait_for_cs_ == 0 ||
		cmd_seq < cmd_seq_ || (cmd_seq == cmd_seq_ && server_id < server_id_))
		send_permission(client_address);
	// push into queue
	else {
		std::lock_guard<std::mutex> lock_queue(deferred_m_);
		deferred_.emplace_back(client_address);
	}
	cmd_seq_ = std::max(cmd_seq, cmd_seq_) + 1;
}

// OK
void Server::handle_critical_section_permission(const ComplexMessage&, const sockaddr_in& client_address) {
	servers_permited_.emplace(client_address);
	permissions_++;
	if (permissions_ == servers_.size())
		enter_critical_section();
}

// HI_NEW
void Server::handle_server_welcome(const ComplexMessage&, const sockaddr_in& client_address) {
	servers_.emplace(client_address);
}

// YOUR_LIST
void Server::send_whole_file_list(const ComplexMessage&, const sockaddr_in& client_address) {
	uint32_t mtu = get_mtu();

	auto send_vector = [&](const std::vector<std::filesystem::path>& paths) {
		ComplexMessage mes("MY_LIST", 0, 1, "");
		for (const auto& path : paths) {
			std::string filename = path.filename().string();

			bool first = mes.data.empty();

			// adding next filename exceeds mtu so we need to send message now
			if (filename.size() + mes.get_message_size() + !first > mtu) {
				if (mes.send_message(comm_sock_, client_address) < 0)
					throw InternalError("Could not send message to the requesting server.");
				mes.data = filename;
			}
			else {
				if (!first)
					mes.data += "\n";
				mes.data += filename;
			}
		}
		mes.param = 0;
		if (mes.send_message(comm_sock_, client_address) < 0)
			throw InternalError("Could not send message to the requesting server.");
	};

	std::lock_guard<std::mutex> lock_files(files_.mutex_);
	std::lock_guard<std::mutex> lock_dwn_files(dwn_files_.mutex_);
	std::vector<std::filesystem::path> tmp(files_.paths_.begin(), files_.paths_.end());
	tmp.insert(tmp.end(), dwn_files_.paths_.begin(), dwn_files_.paths_.end());
	send_vector(tmp);
}

// MY_LIST
void Server::add_new_file_list(const ComplexMessage& message, const sockaddr_in& client_address) {
	// message.param == 0 if that was the last file list
	if (message.param == 0) {
		file_lists_++;
		servers_list_sent_.emplace(client_address);
	}
	auto tokens = tokenize(message.data, '\n');
	{
		std::lock_guard<std::mutex> lock(servers_files_m_);
		for (const auto& i : tokens)
			servers_files_.emplace_back(i, client_address);
	}
	if (file_lists_ == servers_.size())
		ready_to_add_files();
}

void Server::execute_message(const ComplexMessage& message, const sockaddr_in& client_address) {
	auto it = mess_handler_map_.find(message.cmd);
	if (it != mess_handler_map_.end())
		(this->*(it->second))(message, client_address);
	else
		throw PackageError("Message not handled.");
}


void Server::index_files() {
	std::lock_guard<std::mutex> lock(files_.mutex_);
	files_.paths_.clear();
	used_space_ = 0;

	auto is_unique = [&](const std::string& filename) {
		for (auto& file : servers_files_)
			if (filename == file.first)
				return false;
		return true;
	};

	try {
		// iterate over regular files
		for (const auto& entry : filesystem::directory_iterator(shrd_fldr_)) {
			if (my_is_regular_file(entry.path())) {
				if (sync_ == true && !is_unique(entry.path().filename())) {
					if (filesystem::remove(entry) == false)
						throw InitializationError("Could not remove non-unique file.");
				}
				else {
					files_.paths_.emplace_back(entry.path());
					auto file_size = entry.file_size();
					if (file_size + used_space_ > max_space_)
						throw InitializationError("Not enough space to index all files.");
					used_space_ += file_size;
				}
			}
		}
	}
	catch (std::exception& ex) {
		throw InitializationError(ex.what());
	}
}

Server::Server(std::string mcast_addr, uint16_t cmd_port, uintmax_t max_space,
               std::string shrd_fldr, uint16_t timeout, bool sync, uint16_t verbose)
	: mcast_addr_(std::move(mcast_addr)), cmd_port_(cmd_port), max_space_(max_space),
	  shrd_fldr_(std::move(shrd_fldr)), timeout_(timeout), sync_(sync), verbose_(verbose),
	  cs_sem_(1), barrier_sem_(0), send_permissions_sem_(1) {

	server_id_ = std::chrono::system_clock::now().time_since_epoch().count();

	if (filesystem::exists(shrd_fldr_) == false || my_is_directory(shrd_fldr_) == false)
		throw InitializationError("Directory '" + shrd_fldr_.string() + "' does not exist.");

	// index files
	if (!sync_)
		index_files();

	// create socket
	if ((comm_sock_ = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		throw InitializationError("Error while creating a socket.");

	// multicast
	ip_mreq_.imr_interface.s_addr = htonl(INADDR_ANY);
	if (inet_aton(mcast_addr_.c_str(), &ip_mreq_.imr_multiaddr) == 0)
		close(comm_sock_), throw InitializationError("Invalid multicast address.");
	if (setsockopt(comm_sock_, IPPROTO_IP, IP_ADD_MEMBERSHIP, &ip_mreq_, sizeof(ip_mreq_)) < 0)
		close(comm_sock_), throw InitializationError("Error while initializing Server.");

	// SO_REUSEADDR
	int option = 1;
	if (setsockopt(comm_sock_, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int)) < 0)
		close(comm_sock_), throw InitializationError("Error while initializing Server.");

	// local
	sockaddr_in local_address;
	local_address.sin_family = AF_INET;
	local_address.sin_addr.s_addr = htonl(INADDR_ANY);
	local_address.sin_port = htons(cmd_port);
	if (bind(comm_sock_, (sockaddr*)&local_address, sizeof(local_address)) < 0)
		close(comm_sock_), throw InitializationError("Error while binding socket.");

	// broadcast
	int optval = 1;
	if (setsockopt(comm_sock_, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0)
		close(comm_sock_), throw InitializationError("Error while Initializing Client.");

	// TTL
	optval = 4;
	if (setsockopt(comm_sock_, IPPROTO_IP, IP_MULTICAST_TTL, &optval, sizeof(optval)) < 0)
		close(comm_sock_), throw InitializationError("Error while Initializing Client.");

	remote_address_.sin_family = AF_INET;
	remote_address_.sin_port = htons(cmd_port_);
	if (inet_aton(mcast_addr_.c_str(), &remote_address_.sin_addr) == 0)
		close(comm_sock_), throw InitializationError("Error while initializing Server.");

	// prepare functions map
	mess_handler_map_.emplace("HELLO", &Server::send_server_info);
	mess_handler_map_.emplace("LIST", &Server::send_file_list);
	mess_handler_map_.emplace("DEL", &Server::delete_file);
	mess_handler_map_.emplace("GET", &Server::send_file);
	mess_handler_map_.emplace("ADD", &Server::add_file);
	mess_handler_map_.emplace("IM_NEW", &Server::handle_new_server);
	mess_handler_map_.emplace("CAN_I?", &Server::handle_critical_section_request);
	mess_handler_map_.emplace("OK", &Server::handle_critical_section_permission);
	mess_handler_map_.emplace("YOUR_LIST", &Server::send_whole_file_list);
	mess_handler_map_.emplace("MY_LIST", &Server::add_new_file_list);
	mess_handler_map_.emplace("IM_OUT", &Server::handle_server_disconnect);
	mess_handler_map_.emplace("HI_NEW", &Server::handle_server_welcome);
}

Server::~Server() {
	setsockopt(comm_sock_, IPPROTO_IP, IP_DROP_MEMBERSHIP, &ip_mreq_, sizeof(ip_mreq_));
	close(comm_sock_);
}

void Server::start() {
	constexpr size_t BUFF_SIZE = 512000;
	char buff[BUFF_SIZE];

	LogPrinter pckg_err("[PCKG ERROR] Skipping invalid package", "from", true);
	LogPrinter internal_err("[INTERNAL ERROR] An internal error occurred", "while handling message with", verbose_ >= 1);
	LogPrinter info_err("[INFO] Problem occured while handling message", "from", verbose_ >= 1);
	LogPrinter other_err("[OTHER ERROR] Unknown error occurred", "while handling message from", verbose_ >= 1);

	auto handle_packet = [&] (MessageParser& parser) {
		sockaddr_in client_address;
		socklen_t rcva_len = sizeof(client_address);

		signal_poll(comm_sock_, POLLIN);

		if (sigint)
			return;

		ssize_t rcv_len = recvfrom(comm_sock_, buff, BUFF_SIZE, 0, (sockaddr*) &client_address, &rcva_len);

		if (sigint)
			return;

		if (rcv_len < 0) {
			internal_err.log("An error occurred while receiving a new message.");
			return;
		}

		std::string message_str(buff, buff + rcv_len);

		ComplexMessage message;
		try {
			message = parser.parse_message(message_str);
		}
		catch (std::exception& error) {
			pckg_err.log(client_address, error.what());
			return;
		}

		if (verbose_ >= 2)
			inline_log(true, "Received message: ", message, " from ", client_address);
		else if (verbose_ >= 1)
			inline_log(true, "Received message of type: ", message.cmd, " from ", client_address);

		try {
			execute_message(message, client_address);
		}
		catch (PackageError& error) {
			pckg_err.log(client_address, error.what());
			return;
		}
		catch (InternalError& error) {
			internal_err.log(client_address, error.what());
			return;
		}
		catch (InfoError& error) {
			info_err.log(client_address, error.what());
			return;
		}
		catch (std::exception& error) {
			other_err.log(client_address, error.what());
			return;
		}

		return;
	};

	auto leave = [&] {
		// say to other servers that this server is leaving
		if (sync_ && SimpleMessage("IM_OUT", 0, "").send_message(comm_sock_, remote_address_) < 0)
			throw InitializationError("Could not send message to other servers.");
		// release threads waiting on barrier
		for (uint64_t i = 0; i < wait_for_cs_; i++)
			barrier_sem_.post();
		std::unique_lock<std::mutex> lk(quit_m_);
		// wait for threads to end
		quit_cv_.wait(lk, [&]{ return active_threads_ == 0; });
	};

	MessageParser parser;

	init_phase_ = true;
	// synchronize my files, scan network looking for other servers
	if (sync_) {
		// say to other servers that this server starts
		if (SimpleMessage("IM_NEW", 0, "").send_message(comm_sock_, remote_address_) < 0)
			throw InitializationError("Could not send message to other servers.");

		parser = MessageParser({"HI_NEW", "IM_NEW", "IM_OUT", "YOUR_LIST"}, {"CAN_I?"});

		Timer timer;
		timer.start_timer(1000 * timeout_);
		inline_log(verbose_ >= 1, "Waiting ", timeout_, " seconds to find available servers.");
		// find available servers
		while (!sigint) {
			int code = signal_poll(comm_sock_, POLLIN, timer.get_timeleft());

			if (sigint)
				return leave();

			if (code < 0) {
				internal_err.log("An error occurred while receiving a new message.");
				continue;
			}

			// timeout
			if (code == 0)
				break;

			handle_packet(parser);

			if (sigint)
				return leave();
		}

		if (sigint)
			return leave();

		// get critical section to add files
		want_cs_ = true;
		if (ComplexMessage("CAN_I?", cmd_seq_, server_id_, "").send_message(comm_sock_, remote_address_) < 0)
			leave(), throw InitializationError("Could not send message to other servers.");

		parser = MessageParser({"IM_NEW", "IM_OUT", "OK", "YOUR_LIST"}, {"CAN_I?", "MY_LIST"});

		inline_log(verbose_ >= 1, "Gathering permissions from available servers.");
		while (!sigint) {
			handle_packet(parser);
			if (sigint)
				return leave();

			if (have_all_file_lists_)
				break;
		}

		if (sigint)
			return leave();

		try {
			index_files();
		}
		catch (...) {
			leave();
			throw;
		}

		leave_critical_section();
	}
	init_phase_ = false;

	if (sync_)
		parser = MessageParser({"HELLO", "LIST", "DEL", "GET", "IM_NEW", "OK", "IM_OUT", "YOUR_LIST"},
			{"ADD", "CAN_I?", "MY_LIST"});
	else
		parser = MessageParser({"HELLO", "LIST", "DEL", "GET"}, {"ADD"});

	inline_log(verbose_ >= 1, "Starting main loop.");
	while (!sigint) {
		handle_packet(parser);
		if (sigint)
			return leave();
	}

	leave();
}
