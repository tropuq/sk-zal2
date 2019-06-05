#include "server_class.h"

#include <boost/program_options.hpp>
#include <iostream>
#include <signal.h>

using namespace boost::program_options;
using std::string;

volatile sig_atomic_t sigint = 0;
int sigint_fd_read = 0;
int sigint_fd_write = 0;

void set_sigint(int) {
	sigint = 1;
	write(sigint_fd_write, "sigint", 6);
}

int main(int argc, char** argv) {
	// SIGINT handler
	struct sigaction action;
	sigset_t block_mask;
	sigemptyset (&block_mask);
	sigaddset(&block_mask, SIGINT);

	action.sa_handler = set_sigint;
	action.sa_mask = block_mask;
	action.sa_flags = 0;

	if (sigaction(SIGINT, &action, 0) == -1)
		perror("sigaction");

	int p[2];
	pipe(p);
	sigint_fd_read = p[0];
	sigint_fd_write = p[1];

	// arguments
	std::string mcast_addr;
	uint16_t cmd_port;
	uintmax_t max_space;
	std::string shrd_fldr;
	uint16_t timeout;
	bool synchronized;
	uint16_t verbose;

	auto check_timeout_range = [](uint16_t mn, uint16_t mx, const char* const opt_name){
		return [opt_name, mn, mx](uint16_t v) {
			if (v < mn || v > mx)
				throw validation_error(validation_error::invalid_option_value,
					opt_name, std::to_string(v));
		};
	};

	try {
		options_description desc;
		desc.add_options()
			("help", "Print help")
			("multicast-address,g", value<string>(&mcast_addr)->required(), "multicast address of the server")
			("port,p", value<uint16_t>(&cmd_port)->required(), "server port")
			("max-space,b", value<uintmax_t>(&max_space)->default_value(52428800), "max space")
			("shrd-fldr,f", value<string>(&shrd_fldr)->required(), "folder for sharing")
			("timeout,t", value<uint16_t>(&timeout)->default_value(5)
				->notifier(check_timeout_range(1, 300, "timeout")), "timeout for TCP connections in range <1; 300>")
			("synchronized,s", value<bool>(&synchronized)->default_value(false), "start with synchronization")
			("verbose,v", value<uint16_t>(&verbose)->default_value(0), "start with increased verbosity");

		variables_map vm;
		store(parse_command_line(argc, argv, desc), vm);

		verbose = vm.count("verbose") > 0;

		if (vm.count("help")) {
			std::cout << desc << std::endl;
			return 0;
		}

		notify(vm);
	}
	catch (std::exception &ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
		close(p[0]);
		close(p[1]);
		return 1;
	}

	try {
		Server ser(mcast_addr, cmd_port, max_space, shrd_fldr, timeout, synchronized, verbose);
		ser.start();
	}
	catch (std::exception& ex) {
		std::cerr << ex.what() << std::endl;
	}

	close(p[0]);
	close(p[1]);

	return sigint;
}
