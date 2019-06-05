#pragma once

#include <any>
#include <poll.h>
#include <stdexcept>
#include <sys/timerfd.h>
#include <unistd.h>
#include <vector>

template<typename FDType>
class Poll {
private:
	std::vector<pollfd> fds_;
	std::vector<std::any> info_;
	std::vector<FDType> type_;
public:

	Poll() = default;

	pollfd& get_pollfd(size_t i);
	std::any& get_info(size_t i);
	FDType get_type(size_t i);

	// returns poll result
	int mypoll();

	void clear();
	void remove_fd(size_t i);

	size_t size() const;

	void add_fd(int fd, short events, std::any info, FDType type);
	void add_fd(int fd, short events, FDType type);
	// returns fd to created timerfd
	int add_timer(int seconds, std::any info, FDType type);
	int add_timer(int seconds, FDType type);
};

template<typename FDType>
pollfd& Poll<FDType>::get_pollfd(size_t i) {
	return fds_[i];
}

template<typename FDType>
std::any& Poll<FDType>::get_info(size_t i) {
	return info_[i];
}

template<typename FDType>
FDType Poll<FDType>::get_type(size_t i) {
	return type_[i];
}

template<typename FDType>
int Poll<FDType>::mypoll() {
	return poll(fds_.data(), fds_.size(), -1);
}

template<typename FDType>
void Poll<FDType>::clear() {
	while (fds_.size() > 1) {
		if (fds_.back().fd > 2)
			close(fds_.back().fd);
		fds_.pop_back();
		info_.pop_back();
		type_.pop_back();
	}
}

template<typename FDType>
size_t Poll<FDType>::size() const {
	return fds_.size();
}

template<typename FDType>
void Poll<FDType>::remove_fd(size_t i) {
	if (i > 0) {
		if (fds_[i].fd > 2)
			close(fds_[i].fd);
		std::swap(fds_[i], fds_.back());
		std::swap(info_[i], info_.back());
		std::swap(type_[i], type_.back());
		fds_.pop_back();
		info_.pop_back();
		type_.pop_back();
	}
}

template<typename FDType>
void Poll<FDType>::add_fd(int fd, short events, std::any info, FDType type) {
	fds_.emplace_back(pollfd{fd, events, 0});
	info_.emplace_back(std::move(info));
	type_.emplace_back(type);
}

template<typename FDType>
void Poll<FDType>::add_fd(int fd, short events, FDType type) {
	fds_.emplace_back(pollfd{fd, events, 0});
	info_.emplace_back(-1);
	type_.emplace_back(type);
}

// returns fd to created timerfd
template<typename FDType>
int Poll<FDType>::add_timer(int seconds, std::any info, FDType type) {
	int fd = timerfd_create(CLOCK_REALTIME, 0);
	if (fd < 0)
		throw std::runtime_error("Could not create timer.");

	itimerspec tim;
	tim.it_interval.tv_sec = 0;
	tim.it_interval.tv_nsec = 0;
	tim.it_value.tv_sec = seconds;
	tim.it_value.tv_nsec = 0;

	if (timerfd_settime(fd, 0, &tim, nullptr) < 0)
		close(fd), throw std::runtime_error("Could not create timer.");

	fds_.emplace_back(pollfd{fd, POLLIN, 0});
	info_.emplace_back(std::move(info));
	type_.emplace_back(type);

	return fd;
}

template<typename FDType>
int Poll<FDType>::add_timer(int seconds, FDType type) {
	int fd = timerfd_create(CLOCK_REALTIME, 0);
	if (fd < 0)
		throw std::runtime_error("Could not create timer.");

	itimerspec tim;
	tim.it_interval.tv_sec = 0;
	tim.it_interval.tv_nsec = 0;
	tim.it_value.tv_sec = seconds;
	tim.it_value.tv_nsec = 0;

	if (timerfd_settime(fd, 0, &tim, nullptr) < 0)
		close(fd), throw std::runtime_error("Could not create timer.");

	fds_.emplace_back(pollfd{fd, POLLIN, 0});
	info_.emplace_back(-1);
	type_.emplace_back(type);

	return fd;
}
