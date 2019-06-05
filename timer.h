#pragma once

#include "message.h"

#include <chrono>

class Timer {
private:
	int init_time_ = -1;
	std::chrono::time_point<std::chrono::high_resolution_clock> t_;
public:
	Timer() : t_(std::chrono::high_resolution_clock::now()) {}
	// returns timeleft in miliseconds
	int get_timeleft() const;
	void start_timer(int miliseconds);
	void stop_timer();
};
