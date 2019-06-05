#include "timer.h"

int Timer::get_timeleft() const {
	if (init_time_ < 0)
		return -1;
	auto now = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> tm = now - t_;
	double diff = init_time_ - tm.count();
	return diff < 0 ? 0 : diff;
}

void Timer::start_timer(int mili) {
	init_time_ = mili;
	t_ = std::chrono::high_resolution_clock::now();
}

void Timer::stop_timer() {
	init_time_ = -1;
}
