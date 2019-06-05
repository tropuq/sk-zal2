#pragma once

#include <semaphore.h>
#include <stdexcept>
#include <string>
#include <string.h>

class Semaphore {
	sem_t sem;

public:
	explicit Semaphore(unsigned value) {
		if (sem_init(&sem, 0, value))
			throw std::runtime_error(std::string("sem_init() - ") + strerror(errno));
	}

	void wait();

	// Returns false iff the operation would block
	bool try_wait();

	void post();

	~Semaphore() {
		sem_destroy(&sem);
	}
};
