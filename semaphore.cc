#include "semaphore.h"

void Semaphore::wait() {
	for (;;) {
		if (sem_wait(&sem) == 0)
			return;

		if (errno == EINTR)
			continue;

		throw std::runtime_error(std::string("sem_wait() - ") + strerror(errno));
	}
}

bool Semaphore::try_wait() {
	for (;;) {
		if (sem_trywait(&sem) == 0)
			return true;

		if (errno == EINTR)
			continue;

		if (errno == EAGAIN)
			return false;

		throw std::runtime_error(std::string("sem_trywait() - ") + strerror(errno));
	}
}

void Semaphore::post() {
	if (sem_post(&sem))
		throw std::runtime_error(std::string("sem_post() - ") + strerror(errno));
}
