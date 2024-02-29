/* SPDX-License-Identifier: Apache-2.0 */
#include <array>
#include <cstring>
#include <cassert>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <vector>

extern "C" {
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <systemd/sd-bus.h>
}

extern "C" {
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>       
}

const unsigned NUM_WORKERS = 16;
int pipefd[2] = {};

static int start_workers(unsigned n_workers, std::vector<pid_t>& workers) {
        for (unsigned i = 0; i < n_workers; i++) {
                pid_t p;
                
                p = fork();
                if (p < 0) {
                        
                        return -errno;
                }

                if (p == 0) {
                        execl("/usr/bin/sleep", "sleep", "infinity", NULL);
                        exit(1);
                }

                workers.push_back(p);
        }

        return 0;
}

static int migrate_workers(const std::vector<pid_t>& workers) {
        sd_bus_message *message = nullptr, *reply = nullptr;
        char scope_name[] = "aux-scope-workers-XXXXXX.scope";
        const char *job = nullptr;
        sd_bus *bus = nullptr;
        int r;
        
        r = sd_bus_open_system(&bus);
        if (r < 0) {
                std::cerr << "Failed to acquire bus." << std::endl;
                return -r;
        }
        std::unique_ptr<sd_bus, void (*)(sd_bus*)> pb(bus, [](sd_bus *bus) { sd_bus_unref(bus); });
                

        r = sd_bus_message_new_method_call(bus, &message,
                                           "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "StartAuxiliaryScope");
        if (r < 0) {
                std::cerr << "Failed to create bus message." << std::endl;
                return r;
        }
        std::unique_ptr<sd_bus_message, void (*)(sd_bus_message*)> pm(message, [](sd_bus_message *m) { sd_bus_message_unref(m); });

        /* Using mktemp() is deprecated however we are not generating filenames so it should be OK in this context. */
        scope_name[strlen("aux-scope-workers-XXXXXX")] = '\0';
        (void) mktemp(scope_name);
        scope_name[strlen("aux-scope-workers-XXXXXX")] = '.';

        r = sd_bus_message_append_basic(message, 's', scope_name);
        if (r < 0) {
                std::cerr << "Failed to attach scope name." << std::endl;
                return r;
        }

        r = sd_bus_message_open_container(message, 'a', "h");
        if (r < 0) {
                std::cerr << "Failed to create array of FDs." << std::endl;
                return r;
        }

        for (auto& w: workers) {
                int fd;

                fd = syscall(SYS_pidfd_open, w, 0);
                if (fd < 0) {
                        std::cerr << "Failed to obtain pidfd." << std::endl;
                        return r;
                }
                        
                r = sd_bus_message_append_basic(message, 'h', &fd);
                if (r < 0) {
                        std::cerr << "Failed to append PIDFD to message." << std::endl;
                        return r;
                }
        }

        r = sd_bus_message_close_container(message);
        if (r < 0) {
                std::cerr << "Failed to close container." << std::endl;
                return r;
        }

        r = sd_bus_message_append(message, "ta(sv)", UINT64_C(0), 1, "Description", "s", "Test auxiliary scope");
        if (r < 0) {
                std::cerr << "Failed to append unit properties." << std::endl;
                return r;
        }

        r = sd_bus_call(bus, message, 0, nullptr, &reply);
        if (r < 0) {
                std::cerr << "Failed to start auxiliary scope." << std::endl;
                return r;
        }

        r = sd_bus_message_read(reply, "o", &job);
        if (r < 0) {
                std::cerr << "Failed to read reply." << std::endl;
                return r;
        }

        std::cout << "PIDs migrated successfully." << std::endl;

        return 0;
}

static int update_main_pid(void) {
        std::stringstream ss;
        pid_t p;
        int r;
        
        p = fork();
        if (p < 0) {
                std::cerr << "Failed to fork()." << std::endl;
                return -errno;
        }

        if (p == 0) {
                read(pipefd[0], &r, sizeof(r));
                _exit(0);
        }

        ss << "MAINPID=" << p;

        r = sd_notify(0, ss.str().c_str());
        if (r < 0) {
                std::cerr << "Failed to set new MAINPID" << std::endl;
                return r;
        }

        std::cout << "MAINPID is now " << p << std::endl;
        return 0;
}

static int sigterm_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        std::vector<pid_t> *workers = static_cast<std::vector<pid_t>*>(userdata);
        int r;

        assert(si->ssi_signo == SIGTERM);

        r = pipe2(pipefd, O_CLOEXEC|O_DIRECT);
        if (r < 0)
                return r;

        r = update_main_pid();
        if (r < 0)
                return r;

        /* We are no longer MAINPID so let's add our selves to the list of PIDs to migrate */
        workers->push_back(getpid());
        
        r = migrate_workers(*workers);
        if (r < 0)
                return r;

        /* Our job is now done so let's notify the child and disable event source */
        write(pipefd[1], &r, sizeof(r));
        sd_event_source_set_enabled(s, SD_EVENT_OFF);
        return 0;
}

int sigint_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        assert(si->ssi_signo == SIGINT);

        (void) userdata;
        sd_event_exit(sd_event_source_get_event(s), 0);
        return 0;
}

int main(void) {
        int r;

        std::vector<pid_t> workers;
        r = start_workers(NUM_WORKERS, workers);
        if (r < 0) {
                std::cerr << "Failed to create worker process: " << ::strerror(-r) << std::endl;
                return EXIT_FAILURE;
        }

        sd_event *loop = nullptr;
        sd_event_source *sigterm_event_source = nullptr, *sigint_event_source = nullptr;
        
        r = sd_event_new(&loop);
        if (r < 0) {
                std::cerr << "Failed to allocate event loop." << std::endl;
                return EXIT_FAILURE;
        }
        std::unique_ptr<sd_event, void (*)(sd_event*)> pl(loop, [](sd_event *loop) { sd_event_unref(loop); });

        r = sd_event_add_signal(loop, &sigterm_event_source, SIGTERM|SD_EVENT_SIGNAL_PROCMASK, sigterm_handler, &workers);
        if (r < 0) {
                std::cerr << "Failed to add SIGTERM event source." << std::endl;
                return EXIT_FAILURE;
        }
        std::unique_ptr<sd_event_source, void (*)(sd_event_source*)> pt(sigterm_event_source, [](sd_event_source *source) { sd_event_source_unref(source); });

        r = sd_event_add_signal(loop, &sigint_event_source, SIGINT|SD_EVENT_SIGNAL_PROCMASK, sigint_handler, nullptr);
        if (r < 0) {
                std::cerr << "Failed to add SIGINT event source." << std::endl;
                return EXIT_FAILURE;
        }
        std::unique_ptr<sd_event_source, void (*)(sd_event_source*)> pi(sigint_event_source, [](sd_event_source *source) { sd_event_source_unref(source); });

        r = sd_notify(0, "READY=1");
        if (r < 0) {
                std::cerr << "Failed to send ready notification to systemd" << std::endl;
                return EXIT_FAILURE;
        }
        
        r = sd_event_loop(loop);
        if (r < 0) {
                std::cerr << "Event loop failed." << std::endl;
                return EXIT_FAILURE;
        }
        
        return EXIT_SUCCESS;
}

