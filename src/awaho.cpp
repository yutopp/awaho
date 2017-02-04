//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//

#include <iostream>
#include <memory>
#include <array>
#include <cstring>

#include <boost/scope_exit.hpp>
#include <boost/optional.hpp>

#define BOOST_THREAD_PROVIDES_FUTURE
#include <boost/thread.hpp>
#include <boost/thread/future.hpp>

#include <boost/filesystem/path.hpp>
#include <boost/interprocess/anonymous_shared_memory.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/range/adaptor/indexed.hpp>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "user.hpp"
#include "container_options.hpp"
#include "jailed_command_executor.hpp"
#include "virtual_root.hpp"
#include "utility.hpp"

#include "ext/picojson.h"


namespace awaho
{
    namespace fs = boost::filesystem;
    namespace bio = boost::iostreams;
    namespace adap = boost::adaptors;
    namespace ipc = boost::interprocess;

    struct executed_result
    {
        bool exited;
        int exit_status;
        bool signaled;
        int signal;
        double user_time_micro_sec;
        double system_time_micro_sec;
        double cpu_time_micro_sec;
        unsigned long long used_memory_bytes;
    };

    std::ostream& operator<<( std::ostream& os, executed_result const& res )
    {
        os << "exited: " << res.exited << std::endl
           << "exit_status:  " << res.exit_status << std::endl
           << "signaled: " << res.signaled << std::endl
           << "signal: " << res.signal << std::endl
           << "user_time_micro_sec: " << res.user_time_micro_sec << std::endl
           << "system_time_micro_sec: " << res.system_time_micro_sec << std::endl
           << "cpu_time_micro_sec: " << res.cpu_time_micro_sec << std::endl
           << "used_memory_bytes: " << res.used_memory_bytes << std::endl
            ;

        return os;
    }

    struct comm_info_t
    {
        static constexpr std::size_t BufferLength = 2000;

        int error_status;
        char message[BufferLength];
    };


    void monitor_pid(
        int const pid,
        boost::promise<boost::optional<executed_result>>& p
        )
    {
        int child_status;
        ::rusage usage;

        if ( ::wait4( pid, &child_status, 0, &usage ) == -1 ) {
            std::cerr << "Failed to waitpid."
                      << " errno=" << errno << " : " << std::strerror( errno ) << std::endl;
            p.set_value( boost::none );
            return;
        }

        auto const user_time_micro_sec =
            static_cast<double>( usage.ru_utime.tv_sec ) * 1e6 + static_cast<double>( usage.ru_utime.tv_usec );
        auto const system_time_micro_sec =
            static_cast<double>( usage.ru_stime.tv_sec ) * 1e6 + static_cast<double>( usage.ru_stime.tv_usec );

        auto const cpu_time_micro_sec = user_time_micro_sec + system_time_micro_sec;

        auto const used_memory_bytes = static_cast<unsigned long long>( usage.ru_maxrss ) * 1024;  // units is KB

        auto result = executed_result{
            WIFEXITED(child_status),
            WEXITSTATUS(child_status),
            WIFSIGNALED(child_status),
            WTERMSIG(child_status),
            user_time_micro_sec,
            system_time_micro_sec,
            cpu_time_micro_sec,
            used_memory_bytes
        };
        p.set_value( std::move( result ) );
    }

    auto export_result_to_fd(
        executed_result const& child_result,
        container_options_t const& opts,
        comm_info_t const& comm_info
        )
        -> bool
    {
        auto const close_flag = ( opts.result_output_fd > 2 )
            ? bio::file_descriptor_flags::close_handle
            : bio::file_descriptor_flags::never_close_handle
            ;
        bio::stream<bio::file_descriptor_sink> ofs( opts.result_output_fd, close_flag );
        if ( !ofs ) {
            std::cerr << "Failed to create fd stream" << std::endl;
            return false;
        }

        if ( opts.result_output_type == "json" ) {
            picojson::value::object obj{
                { "exited", picojson::value( child_result.exited ) },
                { "exitStatus", picojson::value( static_cast<double>( child_result.exit_status ) ) },
                { "signaled", picojson::value( child_result.signaled ) },
                { "signal", picojson::value( static_cast<double>( child_result.signal ) ) },

                { "userTimeMicroSec", picojson::value( child_result.user_time_micro_sec ) },
                { "systemTimeMicroSec", picojson::value( child_result.system_time_micro_sec ) },
                { "cpuTimeMicroSec", picojson::value( child_result.cpu_time_micro_sec ) },
                { "usedMemoryBytes", picojson::value( static_cast<double>( child_result.used_memory_bytes ) ) },

                { "systemErrorStatus", picojson::value( static_cast<double>( comm_info.error_status ) ) },
                { "systemErrorMessage", picojson::value( comm_info.message ) },
            };
            picojson::value root( obj );

            root.serialize( std::ostream_iterator<char>( ofs ) );

        } else {
            std::cerr << "Error: type " << opts.result_output_type << " is not supported" << std::endl;
            return false;
        }

        return true;
    }


    // this function must be invoked by cloned process
    int execute_command_with_monitor(
        fs::path const& host_container_dir,
        container_options_t const& opts,
        linux::user const& user,
        comm_info_t& comm_info
        )
    {
        // fork process that executes sandboxed process
        auto const pid = ::fork();
        if ( pid == -1 ) {
            // error
            comm_info.error_status = 10;
            std::strncpy(
                comm_info.message,
                "Failed to fork",
                comm_info_t::BufferLength - 1
                );
            return -30;
        }

        if ( pid == 0 ) {
            // if succeeded, this function is 'noreturn'
            execute_command_in_jail_entry( host_container_dir, opts, user, comm_info );

            // if reached to here, maybe error...
            std::exit( -100 );    // never call destructor of stack objects(Ex. anon_user)

        } else {
            // parent process(monitor)
            boost::promise<boost::optional<executed_result>> p;
            boost::future<boost::optional<executed_result>> f = p.get_future();

            //
            boost::thread th( monitor_pid, pid, boost::ref( p ) );

            //
            if ( opts.limits.cputime ) {
                // realtime checking apart from cgroup limits
                // prevent sleep() function running infinite
                // +3 is extention...
                auto const span
                    = boost::chrono::seconds{ *opts.limits.cputime + 3 };
                if ( f.wait_for( span ) == boost::future_status::timeout ) {
                    std::cout << "Timer timeout!" << std::endl;

                    // timeouted, so kill the child
                    if ( ::kill( pid, SIGKILL ) == -1 ) {
                        std::cerr << "Failed to kill child."
                                  << " errno=" << errno
                                  << " : " << std::strerror(errno) << std::endl;
                        return -31;
                    }
                }
            }

            // wait for result, blocking
            std::cout << "[+] Monitor: wait for child process termination" << std::endl;
            auto const child_result = f.get();
            th.join();

            if ( child_result ) {
                std::cout << "[+] Monitor: child process is finished" << std::endl
                          << *child_result << std::endl;

                if ( !export_result_to_fd( *child_result, opts, comm_info ) ) {
                    return -32;
                }

                // export_result_to_fd may not output newline...
                std::cout << std::endl;

            } else {
                std::cerr << "parent process: child finished :: failed to waitpid" << std::endl;
                return -33;
            }

            return 0;
        }
    }


    struct arguments_for_jail
    {
        fs::path const* const p_host_container_dir;
        container_options_t const* const p_opts;
        linux::user const* const p_user;
    };

    // this function must be invoked by cloned process
    int cloned_entry_point( void* raw_args )
    {
        arguments_for_jail const* const args =
            static_cast<arguments_for_jail const*>( raw_args );
        fs::path const& host_container_dir
            = *args->p_host_container_dir;
        container_options_t const& opts
            = *args->p_opts;
        linux::user const& user
            = *args->p_user;

        // make the special pipe close when exec
        if ( opts.result_output_fd > 2 ) {
            if ( ::fcntl( opts.result_output_fd, F_SETFD, FD_CLOEXEC ) == -1 ) {
                std::cerr << "Failed to set FD_CLOEXEC to fd("
                          << opts.result_output_fd << ")" << std::endl;
                return -20;
            }
        }

        try {
            constexpr auto CommBufferSize = 2048;

            // create shared buffer (comm_info)
            ipc::mapped_region region( ipc::anonymous_shared_memory( CommBufferSize ) );
            void* const ptr = region.get_address();
            auto const offset =
                alignof(comm_info_t) - ( reinterpret_cast<std::uintptr_t>( ptr ) % alignof(comm_info_t) );
            auto const free_size = CommBufferSize - offset;
            if ( free_size < sizeof(comm_info_t) ) {
                std::cerr << "Invalid object size" << std::endl;
                return -21;
            }

            void* aligned_ptr = static_cast<void*>( static_cast<char*>( ptr ) + offset );
            auto comm_info_p = new(aligned_ptr) comm_info_t{};  // value initialize

            return execute_command_with_monitor(
                host_container_dir,
                opts,
                user,
                *comm_info_p
                );

        } catch( ipc::interprocess_exception const& ex ) {
            std::cerr << "IPC error: " << ex.what() << std::endl;
            return -22;

        } catch(...) {
            std::cerr << "Unknown exception" << std::endl;
            return -23;
        }
    }


    static const std::array<int, 7> IgnSignals{{
        SIGHUP,
        SIGINT,
        SIGQUIT,
        SIGPIPE,
        SIGTERM,
        SIGXCPU,
        SIGXFSZ
    }};
    void ignore_signals()
    {
        for( auto&& sig : IgnSignals ) {
            if ( ::signal( sig, SIG_IGN ) == SIG_ERR ) {
                std::stringstream ss;
                ss << "Failed to signal: " << sig
                   << " errno=" << errno << " : " << std::strerror( errno );
                throw std::runtime_error( ss.str() );
            }
        }
    }


    int run_in_container( container_options_t const& opts )
    {
        std::cout << "Host base dir: " << opts.host_containers_base_dir << std::endl;

        // TODO: fix
        expect_cap();

        // make user
        auto const anon_user = make_anonymous_user();
        if ( anon_user == boost::none ) {
            std::cerr << "Failed to create user" << std::endl;
            return -10;
        }
        assert( anon_user->valid() );

        auto const host_container_dir = opts.host_containers_base_dir / anon_user->name();
        std::cout << "Host container dir: " << host_container_dir << std::endl;

        // after execution, destruct environment
        BOOST_SCOPE_EXIT_ALL(&host_container_dir, &opts) {
            std::cout << "[+] Destruct sandbox environment" << std::endl;
            destruct_virtual_root(
                opts.host_containers_base_dir,
                host_container_dir,
                opts.mount_points,
                opts.copy_points
                );
        };

        // TODO: change process name

        std::size_t const stack_for_child_size = opts.stack_size;
        auto stack_for_child = new std::uint8_t[stack_for_child_size];

        //
        auto args = arguments_for_jail {
            &host_container_dir,
            &opts,
            &*anon_user
        };
        // create the process that executes jailed command with monitor
        // namespaces are separated
        pid_t const pid = ::clone(
            &cloned_entry_point,
            stack_for_child + stack_for_child_size,
            CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | SIGCHLD | CLONE_UNTRACED/* | CLONE_NEWUSER*/,
            &args
            );
        if ( pid == -1 ) {
            std::cerr << "Clone failed. errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return -11;
        }

        // to execute destructor when signal raised
        ignore_signals();

        // blocking, wait for cloned process[monitor root]
        std::cout << "[+] Waitpid(for clone)" << std::endl;

        int status;
        if ( waitpid( pid, &status, 0 ) == -1 ) {
            std::cerr << "waitpid failed. errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return -12;
        }

        std::cout << "[+] Finished [run_in_container]" << std::endl;

        return status;
    }

    int execute( container_options_t const& opts ) noexcept
    try {
        std::cout << opts << std::endl;

        return run_in_container( opts );

    } catch( std::exception const& e ) {
        std::cerr << "Exception[execute]: " << e.what() << std::endl;
        return -1;

    } catch(...) {
        std::cerr << "Unexpected exception[execute]" << std::endl;
        return -2;
    }

} // namespace awaho
