//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
#include "container_environment.hpp"
#include "file_manip.hpp"
#include "container_options.hpp"

#include <iostream>
#include <memory>
#include <array>

#include <cstdlib>

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <string>
#include <algorithm>
#include <iterator>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/range/adaptor/indexed.hpp>

#include <boost/scope_exit.hpp>
#include <boost/optional.hpp>

#include <boost/interprocess/anonymous_shared_memory.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>

#include <boost/range/algorithm_ext/erase.hpp>

#include <sys/resource.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <chrono>
#include <thread>
#include <atomic>
#include <future>

#include "user.hpp"
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




    void set_limit( int resource, rlim_t lim_soft, rlim_t lim_hard )
    {
        assert( lim_hard >= lim_soft);

        auto limits = ::rlimit{ lim_soft, lim_hard };
        if ( ::setrlimit( resource, &limits ) == -1 ) {
            std::stringstream ss;
            ss << "Failed to set_limit: "
               << resource << " : " << lim_soft << " / " << lim_hard
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }
    }

    void set_limit( int resource, rlim_t lim )
    {
        set_limit( resource, lim, lim );
    }


    template<typename V>
    auto make_buffer_for_execve(
        V const& data_set
        )
        -> std::tuple<std::vector<char*>, std::shared_ptr<char>>
    {
        std::vector<char*> ptr_list(
            data_set.size() + 1,
            nullptr
            ); // +1 is for termination

        auto const cont_buf_len =
            std::accumulate( data_set.cbegin(), data_set.cend(),
                             0, []( std::size_t const& len, std::string const& r ) {
                                 return len + ( r.size() + 1 );     // length + EOF
                             });

        // 0 filled continuous buffer
        std::shared_ptr<char> argv_buf(
            new char[cont_buf_len]{},
            std::default_delete<char[]>()
            );

        std::size_t argv_cur_len = 0;
        for( auto&& im : data_set | adap::indexed( 0 ) ) {
            // current ptr in continuous buffer
            char* const cur_ptr = argv_buf.get() + argv_cur_len;

            std::copy( im.value().cbegin(), im.value().cend(), cur_ptr );

            ptr_list[im.index()] = cur_ptr;

            argv_cur_len += im.value().size() + 1;  // +1 is EOF
        }
        assert( argv_cur_len == cont_buf_len );

        return std::make_tuple( std::move( ptr_list ), argv_buf );
    }






    // this function must be invoked by forked process
    void execute_command_in_jail(
        fs::path const& host_container_dir,
        container_options_t const& opts,
        linux::user const& user
        )
    {
        // make environment
        make_jail_environment(
            host_container_dir,
            opts.mount_points,
            opts.copy_points,
            user
            );

        // into jail
        if ( ::chroot( host_container_dir.c_str() ) == -1 ) {
            std::stringstream ss;
            ss << "Failed to chroot: "
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }

        // move to home
        fs::current_path( opts.in_container_start_path );

        // set limits
        if ( opts.limits.core ) {
            set_limit( RLIMIT_CORE, *opts.limits.core );
        }
        if ( opts.limits.nofile ) {
            set_limit( RLIMIT_NOFILE, *opts.limits.nofile );
        }
        if ( opts.limits.nproc ) {
            set_limit( RLIMIT_NPROC, *opts.limits.nproc );
        }
        if ( opts.limits.memlock ) {
            set_limit( RLIMIT_MEMLOCK, *opts.limits.memlock );
        }
        if ( opts.limits.cputime ) {
            // CPU can be used only cpu_limit_time(sec)
            set_limit( RLIMIT_CPU, *opts.limits.cputime, *opts.limits.cputime + 3 );
        }
        if ( opts.limits.memory ) {
            // Memory can be used only memory_limit_bytes [be careful!]
            set_limit( RLIMIT_AS, *opts.limits.memory, *opts.limits.memory * 1.2 );
        }
        if ( opts.limits.fsize ) {
            set_limit( RLIMIT_FSIZE, *opts.limits.fsize );
        }

        set_limit( RLIMIT_STACK, opts.stack_size );

        // TODO: set umask



        // std::system("ls -la /proc/self/fd");

        // redirect: pipes[debug]
        for( auto const& pr : opts.pipe_redirects ) {
            std::cout << "==> host fd: " << pr.host_fd
                      << " will recieve data of child fd: " << pr.guest_fd
                      << std::endl;
        }

        // redirect: pipes
        for( auto const& pr : opts.pipe_redirects ) {
            if ( ::dup2( pr.host_fd, pr.guest_fd ) == -1 ) {
                std::stringstream ss;
                ss << "Failed to dup2: "
                   << " errno=" << errno << " : " << std::strerror( errno );
                throw std::runtime_error( ss.str() );
            }

            if ( ::close( pr.host_fd ) == -1 ) {
                std::stringstream ss;
                ss << "Failed to close the host pipe: "
                   << " errno=" << errno << " : " << std::strerror( errno );
                throw std::runtime_error( ss.str() );
            }
        }

        // === discard privilege
        // change group
        if ( ::setresgid( user.group_id(), user.group_id(), user.group_id() ) == -1 ) {
            std::stringstream ss;
            ss << "Failed to setresgid: "
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }

        // change user
        if ( ::setresuid( user.user_id(), user.user_id(), user.user_id() ) == -1 ) {
            std::stringstream ss;
            ss << "Failed to setresuid: "
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }
        // ===

        // ==
        // now I am in the sandbox!
        // ==
        if ( opts.commands.size() < 1 ) {
            std::stringstream ss;
            ss << "Failed to prepare environment: commands must have >= 1 elements (" << opts.commands.size() << ")";
            throw std::runtime_error( ss.str() );
        }

        auto const& filename = opts.commands[0];

        auto argv_pack = make_buffer_for_execve( opts.commands );
        auto& argv = std::get<0>( argv_pack );

        auto envp_pack = make_buffer_for_execve( opts.envs );
        auto& envp = std::get<0>( envp_pack );



        // replace self process
        if ( ::execve( filename.c_str(), argv.data(), envp.data() ) == -1 ) {
            std::stringstream ss;
            ss << "Failed to execve: "
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }
    }


    struct comm_info_t
    {
        static constexpr std::size_t BufferLength = 2000;

        int error_status;
        char message[BufferLength];
    };

    struct arguments_for_jail
    {
        fs::path const* const p_host_container_dir;
        container_options_t const* const p_opts;
        linux::user const* const p_user;
        comm_info_t* comm_info;
    };

    void child_process(
        fs::path const& host_container_dir,
        container_options_t const& opts,
        linux::user const& user,
        comm_info_t& comm_info
        )
    try {
        execute_command_in_jail( host_container_dir, opts, user );
        // after this, stdio should not be used, because they may be redirected

    } catch( fs::filesystem_error const& e ) {
        // TODO: error handling
        comm_info.error_status = 100;
        std::strncpy( comm_info.message, e.what(), comm_info_t::BufferLength - 1 );

    } catch( std::exception const& e ) {
        comm_info.error_status = 200;
        std::strncpy( comm_info.message, e.what(), comm_info_t::BufferLength - 1 );

    } catch(...) {
        comm_info.error_status = 300;
        std::strncpy(
            comm_info.message,
            "Unexpected exception[execute_command_in_jail_entry]",
            comm_info_t::BufferLength - 1
            );
    }

    void wait_pid_with_monitor(
        int const pid,
        std::promise<boost::optional<executed_result>> p
        )
    {
        int child_status;
        ::rusage usage;

        if ( ::wait4( pid, &child_status, 0, &usage ) == -1 ) {
            std::cerr << "Failed to waitpid. errno=" << errno << " : " << std::strerror(errno) << std::endl;
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
        std::cout << "parent process: child finished / " << std::endl
                  << child_result << std::endl;

        auto const close_flag = ( opts.result_output_fd > 2 )
            ? bio::file_descriptor_flags::close_handle
            : bio::file_descriptor_flags::never_close_handle
            ;
        bio::stream<bio::file_descriptor_sink> ofs( opts.result_output_fd, close_flag );
        if ( !ofs ) {
            std::cerr << "parent process: child finished :: failed to create result" << std::endl;
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
    int execute_command_in_jail_entry(
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
            return -1;
        }

        if ( pid == 0 ) {
            // child process
            child_process( host_container_dir, opts, user, comm_info );

            // if reached to here, maybe error...
            std::exit( -100 );    // never call destructor of stack objects(Ex. anon_user)
        }

        // parent process

        std::promise<boost::optional<executed_result>> p;
        auto f = p.get_future();

        //
        std::thread th( wait_pid_with_monitor, pid, std::move( p ) );
        if ( opts.limits.cputime ) {
            // realtime checking apart from cgroup limits
            // prevent sleep() function running infinite
            // +4 is extention...
            auto const span
                = std::chrono::seconds{ *opts.limits.cputime + 4 };
            if ( f.wait_for( span ) == std::future_status::timeout ) {
                std::cout << "Timer timeout!" << std::endl;

                if ( ::kill( pid, SIGKILL ) == -1 ) {
                    std::cerr << "Failed to kill child."
                              << " errno=" << errno
                              << " : " << std::strerror(errno) << std::endl;
                    return -1;
                }
            }
        }

        // wait for result, blocking
        auto const child_result = f.get();
        th.join();

        if ( child_result ) {
            export_result_to_fd( *child_result, opts, comm_info );

        } else {
            std::cerr << "parent process: child finished :: failed to waitpid" << std::endl;
            return -1;
        }

        return 0;
    }







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
                return -1;
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
                // throw
                return -10;
            }

            void* aligned_ptr = static_cast<void*>( static_cast<char*>( ptr ) + offset );
            auto comm_info_p = new(aligned_ptr) comm_info_t{};  // value initialize

            return execute_command_in_jail_entry(
                host_container_dir,
                opts,
                user,
                *comm_info_p
                );

        } catch( ipc::interprocess_exception const& ex ) {
            std::cerr << "ipc error: " << ex.what() << std::endl;
            return -1;

        } catch(...) {
            std::cerr << "unknown" << std::endl;
            return -2;
        }

        std::cout << "wait_pid_with_monitor finished" << std::endl;
        return 0;
    }

    // TODO: exception handling
    int run_in_container( container_options_t const& opts )
    {
        std::cout << "Host base dir: " << opts.host_containers_base_dir << std::endl;

        expect_root();



        // make user
        auto const anon_user = make_anonymous_user();
        if ( anon_user == boost::none ) {
            std::cerr << "Failed to create user" << std::endl;
            return -2;
        }
        assert( anon_user->valid() );

        auto const host_container_dir = opts.host_containers_base_dir / anon_user->name();
        std::cout << "Host container dir: " << host_container_dir << std::endl;

        // after execution, reset environment
        BOOST_SCOPE_EXIT_ALL(&host_container_dir, &opts) {
            reset_jail_environment(
                opts.host_containers_base_dir,
                host_container_dir,
                opts.mount_points,
                opts.copy_points
                );
        };

        std::size_t const stack_for_child_size = opts.stack_size;
        auto stack_for_child = new std::uint8_t[stack_for_child_size];

        //
        auto args = arguments_for_jail {
            &host_container_dir,
            &opts,
            &*anon_user
        };
        // create the process that executes jailed command!
        pid_t const pid = ::clone(
            &cloned_entry_point,
            stack_for_child + stack_for_child_size,
            CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | SIGCHLD | CLONE_UNTRACED/* | CLONE_NEWUSER*/,
            &args
            );
        if ( pid == -1 ) {
            std::cerr << "Clone failed. errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return -3;
        }

        // blocking, wait for cloned process
        int status;
        if ( waitpid( pid, &status, 0) == -1 ) {
            std::cerr << "waitpid failed. errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return -4;
        }

        return status;
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

    int execute( container_options_t const& opts ) noexcept
    try {
        for( auto&& sig : IgnSignals ) {
            if ( ::signal( sig, SIG_IGN ) == SIG_ERR ) {
                std::stringstream ss;
                ss << "Failed to signal: " << sig
                   << " errno=" << errno << " : " << std::strerror( errno );
                throw std::runtime_error( ss.str() );
            }
        }

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


int main( int argc, char* argv[] )
{
    namespace po = boost::program_options;

    // Generic options
    po::options_description generic( "Generic options" );
    generic.add_options()
        ( "base-host-path", po::value<std::string>(), "sandbox path will be $base-host-path/$id" )

        ( "start-guest-path", po::value<std::string>(), "cd to $start-guest-path in container at first (Ex. /home/some_user)" )
        ( "mount", po::value<std::vector<std::string>>(), "host:guest(:rw?)" )
        ( "copy", po::value<std::vector<std::string>>(), "host:guest" )

        ( "core", po::value<::rlim_t>(), "setrlimit core" )
        ( "nofile", po::value<::rlim_t>(), "setrlimit nofile" )
        ( "nproc", po::value<::rlim_t>(), "setrlimit nproc" )
        ( "memlock", po::value<::rlim_t>(), "setrlimit memlock" )
        ( "cputime", po::value<::rlim_t>(), "setrlimit cpu time" )
        ( "memory", po::value<::rlim_t>(), "setrlimit memory" )
        ( "fsize", po::value<::rlim_t>(), "setrlimit fsize" )

        ( "stack-size", po::value<std::size_t>(), "stack size" )
        ( "pipe", po::value<std::vector<std::string>>(), "host-fd:guest-fd" )

        // commands is "argv-in-container"
        ( "env", po::value<std::vector<std::string>>(), "env variables" )

        ( "result-fd", po::value<int>(), "fd can get detail of result" )
        ( "result-type", po::value<std::string>(), "type of result [json]" )

        ( "help", "produce help message" )
        ;

    po::options_description hidden( "Hidden options" );
    hidden.add_options()
        ( "argv-in-container", po::value<std::vector<std::string>>(), "argv" )
        ;

    po::options_description cmdline_options;
    cmdline_options
        .add( generic )
        .add( hidden )
        ;

    po::positional_options_description p;
    p.add( "argv-in-container", -1 );

    try {
        po::variables_map vm;
        po::store(
            po::command_line_parser( argc, argv )
                .options( cmdline_options )
                .positional( p )
                .run(),
            vm
            );
        po::notify( vm );

        //
        if ( vm.count( "help" ) ) {
            std::cout << cmdline_options << std::endl;
            return 0;
        }

        // default option
        auto c_opts = awaho::container_options_t{
            "/tmp/containers_tmp",

            "/",                        // start path in container
            {},                         // mounts
            {},                         // copies
            awaho::limits_values_t{},   // no limitation(use system default)

            2 * 1024 * 1024,            // stack size
            {},                         // no pipe redirect

            { "/bin/bash" },            // default comands
            {},                         // default envs

            1,                          // default fd gets result (stdout)
            "json"                      // default result format
        };

        if ( vm.count( "base-host-path" ) ) {
            auto const& base_host_path =
                vm["base-host-path"].as<std::string>();

            c_opts.host_containers_base_dir = base_host_path;
        }

        if ( vm.count( "start-guest-path" ) ) {
            auto const& start_guest_path =
                vm["start-guest-path"].as<std::string>();

            c_opts.in_container_start_path = start_guest_path;
        }

        if ( vm.count( "mount" ) ) {
            auto const& mounts =
                vm["mount"].as<std::vector<std::string>>();
            for( auto&& v : mounts ) {
                std::vector<std::string> d;
                boost::algorithm::split( d, v, boost::is_any_of(":") );

                if ( d.size() < 2 ) {
                    throw std::runtime_error( "invalid mount option" ); // TODO: fix
                }

                auto mp = awaho::mount_point{
                    d[0],   // host
                    d[1],   // guest
                    true    // readonly(default)
                };

                if ( d.size() >= 3 ) {
                    if ( d[2] == "rw" ) {
                        mp.is_readonly = false;

                    } else if ( d[2] == "ro" ) {
                        mp.is_readonly = true;

                    } else {
                        throw std::runtime_error( "unknown mount option" ); // TODO: fix
                    }
                }

                c_opts.mount_points.emplace_back( std::move( mp ) );
            }
        }

        if ( vm.count( "copy" ) ) {
            auto const& copies =
                vm["copy"].as<std::vector<std::string>>();
            for( auto&& v : copies ) {
                std::vector<std::string> d;
                boost::algorithm::split( d, v, boost::is_any_of(":") );

                if ( d.size() < 2 ) {
                    throw std::runtime_error( "invalid copy option" ); // TODO: fix
                }

                auto cp = awaho::copy_point{
                    d[0],   // host
                    d[1],   // guest
                };

                c_opts.copy_points.emplace_back( std::move( cp ) );
            }
        }

        {
            if ( vm.count( "core" ) ) {
                c_opts.limits.core
                    = vm["core"].as<::rlim_t>();
            }

            if ( vm.count( "nofile" ) ) {
                c_opts.limits.nofile
                    = vm["nofile"].as<::rlim_t>();
            }

            if ( vm.count( "nproc" ) ) {
                c_opts.limits.nproc
                    = vm["nproc"].as<::rlim_t>();
            }

            if ( vm.count( "memlock" ) ) {
                c_opts.limits.memlock
                    = vm["memlock"].as<::rlim_t>();
            }

            if ( vm.count( "cputime" ) ) {
                c_opts.limits.cputime
                    = vm["cputime"].as<::rlim_t>();
            }

            if ( vm.count( "memory" ) ) {
                c_opts.limits.memory
                    = vm["memory"].as<::rlim_t>();
            }

            if ( vm.count( "fsize" ) ) {
                c_opts.limits.fsize
                    = vm["fsize"].as<::rlim_t>();
            }
        }

        if ( vm.count( "stack-size" ) ) {
            auto const& stack_size =
                vm["stack-size"].as<std::size_t>();

            c_opts.stack_size = stack_size;
        }

        if ( vm.count( "pipe" ) ) {
            auto const& pipes =
                vm["pipe"].as<std::vector<std::string>>();
            for( auto&& v : pipes ) {
                std::vector<std::string> d;
                boost::algorithm::split( d, v, boost::is_any_of(":") );

                if ( d.size() != 2 ) {
                    throw std::runtime_error( "invalid pipe option" ); // TODO: fix
                }

                auto pr = awaho::pipe_redirect_t{
                    boost::lexical_cast<int>( boost::trim_copy( d[0] ) ),   // host
                    boost::lexical_cast<int>( boost::trim_copy( d[1] ) ),   // guest
                };

                c_opts.pipe_redirects.emplace_back( std::move( pr ) );
            }
        }

        if ( vm.count( "argv-in-container" ) ) {
            auto commands =
                vm["argv-in-container"].as<std::vector<std::string>>();

            c_opts.commands = boost::remove_erase( commands, "" );  // remove empty
        }

        if ( vm.count( "env" ) ) {
            auto envs = vm["env"].as<std::vector<std::string>>();
            c_opts.envs = boost::remove_erase( envs, "" );  // remove empty
        }

        if ( vm.count( "result-fd" ) ) {
            c_opts.result_output_fd =
                vm["result-fd"].as<int>();
        }

        if ( vm.count( "result-type" ) ) {
            c_opts.result_output_type =
                vm["result-type"].as<std::string>();
        }

        return awaho::execute( c_opts );

    } catch( std::exception const& e ) {
        std::cerr << "Exception: " << std::endl
                  << e.what() << std::endl;
        return -10;

    } catch(...) {
        std::cerr << "Unexpected exception: " << std::endl;
        return -20;
    }
}
