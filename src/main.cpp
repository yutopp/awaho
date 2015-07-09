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

#include <cstdlib>

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include <boost/scope_exit.hpp>
#include <boost/optional.hpp>

#include <boost/interprocess/anonymous_shared_memory.hpp>
#include <boost/interprocess/mapped_region.hpp>




#include <random>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <chrono>
#include <thread>
#include <atomic>
#include <future>

#include "files.hpp"
#include "linux_user.hpp"

namespace awaho
{
    namespace fs = boost::filesystem;

    struct mount_point
    {
        fs::path host_path;
        fs::path guest_path;
        int permission;
        bool is_readonly;
    };

    struct limits_values
    {
        int core;       //
        int nofile;     // number
        int nproc;      // number
        int memlock;    // number
        int cpu;        // seconds
        int memory;     // bytes
        int fsize;      // bytes
    };

    struct container_options
    {
        fs::path host_containers_base_dir;

        fs::path in_container_home_path;
        std::vector<mount_point> mount_points;
        limits_values limits;

        std::size_t stack_size;
    };


    auto make_random_name()
        -> std::string
    {
        static char const BaseChars[] = "abcdefghijklmnopqrstuvwxyz1234567890";

        auto gen = std::mt19937( std::random_device{}() );
        auto dist = std::uniform_int_distribution<int>{
            0,
            sizeof(BaseChars) / sizeof(char) - 1 /*term*/ -1 /*closed-interval*/
        };

        constexpr auto MaxNameLength = 10;    //28;
        char random_chars[MaxNameLength+1] = {};
        for( int i=0; i<MaxNameLength; ++i ) {
            auto const index = dist(gen);
            random_chars[i] = BaseChars[index];
        }

        return std::string("_") + random_chars;
    }

    auto make_anonymous_user()
        -> boost::optional<linux::user>
    {
        // retry 5 times
        for( int i=0; i<5; ++i ) {
            linux::user u( make_random_name() );
            if ( u.valid() ) {
                return std::move( u );
            }
        }

        return boost::none;
    }


    // NOTE: be careful order of directories. short to long.
    static char const * const HostReadonlyMountPoints[] = {
        "/etc",
        "/include",
        "/lib",
        "/lib32",
        "/lib64",
        "/bin",
        "/usr/include",
        "/usr/lib",
        "/usr/lib32",
        "/usr/lib64",
        "/usr/bin",
        "/usr/local/torigoya",
    };


    template<typename F = decltype(&remove_directory_if_empty)>
    bool remove_container_directory(
        fs::path const& guest_dir,
        F const& rm_f = &remove_directory_if_empty
        )
    {
        assert( guest_dir.is_absolute() );

        auto const begin = fs::directory_iterator( guest_dir );
        auto const end = fs::directory_iterator();

        for( auto&& it : boost::make_iterator_range( begin, end ) ) {
            auto const& p = it.path();
            std::cout << "-> " << p << std::endl;

            if ( fs::is_symlink( p ) ) {
                // TODO: unlink

            } else if ( fs::is_directory( p ) ) {
                remove_container_directory( p, rm_f );

            } else if ( fs::is_regular_file( p ) ) {
                // TODO: remove

            }
        }

        return rm_f( guest_dir );
    }

    static std::tuple<char const*, ::dev_t, ::mode_t> const StandardNodes[] = {
        std::make_tuple( "null", ::makedev( 1, 3 ), 0666 ),
        std::make_tuple( "zero", ::makedev( 1, 5 ), 0666 ),
        std::make_tuple( "full", ::makedev( 1, 7 ), 0666 ),
        std::make_tuple( "random", ::makedev( 1, 8 ), 0644 ),
        std::make_tuple( "urandom", ::makedev( 1, 9 ), 0644 )
    };

    void make_standard_nodes(
        fs::path const& guest_mount_point,
        fs::perms const& prms
        )
    {
        // TODO: add timeout
        // TODO: check permission
        std::cout << "Createing: " << "/dev" << " to " << guest_mount_point << std::endl;

        //
        fs::create_directories( guest_mount_point );
        fs::permissions( guest_mount_point, prms );

        //
        for( auto const& n : StandardNodes ) {
            make_node( guest_mount_point / std::get<0>( n ), std::get<1>( n ), std::get<2>( n ) );
        }
    }

    bool remove_standard_nodes(
        fs::path const& guest_mount_point
        ) noexcept
    {
        using namespace boost::adaptors;

        bool result = true;

        for( auto const& n : StandardNodes | reversed ) {
            try {
                fs::remove( guest_mount_point / std::get<0>( n ) );

            } catch(...) {
                // TODO: error handling
                result = false;
            }
        }

        return result;
    }

    void link_io(
        fs::path const& guest_proc_dir,
        fs::path const& guest_dev_dir
        )
    {
        make_symlink( guest_proc_dir / "self" / "fd" / "0", guest_dev_dir / "stdin" );
        make_symlink( guest_proc_dir / "self" / "fd" / "1", guest_dev_dir / "stdout" );
        make_symlink( guest_proc_dir / "self" / "fd" / "2", guest_dev_dir / "stderr" );
    }

    bool unlink_io(
        fs::path const& guest_dev_dir
        ) noexcept
    {
        auto const b1 = remove_symlink( guest_dev_dir / "stderr" );
        auto const b2 = remove_symlink( guest_dev_dir / "stdout" );
        auto const b3 = remove_symlink( guest_dev_dir / "stdin" );

        return b1 && b2 && b3;
    }

    static auto const guest_proc_path = fs::path( "./proc" );
    static auto const guest_dev_path = fs::path( "./dev" );
    static auto const guest_tmp_path = fs::path( "./tmp" );

    template<typename MountPoints>
    void create_files_in_jail(
        fs::path const& host_container_dir,
        MountPoints const& mount_points,
        linux::user const& user
        )
    {
        // important
        fs::current_path( host_container_dir );

        // mount system dirs
        for( auto const& host_ro_mount_point : HostReadonlyMountPoints ) {
            if ( !fs::exists( host_ro_mount_point ) ) {
                continue;
            }

            auto const in_container_mount_point = fs::path(".") / host_ro_mount_point;
            mount_directory_ro( host_ro_mount_point, in_container_mount_point );
        }

        //
        for( auto const& users_mp : mount_points ) {
            if ( !fs::exists( users_mp.host_path ) ) {
                continue;
            }

            auto const in_container_mount_point = fs::path(".") / users_mp.guest_path;
            mount_directory_ro( users_mp.host_path, in_container_mount_point );
            change_directory_owner_rec( in_container_mount_point, user );
        }

        //
        mount_procfs( guest_proc_path );
        mount_tmpfs( guest_tmp_path );

        //
        make_standard_nodes( guest_dev_path, fs::perms( 0555 ) );

        //
        link_io( guest_proc_path, guest_dev_path );
    }

    template<typename MountPoints>
    void make_jail_environment(
        fs::path const& host_container_dir,
        MountPoints const& mount_points,
        linux::user const& user
        )
    {
        std::cerr << "make_jail_environment" << std::endl;

        // create container dir
        fs::create_directories( host_container_dir );

        // create/mount/link files
        create_files_in_jail( host_container_dir, mount_points, user );
    }


    template<typename MountPoints>
    void reset_jail_environment(
        fs::path const& host_jail_base_path,
        fs::path const& host_container_dir,
        MountPoints const& mount_points
        )
    {
        using namespace boost::adaptors;

        // important
        fs::current_path( host_container_dir );

        //
        unlink_io( guest_dev_path );

        //
        remove_standard_nodes( guest_dev_path );

        //
        cleanup_directory( guest_tmp_path );
        cleanup_directory( guest_proc_path );

        //
        for( auto const& users_mp : mount_points | reversed ) {
            auto const in_container_mount_point = fs::path(".") / users_mp.guest_path;

            if ( !fs::exists( in_container_mount_point ) ) {
                continue;
            }

            cleanup_directory( in_container_mount_point );
        }

        //
        for( auto const& host_ro_mount_point : HostReadonlyMountPoints | reversed ) {
            auto const in_container_mount_point = fs::path(".") / host_ro_mount_point;

            if ( !fs::exists( in_container_mount_point ) ) {
                continue;
            }

            cleanup_directory( in_container_mount_point );
        }

        //
        fs::current_path( host_jail_base_path );
        remove_container_directory( host_container_dir );
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


    struct arguments_for_jail
    {
        fs::path const* const p_host_container_dir;
        container_options const* const p_opts;
        linux::user const* const p_user;
        int* comm;
    };


    // this function must be invoked by forked process
    void execute_command_in_jail(
        fs::path const& host_container_dir,
        container_options const& opts,
        linux::user const& user
        )
    {
        // make environment
        make_jail_environment(
            host_container_dir,
            opts.mount_points,
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
        fs::current_path( opts.in_container_home_path );

        // set limits
        set_limit( RLIMIT_CORE, opts.limits.core );
        set_limit( RLIMIT_NOFILE, opts.limits.nofile );
        set_limit( RLIMIT_NPROC, opts.limits.nproc );
        set_limit( RLIMIT_MEMLOCK, opts.limits.memlock );
        set_limit( RLIMIT_CPU, opts.limits.cpu + 1, opts.limits.cpu + 3 );  // CPU can be used only cpu_limit_time(sec)
        set_limit( RLIMIT_AS, opts.limits.memory );                         // Memory can be used only memory_limit_bytes [be careful!]
        set_limit( RLIMIT_FSIZE, opts.limits.fsize );

        set_limit( RLIMIT_STACK, opts.stack_size );

        // TODO: set umask

        // ===
        // change group
        if ( ::setresgid( user.group_id(), user.group_id(), user.group_id() ) != 0 ) {
            std::stringstream ss;
            ss << "Failed to setresgid: "
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }

        // change user
        if ( ::setresuid( user.user_id(), user.user_id(), user.user_id() ) != 0 ) {
            std::stringstream ss;
            ss << "Failed to setresuid: "
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }
        // ===

        //
        std::system("pwd");
        std::system("ls -la");

        std::system("ls -la /");
        std::system("cd /; ls -la ../");

        std::system("ls -la /dev");

        std::system("echo /home");
        std::system("ls -la /home");
        std::system("echo /home/torigoya");
        std::system("ls -la /home/torigoya");

        std::system("id");

        std::system("uname -a");

        std::system("ps aux");

        std::system("prlimit");

        std::system("sudo ls -la");
        // execute target program

    }

    // this function must be invoked by forked process
    int execute_command_in_jail_entry( void* raw_args )
    {
        arguments_for_jail const* const args =
            static_cast<arguments_for_jail const*>( raw_args );

        fs::path const& host_container_dir
            = *args->p_host_container_dir;
        container_options const& opts
            = *args->p_opts;
        linux::user const& user
            = *args->p_user;
        int& comm = *args->comm;

        try {
            execute_command_in_jail( host_container_dir, opts, user );

        } catch( fs::filesystem_error const& e ) {
            // TODO: error handling
            comm = 100;

        } catch( std::exception const& e ) {
            comm = 200;

        } catch(...) {
            comm = 300;
        }

        // if reached to here, maybe error...
        std::exit( -1 );    // never call destructor of stack objects(Ex. anon_user)
    }

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

    // TODO: exception handling
    void run_in_container( container_options const& opts )
    {
        std::cout << "Host base dir: " << opts.host_containers_base_dir << std::endl;

        // make user
        auto const anon_user = make_anonymous_user();
        if ( anon_user == boost::none ) {
            std::cerr << "Failed to create user" << std::endl;
            return;
        }
        assert( anon_user->valid() );

        auto const host_container_dir = opts.host_containers_base_dir / anon_user->name();
        std::cout << "Host container dir: " << host_container_dir << std::endl;

        // after execution, reset environment
        BOOST_SCOPE_EXIT_ALL(&host_container_dir, &opts) {
            reset_jail_environment(
                opts.host_containers_base_dir,
                host_container_dir,
                opts.mount_points
                );
        };

        std::size_t const stack_for_child_size = opts.stack_size;
        auto stack_for_child = new std::uint8_t[stack_for_child_size];

        namespace ipc = boost::interprocess;

        try{
            ipc::mapped_region region( ipc::anonymous_shared_memory( 1000 ) );

            void* ptr = region.get_address();
            std::size_t s = 1000;
            auto p_shmem =
                std::align( alignof(int), sizeof(int), ptr, s );
            if ( p_shmem == nullptr ) {
                std::cerr << "Failed to get aligned memory" << std::endl;
                throw 10;
            }
            auto comm = static_cast<int*>( p_shmem );

            *comm = 0;

            //
            auto args = arguments_for_jail {
                &host_container_dir,
                &opts,
                &*anon_user,
                comm
            };
            // create the process that executes jailed command!
            pid_t const pid = ::clone(
                &execute_command_in_jail_entry,
                stack_for_child + stack_for_child_size,
                CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | SIGCHLD | CLONE_UNTRACED/* | CLONE_NEWUSER*/,
                &args
                );
            if ( pid == -1 ) {
                std::cerr << "Clone failed. errno=" << errno << " : " << std::strerror(errno) << std::endl;
                return;
            }

            // parent process
            std::cout << "parent process" << std::endl;

            std::promise<boost::optional<executed_result>> p;
            auto f = p.get_future();

            std::thread th(
                [pid]( std::promise<boost::optional<executed_result>> p ) {
                    int child_status;
                    ::rusage usage;

                    if ( ::wait4( pid, &child_status, 0, &usage ) == -1 ) {
                        std::cerr << "Failed to waitpid. errno=" << errno << " : " << std::strerror(errno) << std::endl;
                        p.set_value( boost::none );
                        return;
                    }

                    auto const user_time_micro_sec =
                        static_cast<double>( usage.ru_utime.tv_sec ) * 1000000.0 + static_cast<double>( usage.ru_utime.tv_usec );
                    auto const system_time_micro_sec =
                        static_cast<double>( usage.ru_stime.tv_sec ) * 1000000.0 + static_cast<double>( usage.ru_stime.tv_usec );

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
                },
                std::move( p )
                );

            // realtime checking apart from cgroup limits
            // prevent sleep() function running infinite
            auto const span = std::chrono::seconds{ opts.limits.cpu + 4 };   // +4 is extention...
            if ( f.wait_for( span ) == std::future_status::timeout ) {
                std::cout << "Timer timeout!" << std::endl;

                if ( ::kill( pid, SIGKILL ) == -1 ) {
                    std::cerr << "Failed to kill child. errno=" << errno << " : " << std::strerror(errno) << std::endl;
                }
            }

            // wait for result, blocking
            auto const child_result = f.get();
            th.join();

            std::cout << "waitpid finished" << std::endl;

            std::cout << "=====> " << *comm << std::endl;
            //
            if ( child_result ) {
                std::cout << "parent process: child finished / " << std::endl
                          << *child_result << std::endl;
            } else {
                std::cerr << "parent process: child finished :: failed to waitpid" << std::endl;
            }

        } catch( ipc::interprocess_exception const& ex ) {
            std::cerr << "ipc error: " << ex.what() << std::endl;
        }
    }


    void sig_handler(int signum)
    {
    }



    int execute( int argc, char* argv[] )
    {
/*
        if ( ::signal(SIGTERM, sig_handler) == SIG_ERR ) {
            printf("\ncan't catch SIGUSR1\n");
        }
*/
        // change process name
        char const process_name[_POSIX_PATH_MAX] = "d=(^o^)=b";
        std::copy( process_name, process_name + _POSIX_PATH_MAX, argv[0] );

        //
        auto const cwd = fs::current_path();
        auto const host_jail_base_dir = cwd / "containers_tmp";

        //
        auto const in_container_home_path = "/home/torigoya";
        auto home_mount_point = mount_point{
            cwd / "test" / "test_home",
            in_container_home_path,
            0700,
            false
        };

        //
        auto const limits = limits_values{
            0,
            512,
            30,
            1024,
            2,
            1 * 1024 * 1024 * 1024,
            2 * 1024 * 1024,
        };

        auto c_opts = container_options{
            host_jail_base_dir,

            in_container_home_path,
            { home_mount_point },
            limits,

            1 * 1024 * 1024     // stack size
        };

        try {
            run_in_container( c_opts );

        } catch(...) {
            // TODO: error handling
            std::cerr << "exception" << std::endl;
            return -1;
        }

        return 0;
    }
}


int main( int argc, char* argv[] )
{
    namespace po = boost::program_options;

    // Generic options
    po::options_description generic( "Generic options" );
    generic.add_options()
        ( "version,v", "print version string" )
        ( "help", "produce help message" )
        ;

    po::options_description hidden( "Hidden options" );
    hidden.add_options()
        ( "argv-in-container", po::value<std::vector<std::string>>(), "input file" )
        ;

    po::options_description cmdline_options;
    cmdline_options
        .add( generic )
        .add( hidden )
        ;

    po::positional_options_description p;
    p.add("argv-in-container", -1);

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

    } catch( std::exception const& e ) {
        std::cerr << "Exception: " << std::endl
                  << e.what() << std::endl;
        return -1;
    }

    return awaho::execute( argc, argv );
}
