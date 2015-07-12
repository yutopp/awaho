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

#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>

#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>

#include <sys/resource.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <chrono>
#include <thread>
#include <atomic>
#include <future>

#include "files.hpp"
#include "user.hpp"
#include "utility.hpp"

#include "ext/picojson.h"


namespace awaho
{
    namespace fs = boost::filesystem;
    namespace bio = boost::iostreams;
    namespace adap = boost::adaptors;

    struct mount_point
    {
        fs::path host_path;
        fs::path guest_path;

        bool is_readonly;
    };

    struct copy_point
    {
        fs::path host_path;
        fs::path guest_path;
    };

    struct limits_values_t
    {
        boost::optional<::rlim_t> core;     //
        boost::optional<::rlim_t> nofile;   // number
        boost::optional<::rlim_t> nproc;    // number
        boost::optional<::rlim_t> memlock;  // number
        boost::optional<::rlim_t> cputime;  // seconds
        boost::optional<::rlim_t> memory;   // bytes
        boost::optional<::rlim_t> fsize;    // bytes
    };

    struct pipe_redirect_t
    {
        int host_fd;
        int guest_fd;
    };

    struct container_options_t
    {
        fs::path host_containers_base_dir;

        fs::path in_container_start_path;       // Ex. "/home/some-user/"
        std::vector<mount_point> mount_points;
        std::vector<copy_point> copy_points;
        limits_values_t limits;

        std::size_t stack_size;
        std::vector<pipe_redirect_t> pipe_redirects;

        std::vector<std::string> commands;
        std::vector<std::string> envs;

        int result_output_fd;
        std::string result_output_type;
    };

    std::ostream& operator<<( std::ostream& os, container_options_t const& opts )
    {
        os << "container_options" << std::endl;
        os << "  host_containers_base_dir: " << opts.host_containers_base_dir << std::endl
           << "  in_container_start_path : " << opts.in_container_start_path << std::endl
            ;
        os << "  mounts: " << std::endl;
        for( auto&& im : opts.mount_points | boost::adaptors::indexed( 0 ) ) {
            os << "    " << im.index() << " ==" << std::endl;

            auto&& mp = im.value();
            os << "      HOST     : " << mp.host_path << std::endl
               << "      GUEST    : " << mp.guest_path << std::endl
               << "      READONLY : " << mp.is_readonly << std::endl
                ;
        }

        os << "  copies: " << std::endl;
        for( auto&& im : opts.copy_points | boost::adaptors::indexed( 0 ) ) {
            os << "    " << im.index() << " ==" << std::endl;

            auto&& cp = im.value();
            os << "      HOST     : " << cp.host_path << std::endl
               << "      GUEST    : " << cp.guest_path << std::endl
                ;
        }

        os << "  limits: " << std::endl;
        {
            auto const& lim = opts.limits;
            if ( lim.core ) {
                os << "    " << "core    : " << *lim.core << std::endl;
            }
            if ( lim.nofile ) {
                os << "    " << "nofile  : " << *lim.nofile << std::endl;
            }
            if ( lim.nproc ) {
                os << "    " << "nproc   : " << *lim.nproc << std::endl;
            }
            if ( lim.memlock ) {
                os << "    " << "memlock : " << *lim.memlock << std::endl;
            }
            if ( lim.cputime ) {
                os << "    " << "cputime : " << *lim.cputime << std::endl;
            }
            if ( lim.memory ) {
                os << "    " << "memory  : " << *lim.memory << std::endl;
            }
            if ( lim.fsize ) {
                os << "    " << "fsize   : " << *lim.fsize << std::endl;
            }
        }

        os << "  stack_size: " << opts.stack_size << std::endl;

        os << "  pipes: " << std::endl;
        for( auto&& im : opts.pipe_redirects | boost::adaptors::indexed( 0 ) ) {
            os << "    " << im.index() << " ==" << std::endl;

            auto&& pr = im.value();
            os << "      HOST FD  : " << pr.host_fd << std::endl
               << "      GUEST FD : " << pr.guest_fd << std::endl
                ;
        }

        os << "  commands: " << std::endl
           << "    " << boost::algorithm::join( opts.commands, ", " ) << std::endl;

        os << "  envs: " << std::endl;
        for( auto&& env : opts.envs ) {
            os << "    " << env << std::endl;
        }

        os << "  result_output_fd  : " << opts.result_output_fd << std::endl
           << "  result_output_type: " << opts.result_output_type << std::endl
            ;

        return os;
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
        make_symlink( guest_proc_dir / "self/fd/0", guest_dev_dir / "stdin" );
        make_symlink( guest_proc_dir / "self/fd/1", guest_dev_dir / "stdout" );
        make_symlink( guest_proc_dir / "self/fd/2", guest_dev_dir / "stderr" );
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

        // TODO: copy "copy_point" dir

        // mount system dirs
        for( auto const& host_ro_mount_point : HostReadonlyMountPoints ) {
            if ( !fs::exists( host_ro_mount_point ) ) {
                continue;
            }

            auto const in_container_mount_point = fs::path(".") / host_ro_mount_point;
            mount_directory_ro( host_ro_mount_point, in_container_mount_point );
        }

        // mount users dirs
        for( auto const& users_mp : mount_points ) {
            if ( !fs::exists( users_mp.host_path ) ) {
                std::stringstream ss;
                ss << "Failed: mount dir you specified is not found. "
                   << users_mp.host_path;
                throw std::runtime_error( ss.str() );
            }

            auto const in_container_mount_point = fs::path(".") / users_mp.guest_path;
            unsigned long mountflags = MS_BIND | MS_NOSUID | MS_NODEV;
            if ( users_mp.is_readonly ) {
                mountflags |= MS_RDONLY;
            }

            mount_directory(
                users_mp.host_path,
                in_container_mount_point,
                nullptr,
                mountflags
                );
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
        try {
            fs::current_path( host_container_dir );

        } catch( fs::filesystem_error const& e ) {
            std::cerr << "Exception[reset_jail_environment]: "
                      << e.what() << std::endl;
            return;
        }

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

        // TODO: copy "copy_point" dir

        //
        try {
            fs::current_path( host_jail_base_path );
            remove_container_directory( host_container_dir );

        } catch( fs::filesystem_error const& e ) {
            std::cerr << "Exception[reset_jail_environment/last]: "
                      << e.what() << std::endl;
            return;
        }
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
        /*
        std::this_thread::sleep_for(std::chrono::seconds(4));

        std::cout << " SLEEP =============" << std::endl;
        return;
        */

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

        std::system("ls -la /proc/self/fd");

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

        // ===
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

        //
        std::system("pwd");
        std::system("ls -la");

        // std::system("rm /etc/yutopp_test.txt");

        // std::this_thread::sleep_for(std::chrono::seconds(4));

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

        std::system("touch bo.txt");

        std::system("ln -s /proc proc");
        std::system("ln /lib/yutopp.lib beautiful_something");

        // execute target program!
        auto const& filename = opts.commands.at( 0 );

        auto argv_pack = make_buffer_for_execve( opts.commands );
        auto& argv = std::get<0>( argv_pack );

        auto envp_pack = make_buffer_for_execve( opts.envs );
        auto& envp = std::get<0>( envp_pack );

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

    // this function must be invoked by forked process
    int execute_command_in_jail_entry( void* raw_args )
    {
        arguments_for_jail const* const args =
            static_cast<arguments_for_jail const*>( raw_args );

        fs::path const& host_container_dir
            = *args->p_host_container_dir;
        container_options_t const& opts
            = *args->p_opts;
        linux::user const& user
            = *args->p_user;
        comm_info_t& comm_info = *args->comm_info;

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
    void run_in_container( container_options_t const& opts )
    {
        std::cout << "Host base dir: " << opts.host_containers_base_dir << std::endl;

        expect_root();

        // make the special pipe close when exec
        if ( opts.result_output_fd > 2 ) {
            if ( ::fcntl( opts.result_output_fd, F_SETFD, FD_CLOEXEC ) == -1 ) {
                // throw
            }
        }

        // make user
        auto const anon_user = make_anonymous_user();
        if ( anon_user == boost::none ) {
            std::cerr << "Failed to create user" << std::endl;
            // throw
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
            constexpr auto CommBufferSize = 2048;

            // create shared buffer (comm_info)
            ipc::mapped_region region( ipc::anonymous_shared_memory( CommBufferSize ) );
            void* const ptr = region.get_address();
            auto const offset =
                alignof(comm_info_t) - ( reinterpret_cast<std::uintptr_t>( ptr ) % alignof(comm_info_t) );
            auto const free_size = CommBufferSize - offset;
            if ( free_size < sizeof(comm_info_t) ) {
                // throw
            }

            void* aligned_ptr = static_cast<void*>( static_cast<char*>( ptr ) + offset );
            auto comm_info_p = new(aligned_ptr) comm_info_t{};  // value initialize

            //
            auto args = arguments_for_jail {
                &host_container_dir,
                &opts,
                &*anon_user,
                comm_info_p
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
                },
                std::move( p )
                );


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
                    }
                }
            }

            // wait for result, blocking
            auto const child_result = f.get();
            th.join();

            std::cout << "waitpid finished" << std::endl;

            //
            if ( child_result ) {
                std::cout << "parent process: child finished / " << std::endl
                          << *child_result << std::endl;

                auto const close_flag = ( opts.result_output_fd > 2 )
                    ? bio::file_descriptor_flags::close_handle
                    : bio::file_descriptor_flags::never_close_handle
                    ;
                bio::stream<bio::file_descriptor_sink> ofs( opts.result_output_fd, close_flag );
                if ( !ofs ) {
                    std::cerr << "parent process: child finished :: failed to create result" << std::endl;
                }

                if ( opts.result_output_type == "json" ) {
                    picojson::value::object obj{
                        { "exited", picojson::value( child_result->exited ) },
                        { "exitStatus", picojson::value( static_cast<double>( child_result->exit_status ) ) },
                        { "signaled", picojson::value( child_result->signaled ) },
                        { "signal", picojson::value( static_cast<double>( child_result->signal ) ) },

                        { "userTimeMicroSec", picojson::value( child_result->user_time_micro_sec ) },
                        { "systemTimeMicroSec", picojson::value( child_result->system_time_micro_sec ) },
                        { "cpuTimeMicroSec", picojson::value( child_result->cpu_time_micro_sec ) },
                        { "usedMemoryBytes", picojson::value( static_cast<double>( child_result->used_memory_bytes ) ) },
                    };
                    picojson::value root( obj );

                    root.serialize( std::ostream_iterator<char>( ofs ) );

                } else {
                    std::cerr << "Error: type " << opts.result_output_type << " is not supported" << std::endl;

                }

            } else {
                std::cerr << "parent process: child finished :: failed to waitpid" << std::endl;
            }

            // comm check
            std::cout << std::endl
                      << "comm: " << comm_info_p->error_status << std::endl
                      << "mes : " << comm_info_p->message << std::endl;



        } catch( ipc::interprocess_exception const& ex ) {
            std::cerr << "ipc error: " << ex.what() << std::endl;
        }
    }


    void sig_handler(
        boost::system::error_code const& error,
        int signal_number
        )
    {
        std::cout << "!!!!! sig hand: " << signal_number << std::endl;
    }

    int execute( container_options_t const& opts ) noexcept
    try {
        boost::asio::io_service io_service;
        boost::asio::signal_set signals( io_service, SIGINT, SIGTERM );
        signals.async_wait( sig_handler );

        std::cout << opts << std::endl;
        run_in_container( opts );

        return 0;

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
            c_opts.commands =
                vm["argv-in-container"].as<std::vector<std::string>>();
        }

        if ( vm.count( "env" ) ) {
            c_opts.envs =
                vm["env"].as<std::vector<std::string>>();
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
