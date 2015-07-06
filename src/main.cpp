#include <iostream>
#include <memory>
#include <array>
#include <unistd.h>
#include <cstdlib>

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <errno.h>
#include <cstring>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include <sys/mount.h>
#include <boost/scope_exit.hpp>
#include <boost/optional.hpp>
#include <boost/lexical_cast.hpp>

#include <boost/algorithm/string.hpp>

#include <sstream>

#include <random>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <chrono>
#include <thread>
#include <atomic>
#include <future>

namespace awaho
{
    namespace linux
    {
        auto simple_exec( std::string const& command ) noexcept
            -> boost::optional<std::string>
        {
            FILE* const fp = ::popen( command.c_str(), "r" );
            if ( fp == nullptr ) {
                return boost::none;
            }

            BOOST_SCOPE_EXIT_ALL(&fp) {
                pclose(fp);
            };

            try {
                std::stringstream ss;
                constexpr auto BufferSize = 128;
                char buffer[BufferSize];

                while( !::feof( fp ) ) {
                    if ( ::fgets( buffer, BufferSize, fp ) != nullptr ) {
                        ss << buffer;
                    }
                }

                return ss.str();

            } catch( std::exception const& e ) {
                // TODO: I want to use "std::expected"...
                return boost::none;
            }
        }

        class user
        {
        public:
            // name will NOT be escaped. be careful
            user( std::string const& name ) noexcept
                : name_( name )
                , is_valid_( false )
                , is_user_created_( false )
            {
                auto const stat = std::system( ("useradd --no-create-home " + name_).c_str() );
                if ( stat != 0 ) {
                    // return;
                }
                is_user_created_ = true;

                auto const user_id_s = simple_exec( "id --user " + name_ );
                if ( !user_id_s ) {
                    return;
                }

                auto const group_id_s = simple_exec( "id --group " + name_ );
                if ( !group_id_s ) {
                    return;
                }

                try {
                    user_id_ = boost::lexical_cast<int>( boost::trim_copy( *user_id_s ) );
                    group_id_ = boost::lexical_cast<int>( boost::trim_copy( *group_id_s ) );
                    is_valid_ = true;

                } catch(...) {
                    // TODO: ...

                }
            }

            user( user const& ) = delete;
            user( user&& ) = default;

            ~user()
            {
                if ( is_user_created_ ) {
                    auto const stat = std::system( ("userdel " + name_).c_str() );
                    std::cout << "delete stat: " << stat << std::endl;
                }
            }

            auto vaild() const
                -> bool
            {
                return is_valid_;
            }

        private:
            std::string name_;

            bool is_valid_;
            bool is_user_created_;

            int user_id_, group_id_;
        };

        //

    }

    auto make_random_name()
            -> std::string
    {
        static char const BaseChars[] = "abcdefghijklmnopqrstuvwxyz1234567890";

        auto gen = std::mt19937( std::random_device{}() );
        auto dist = std::uniform_int_distribution<int>{
            0,
            sizeof(BaseChars) / sizeof(char) - 1 /*term*/ -1 /*closed-interval*/
        };

        constexpr auto MaxNameLength = 28;
        char random_chars[MaxNameLength+1] = {};
        for( int i=0; i<MaxNameLength; ++i ) {
            auto const index = dist(gen);
            random_chars[i] = BaseChars[index];
        }

        return std::string("_") + random_chars;
    }

    auto make_random_user()
        -> boost::optional<linux::user>
    {
        // retry 5 times
        for( int i=0; i<5; ++i ) {
            linux::user u(make_random_name());
            if ( u.vaild() ) {
                return u;
            }
        }

        return boost::none;
    }

    namespace fs = boost::filesystem;

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

    bool mount_directory(
        fs::path const& host_mount_point,
        fs::path const& guest_mount_point
        )
    {
        // TODO: add timeout
        // TODO: check permission

        std::cout << "Mounting: " << host_mount_point << " to " << guest_mount_point << std::endl;

        //
        fs::create_directories(guest_mount_point);

        //
        if ( ::mount(
                 host_mount_point.c_str(),
                 guest_mount_point.c_str(),
                 nullptr,   // MS_BIND ignores this option
                 MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV,
                 nullptr    // there is no data
                 ) != 0 ) {
            std::cerr << "Failed to mount: " << guest_mount_point << " errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return false;
        }

        return true;
    }

    bool mount_procfs(
        fs::path const& guest_mount_point
        )
    {
        // TODO: add timeout
        // TODO: check permission
        std::cout << "Mounting: " << "proc" << " to " << guest_mount_point << std::endl;

        //
        fs::create_directories(guest_mount_point);

        //
        if ( ::mount(
                 "proc",
                 guest_mount_point.c_str(),
                 "proc",
                 MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV,
                 nullptr    // there is no data
                 ) != 0 ) {
            std::cerr << "Failed to mount: " << guest_mount_point << " errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return false;
        }

        return true;
    }

    bool mount_tmpfs(
        fs::path const& guest_mount_point
        )
    {
        // TODO: add timeout
        // TODO: check permission

        std::cout << "Mounting: " << "/tmp" << " to " << guest_mount_point << std::endl;

        //
        fs::create_directories(guest_mount_point);

        //
        if ( ::mount(
                 "",
                 guest_mount_point.c_str(),
                 "tmpfs",
                 MS_NOEXEC | MS_NODEV,
                 nullptr    // there is no data
                 ) != 0 ) {
            std::cerr << "Failed to mount: " << guest_mount_point << " errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return false;
        }

        return true;
    }

    bool umount_directory(
        fs::path const& guest_mount_point
        )
    {
        std::cout << "Un mounting: " << guest_mount_point << std::endl;

        if ( ::umount2(
                 guest_mount_point.c_str(),
                 MNT_DETACH | UMOUNT_NOFOLLOW
                 ) != 0 ) {
            std::cerr << "Failed to umount: " << guest_mount_point << " errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return false;
        }

        return true;
    }

    // TODO: exception handling
    bool remove_node(
        fs::path const& guest_node_path
        )
    {
        fs::remove( guest_node_path );

        return true;
    }

    bool make_node(
        fs::path const& guest_node_path,
        dev_t const& dev,
        mode_t const& perm
        )
    {
        if ( fs::exists( guest_node_path ) ) {
            if ( !remove_node( guest_node_path ) ) {
                return false;
            }
        }

        if ( ::mknod( guest_node_path.c_str(), S_IFCHR, dev ) != 0 ) {
            std::cerr << "Failed to mknod: " << guest_node_path << " errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return false;
        }

        if ( ::chmod( guest_node_path.c_str(), perm ) != 0 ) {
            std::cerr << "Failed to chmod: " << guest_node_path << " errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return false;
        }

        return true;
    }

    static std::tuple<char const*, ::dev_t, ::mode_t> const StandardNodes[] = {
        std::make_tuple( "null", ::makedev( 1, 3 ), 0666 ),
        std::make_tuple( "zero", ::makedev( 1, 5 ), 0666 ),
        std::make_tuple( "full", ::makedev( 1, 7 ), 0666 ),
        std::make_tuple( "random", ::makedev( 1, 8 ), 0644 ),
        std::make_tuple( "urandom", ::makedev( 1, 9 ), 0644 )
    };

    bool make_standard_nodes(
        fs::path const& guest_mount_point
        )
    {
        // TODO: add timeout
        // TODO: check permission
        std::cout << "Createing: " << "/dev" << " to " << guest_mount_point << std::endl;

        //
        fs::create_directories(guest_mount_point);

        //
        for( auto const& n : StandardNodes ) {
            if ( !make_node( guest_mount_point / std::get<0>( n ), std::get<1>( n ), std::get<2>( n ) ) ) {
                return false;
            }
        }

        return true;
    }

    bool remove_standard_nodes(
        fs::path const& guest_mount_point
        )
    {
        using namespace boost::adaptors;

        //
        for( auto const& n : StandardNodes | reversed ) {
            // TODO: error check
            fs::remove( guest_mount_point / std::get<0>( n ) );
        }

        return true;
    }

    bool remove_symlink(
        fs::path const& dest
        )
    {
        if ( ::unlink( dest.c_str() ) != 0 ) {
            std::cerr << "Failed to unlink: " << dest << " errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return false;
        }

        return true;
    }

    bool make_symlink(
        fs::path const& src,
        fs::path const& dest
        )
    {
        if ( fs::exists( dest ) ) {
            if ( !remove_symlink( dest ) ) {
                return false;
            }
        }

        if ( ::symlink( src.c_str(), dest.c_str() ) != 0 ) {
            std::cerr << "Failed to symlink: " << dest << " -> " << src << " errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return false;
        }

        return true;
    }


    bool link_io(
        fs::path const& guest_proc_dir,
        fs::path const& guest_dev_dir
        )
    {
        if ( !make_symlink( guest_proc_dir / "self" / "fd" / "0", guest_dev_dir / "stdin" ) ) {
            return false;
        }

        if ( !make_symlink( guest_proc_dir / "self" / "fd" / "1", guest_dev_dir / "stdout" ) ) {
            return false;
        }

        if ( !make_symlink( guest_proc_dir / "self" / "fd" / "2", guest_dev_dir / "stderr" ) ) {
            return false;
        }

        return true;
    }

    bool unlink_io(
        fs::path const& guest_dev_dir
        )
    {
        if ( !remove_symlink( guest_dev_dir / "stderr" ) ) {
            return false;
        }

        if ( !remove_symlink( guest_dev_dir / "stdout" ) ) {
            return false;
        }

        if ( !remove_symlink( guest_dev_dir / "stdin" ) ) {
            return false;
        }

        return true;
    }

    void make_jail_environment(
        fs::path const& host_jail_base_path
        )
    {
        // important
        fs::current_path(host_jail_base_path);

        // mount system dirs
        for( auto const& host_ro_mount_point : HostReadonlyMountPoints ) {
            if ( !fs::exists( host_ro_mount_point ) ) {
                continue;
            }

            auto const in_container_mount_point = fs::path(".") / host_ro_mount_point;
            mount_directory(host_ro_mount_point, in_container_mount_point);
        }

        auto const guest_proc_path = fs::path( "./proc" );
        auto const guest_dev_path = fs::path( "./dev" );

        //
        mount_procfs( guest_proc_path );
        mount_tmpfs( fs::path("./tmp") );

        //
        make_standard_nodes( guest_dev_path );

        //
        link_io( guest_proc_path, guest_dev_path );
    }

    void reset_jail_environment(
        fs::path const& host_jail_base_path
        )
    {
        using namespace boost::adaptors;

        // important
        fs::current_path(host_jail_base_path);

        auto const guest_proc_path = fs::path( "./proc" );
        auto const guest_dev_path = fs::path( "./dev" );

        //
        unlink_io( guest_dev_path );

        //
        remove_standard_nodes( guest_dev_path );

        //
        umount_directory( fs::path("./tmp") );
        umount_directory( guest_proc_path );

        //
        for( auto const& host_ro_mount_point : HostReadonlyMountPoints | reversed ) {
            auto const in_container_mount_point = fs::path(".") / host_ro_mount_point;

            if ( !fs::exists( in_container_mount_point ) ) {
                continue;
            }

            umount_directory(in_container_mount_point);
        }
    }



    bool set_limit( int resource, rlim_t lim_soft, rlim_t lim_hard )
    {
        assert( lim_hard >= lim_soft);

        auto limits = ::rlimit{ lim_soft, lim_hard };
        if ( ::setrlimit( resource, &limits ) == -1 ) {
            return false;
        }

        return true;
    }

    bool set_limit( int resource, rlim_t lim )
    {
        return set_limit( resource, lim, lim );
    }

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

    // this function must be invoked by forked process
    void execute_command_in_jail(
        fs::path const& host_jail_base_path,
        limits_values const& limits
        )
    {
        // in jail
        if ( ::chroot( host_jail_base_path.c_str() ) == -1 ) {
            std::cerr << "Failed to chroot. errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return;
        }

        // set limits
        set_limit( RLIMIT_CORE, limits.core );
        set_limit( RLIMIT_NOFILE, limits.nofile );
        set_limit( RLIMIT_NPROC, limits.nproc );
        set_limit( RLIMIT_MEMLOCK, limits.memlock );
        set_limit( RLIMIT_CPU, limits.cpu + 1, limits.cpu + 3 );    // CPU can be used only cpu_limit_time(sec)
        set_limit( RLIMIT_AS, limits.memory );                      // Memory can be used only memory_limit_bytes [be careful!]
        set_limit( RLIMIT_FSIZE, limits.fsize );

        // set umask

        // change user



        std::system("ls -la");

        std::system("ls -la ../");

        std::system("ls -la /dev");

        std::system("id");

        std::system("uname -a");

        std::system("ps aux");

        std::system("prlimit");

        // execute target program

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
    void build_chroot_env()
    {
        auto const tt = fs::current_path();
        auto const host_jail_base_path = tt / "temp";

        std::cout << "Host base: " << host_jail_base_path << std::endl;

        BOOST_SCOPE_EXIT_ALL(&host_jail_base_path) {
            reset_jail_environment(host_jail_base_path);
        };
        try {
            make_jail_environment(host_jail_base_path);
        } catch(...) {
            return;
        }


        // set limits
        auto const limits = limits_values{
            0,
            512,
            30,
            1024,
            2,
            1 * 1024 * 1024 * 1024,
            2 * 1024 * 1024,
        };

        auto const pid = ::fork();
        if ( pid < 0 ) {
            std::cerr << "failed to fork" << std::endl;
        }
        if ( pid == 0 ) {
            // child process
            std::cout << "child process" << std::endl;

            execute_command_in_jail( host_jail_base_path, limits );

            // std::this_thread::sleep_for(std::chrono::seconds(40));

            std::exit(2);

        } else {
            // parent process
            std::cout << "parent process" << std::endl;

            std::promise<boost::optional<executed_result>> p;
            auto f = p.get_future();

            std::thread th( [pid]( std::promise<boost::optional<executed_result>> p ) {
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

            auto const span = std::chrono::seconds{ limits.cpu + 4 };   //
            if ( f.wait_for( span ) == std::future_status::timeout ) {
                std::cout << "Timer timeout!" << std::endl;

                if ( ::kill( pid, SIGKILL ) == -1 ) {
                    std::cerr << "Failed to kill child. errno=" << errno << " : " << std::strerror(errno) << std::endl;
                }
            }

            auto const child_result = f.get();
            th.join();

            std::cout << "waitpid finished" << std::endl;

            //
            if ( child_result ) {
                std::cout << "parent process: child finished / " << std::endl
                          << *child_result << std::endl;
            } else {
                std::cerr << "parent process: child finished :: failed to waitpid" << std::endl;
            }
        }
    }


    void sig_handler(int signum)
    {
    }

    int new_entry(void* args)
    {
        if ( ::signal(SIGTERM, sig_handler) == SIG_ERR ) {
            printf("\ncan't catch SIGUSR1\n");
        }


        build_chroot_env();


        return 0;
    }

    int unshare_resource()
    {
        // stack size: 1MiB
        std::size_t const stack_for_child_size = 1 * 1024 * 1024;
        std::array<std::uint8_t, stack_for_child_size> stack_for_child = {};

        //
        pid_t const child_pid = ::clone(
            &new_entry,
            stack_for_child.data() + stack_for_child.size(),
            CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | SIGCHLD | CLONE_UNTRACED/* | CLONE_NEWUSER*/,
            nullptr
            );
        if ( child_pid == -1 ) {
            std::cerr << "Clone failed. errno=" << errno << " : " << std::strerror(errno) << std::endl;
            return -1;
        }

        //
        int status;
        if ( ::waitpid( child_pid, &status, 0 ) == -1 ) {
            std::cerr << "waitpid failed" << std::endl;
            return -1;
        }

        std::cout << "%%%%%%%%%% SANDBOX: exit status code: " << status << std::endl;
        if ( status == 0 ) {
            return 0;

        } else {
            return -1;
        }
    }
}


int main()
{
    awaho::unshare_resource();
}
