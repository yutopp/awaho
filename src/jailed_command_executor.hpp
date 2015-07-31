//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <iostream>
#include <sstream>
#include <errno.h>
#include <cstring>
#include <exception>

#include <sys/types.h>
#include <unistd.h>

#include <boost/filesystem/path.hpp>

#include <sys/resource.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "rlimit.hpp"
#include "virtual_root.hpp"
#include "container_options.hpp"
#include "user.hpp"
#include "utility.hpp"


namespace awaho
{
    namespace fs = boost::filesystem;

    // this function must be invoked by forked process
    void execute_command_in_jail(
        fs::path const& host_container_dir,
        container_options_t const& opts,
        linux::user const& user
        )
    {
        // create virtual root for container
        construct_virtual_root(
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
        set_limits( opts.limits );
        set_limit( RLIMIT_STACK, opts.stack_size );

        // log
        std::cout << "[+] chrooted and resource limited!" << std::endl;

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

        // overwrite host $PATH environment, to search an executable by execpve
        overwrite_path( opts.envs );

        auto const& filename = opts.commands[0];

        auto argv_pack = make_buffer_for_execve( opts.commands );
        auto& argv = std::get<0>( argv_pack );

        auto envp_pack = make_buffer_for_execve( opts.envs );
        auto& envp = std::get<0>( envp_pack );

        // replace self process
        if ( ::execvpe( filename.c_str(), argv.data(), envp.data() ) == -1 ) {
            std::stringstream ss;
            ss << "Failed to execve: "
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }
    }

    template<typename CommInfo>
    void execute_command_in_jail_entry(
        fs::path const& host_container_dir,
        container_options_t const& opts,
        linux::user const& user,
        CommInfo& comm_info
        )
    try {
        execute_command_in_jail( host_container_dir, opts, user );
        // after this, stdio should not be used, because they may be redirected

    } catch( fs::filesystem_error const& e ) {
        // TODO: error handling
        comm_info.error_status = 100;
        std::strncpy( comm_info.message, e.what(), CommInfo::BufferLength - 1 );

    } catch( std::exception const& e ) {
        comm_info.error_status = 200;
        std::strncpy( comm_info.message, e.what(), CommInfo::BufferLength - 1 );

    } catch(...) {
        comm_info.error_status = 300;
        std::strncpy(
            comm_info.message,
            "Unexpected exception[execute_command_in_jail_entry]",
            CommInfo::BufferLength - 1
            );
    }

} // namespace awaho
