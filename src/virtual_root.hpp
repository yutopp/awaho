//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <iostream>
#include <memory>
#include <cstdlib>
#include <string>
#include <algorithm>
#include <iterator>

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>

#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include <sys/resource.h>
#include <sys/stat.h>

#include "file_manip.hpp"
#include "user.hpp"
#include "utility.hpp"

#include "container_options.hpp"


namespace awaho
{
    namespace fs = boost::filesystem;
    namespace adap = boost::adaptors;

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

            if ( fs::is_symlink( p ) ) {
                // TODO: unlink
                std::cout << "Not implemented: unlink " << p << std::endl;

            } else if ( fs::is_directory( p ) ) {
                remove_container_directory( p, rm_f );

            } else if ( fs::is_regular_file( p ) ) {
                // TODO: remove
                std::cout << "Not implemented: rm " << p << std::endl;
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
        bool result = true;

        for( auto const& n : StandardNodes | adap::reversed ) {
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

    template<typename MountPoints, typename CopyPoints>
    void construct_virtual_root(
        fs::path const& host_container_dir,
        MountPoints const& mount_points,
        CopyPoints const& copy_points,
        linux::user const& user
        )
    {
        std::cerr << "[+] Constructing virtual root for container (host: "
                  << host_container_dir << ")"<< std::endl;

        // create container dir
        fs::create_directories( host_container_dir );

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
            if ( !users_mp.do_chown ) {
                change_directory_owner_rec( in_container_mount_point, user );
            }
        }

        //
        mount_procfs( guest_proc_path );
        mount_tmpfs( guest_tmp_path );

        // copy user's dirs
        for( auto const& users_cp : copy_points ) {
            if ( !fs::exists( users_cp.host_path ) ) {
                std::stringstream ss;
                ss << "Failed: copy file you specified is not found. "
                   << users_cp.host_path;
                throw std::runtime_error( ss.str() );
            }

            auto const in_container_copy_point = fs::path(".") / users_cp.guest_path;
            copy_user_files(
                users_cp.host_path,
                in_container_copy_point
                );
            change_directory_owner_rec( in_container_copy_point, user );
        }

        //
        make_standard_nodes( guest_dev_path, fs::perms( 0555 ) );

        //
        link_io( guest_proc_path, guest_dev_path );
    }

    template<typename MountPoints, typename CopyPoints>
    void destruct_virtual_root(
        fs::path const& host_jail_base_path,
        fs::path const& host_container_dir,
        MountPoints const& mount_points,
        CopyPoints const& copy_points
        )
    {
        boost::system::error_code ec;

        // important
        try {
            fs::current_path( host_container_dir );

        } catch( fs::filesystem_error const& e ) {
            std::cerr << "Exception[destruct_virtual_root]: "
                      << e.what() << std::endl;
            return;
        }

        //
        unlink_io( guest_dev_path );

        //
        remove_standard_nodes( guest_dev_path );

        // remove "copy_point" dir
        for( auto const& users_cp : copy_points ) {
            auto const in_container_copy_point = fs::path(".") / users_cp.guest_path;

            if ( !fs::exists( in_container_copy_point, ec ) ) {
                continue;
            }

            remove_user_files( in_container_copy_point );
        }

        //
        cleanup_directory( guest_tmp_path );
        cleanup_directory( guest_proc_path );

        //
        for( auto const& users_mp : mount_points | adap::reversed ) {
            auto const in_container_mount_point = fs::path(".") / users_mp.guest_path;

            if ( !fs::exists( in_container_mount_point, ec ) ) {
                continue;
            }

            cleanup_directory( in_container_mount_point );
        }

        //
        for( auto const& host_ro_mount_point : HostReadonlyMountPoints | adap::reversed ) {
            auto const in_container_mount_point = fs::path(".") / host_ro_mount_point;

            if ( !fs::exists( in_container_mount_point, ec ) ) {
                continue;
            }

            cleanup_directory( in_container_mount_point );
        }

        //
        try {
            fs::current_path( host_jail_base_path );
            remove_container_directory( host_container_dir );

        } catch( fs::filesystem_error const& e ) {
            std::cerr << "Exception[destruct_virtual_root/last]: "
                      << e.what() << std::endl;
            return;
        }
    }

} // namespace awaho
