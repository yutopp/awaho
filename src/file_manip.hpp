//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <sstream>

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <boost/filesystem.hpp>

#include "linux_user.hpp"


namespace awaho
{
    namespace fs = boost::filesystem;

    void mount(
        fs::path const& host_mount_point,
        fs::path const& guest_mount_point,
        char const* const filesystemtype,
        unsigned long const mountflags
        )
    {
        // TODO: add timeout
        std::cout << "Mounting: " << host_mount_point << " to " << guest_mount_point << std::endl;

        fs::create_directories( guest_mount_point );    // throw exception if failed

        //
        if ( ::mount(
                 host_mount_point.c_str(),
                 guest_mount_point.c_str(),
                 filesystemtype,
                 mountflags,
                 nullptr    // there is no data
                 ) == -1 ) {
            std::stringstream ss;
            ss << "Failed to mount: " << guest_mount_point
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }
    }

    void mount_directory(
        fs::path const& host_mount_point,
        fs::path const& guest_mount_point,
        char const* const filesystemtype,
        unsigned long const mountflags
        )
    {
        if ( !host_mount_point.is_absolute() ) {
            std::stringstream ss;
            ss << "Failed to mount: "
               << host_mount_point << " must be ablosute path";
            throw std::runtime_error( ss.str() );
        }

        if ( !fs::is_directory( host_mount_point ) ) {
            std::stringstream ss;
            ss << "Failed to mount: "
               << host_mount_point << " is not directory";
            throw std::runtime_error( ss.str() );
        }

        //
        if ( fs::exists( guest_mount_point ) ) {
            std::stringstream ss;
            ss << "Failed to mount: GUEST "
               << guest_mount_point << " is already exists";
            throw std::runtime_error( ss.str() );
        }

        mount( host_mount_point, guest_mount_point, filesystemtype, mountflags );
    }

    // throw exception if failed
    void mount_directory_ro(
        fs::path const& host_mount_point,
        fs::path const& guest_mount_point
        )
    {
        mount_directory(
            host_mount_point,
            guest_mount_point,
            nullptr,    // MS_BIND ignores this option
            MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV
            );
    }

    void mount_procfs( fs::path const& guest_mount_point )
    {
        mount(
            "proc",
            guest_mount_point,
            "proc",
            MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV
            );
    }

    void mount_tmpfs( fs::path const& guest_mount_point )
    {
        mount(
            "",
            guest_mount_point,
            "tmpfs",
            MS_NOEXEC | MS_NODEV
            );
    }

    bool umount_directory(
        fs::path const& guest_mount_point
        ) noexcept
    {
        std::cout << "Un mounting: " << guest_mount_point << std::endl;

        if ( ::umount2(
                 guest_mount_point.c_str(),
                 MNT_DETACH | UMOUNT_NOFOLLOW
                 ) != 0 ) {
            std::cerr << "Failed to umount: " << guest_mount_point << " errno=" << errno << " : " << std::strerror( errno ) << std::endl;
            return false;
        }

        return true;
    }


    // return number of files include in THIS directory(not recursive).
    // throws: exception
    auto number_of_files(
        fs::path const& dir
        )
        -> std::size_t
    {
        return std::distance(
            fs::directory_iterator( dir ),
            fs::directory_iterator()
            );
    }


    //
    bool remove_directory_if_empty(
        fs::path const& guest_mount_point
        ) noexcept
    {
        std::cout << "Removing: " << guest_mount_point << std::endl;
        if ( !fs::exists( guest_mount_point ) ) {
            return false;
        }

        try {
            auto const count = number_of_files( guest_mount_point );
            if ( count != 0 ) {
                std::cerr << "Failed to remove: " << guest_mount_point << " There are some files (num = " << count << ") " << std::endl;

                return false;
            }

            fs::remove_all( guest_mount_point );

            return true;

        } catch(...) {
            // TODO: error handling
            return false;
        }
    }


    bool cleanup_directory(
        fs::path const& guest_mount_point
        ) noexcept
    {
        auto const f = umount_directory( guest_mount_point );
        auto const s = remove_directory_if_empty( guest_mount_point );

        return f && s;
    }


    void change_file_owner(
        fs::path const& guest_path,
        linux::user const& user
        )
    {
        std::cout << "Chown: " << guest_path << std::endl;

        if ( ::chown( guest_path.c_str(), user.user_id(), user.group_id() ) != 0 ) {
            std::stringstream ss;
            ss << "Failed to chown."
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }
    }

    void change_directory_owner_rec(
        fs::path const& guest_dir,
        linux::user const& user
        )
    {
        if ( !fs::is_directory( guest_dir ) || fs::is_symlink( guest_dir ) ) {
            return change_file_owner( guest_dir, user );
        }

        auto const begin = fs::directory_iterator( guest_dir );
        auto const end = fs::directory_iterator();

        change_file_owner( guest_dir, user );

        for( auto&& it : boost::make_iterator_range( begin, end ) ) {
            auto const& p = it.path();

            if ( fs::is_directory( p ) && !fs::is_symlink( p ) ) {
                change_directory_owner_rec( p, user );
            } else {
                change_file_owner( p, user );
            }
        }
    }


    bool remove_node(
        fs::path const& guest_node_path
        ) noexcept
    {
        try {
            std::cout << "Removing node: " << guest_node_path << std::endl;

            fs::remove( guest_node_path );

        } catch( fs::filesystem_error const& e ) {
            std::cerr << "Failed to remove_node: "
                      << e.what() << std::endl;
            return false;

        } catch(...) {
            std::cerr << "Failed to remove_node: "
                      << "unexpected" << std::endl;
            return false;
        }

        return true;
    }

    bool remove_file(
        fs::path const& guest_file_path
        ) noexcept
    {
        try {
            std::cout << "Removing file: " << guest_file_path << std::endl;

            fs::remove( guest_file_path );

        } catch( fs::filesystem_error const& e ) {
            std::cerr << "Failed to remove_file: " << guest_file_path
                      << " / reason: " << e.what() << std::endl;
            return false;

        } catch(...) {
            std::cerr << "Failed to remove_file: " << guest_file_path
                      << " / unexpected" << std::endl;
            return false;
        }

        return true;
    }

    void make_node(
        fs::path const& guest_node_path,
        dev_t const& dev,
        mode_t const& perm
        )
    {
        std::cout << "Creating node: " << guest_node_path << std::endl;

        if ( fs::exists( guest_node_path ) ) {
            if ( !remove_node( guest_node_path ) ) {
                std::stringstream ss;
                ss << "Failed to make_node: "
                   << " " << guest_node_path << " is already exists and couldn't remove.";
                throw std::runtime_error( ss.str() );
            }
        }

        if ( ::mknod( guest_node_path.c_str(), S_IFCHR, dev ) != 0 ) {
            std::stringstream ss;
            ss << "Failed to mknod: " << guest_node_path
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }

        if ( ::chmod( guest_node_path.c_str(), perm ) != 0 ) {
            std::stringstream ss;
            ss << "Failed to chmod: " << guest_node_path
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }
    }


    bool remove_symlink(
        fs::path const& dest
        ) noexcept
    {
        if ( ::unlink( dest.c_str() ) != 0 ) {
            std::cerr << "Failed to unlink: " << dest
                      << " errno=" << errno << " : " << std::strerror( errno ) << std::endl;
            return false;
        }

        return true;
    }

    void make_symlink(
        fs::path const& src,
        fs::path const& dest
        )
    {
        if ( fs::exists( dest ) ) {
            if ( !remove_symlink( dest ) ) {
                std::stringstream ss;
                ss << "Failed to make_symlink: "
                   << " " << dest << " is already exists and couldn't remove.";
                throw std::runtime_error( ss.str() );
            }
        }

        if ( ::symlink( src.c_str(), dest.c_str() ) != 0 ) {
            std::stringstream ss;
            ss << "Failed to symlink: " << dest << " -> " << src
               << " errno=" << errno << " : " << std::strerror( errno );
            throw std::runtime_error( ss.str() );
        }
    }


    void copy_user_files(
        fs::path const& host_copy_point,
        fs::path const& guest_copy_point
        )
    {
        // TODO: add timeout
        std::cout << "Cp(userfile): " << host_copy_point << " to " << guest_copy_point
                  << " / is dir: " << fs::is_directory( host_copy_point )
                  << " / is sym: " << fs::is_symlink( host_copy_point ) << std::endl;

        //
        if ( fs::exists( guest_copy_point ) ) {
            std::stringstream ss;
            ss << "Failed to copy: GUEST "
               << guest_copy_point << " is already exists";
            throw std::runtime_error( ss.str() );
        }

        bool const do_rec =
            fs::is_directory( host_copy_point ) &&
            !fs::is_symlink( host_copy_point );

        if ( !fs::exists( guest_copy_point.parent_path() ) ) {
            fs::create_directory( guest_copy_point.parent_path() );
        }

        fs::copy( host_copy_point, guest_copy_point );

        if ( do_rec ) {
            // copy recuesive
            auto const begin = fs::directory_iterator( host_copy_point );
            auto const end = fs::directory_iterator();

            for( auto&& it : boost::make_iterator_range( begin, end ) ) {
                auto const& p = it.path();
                auto const& filename = p.filename();

                copy_user_files( host_copy_point / filename, guest_copy_point / filename );
            }
        }
    }

    // ...?
    bool remove_user_files(
        fs::path const& guest_copy_point
        )
    try {
        std::cout << "Rm(userfile): " << guest_copy_point << std::endl;

        //
        if ( fs::is_symlink( guest_copy_point ) ||
             fs::is_regular_file( guest_copy_point )
            ) {
            fs::remove( guest_copy_point );

            return true;

        } else if ( fs::is_directory( guest_copy_point ) ) {
            // remove recuesive
            auto const begin = fs::directory_iterator( guest_copy_point );
            auto const end = fs::directory_iterator();

            bool succeeded = true;
            for( auto&& it : boost::make_iterator_range( begin, end ) ) {
                auto const& p = it.path();

                succeeded &= remove_user_files( p );
            }

            succeeded &= remove_directory_if_empty( guest_copy_point );

            return succeeded;

        } else {
            return false;
        }

    } catch( fs::filesystem_error const& e ) {
        std::cerr << "Failed to remove_node: "
                  << e.what() << std::endl;
        return false;

    } catch(...) {
        std::cerr << "Failed to remove_node: "
                  << "unexpected" << std::endl;
        return false;
    }

} // namespace awaho
