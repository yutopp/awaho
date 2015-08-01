//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <iostream>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>
#include <boost/range/adaptor/indexed.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/optional.hpp>

#include <sys/resource.h>


namespace awaho
{
    namespace fs = boost::filesystem;
    namespace adap = boost::adaptors;

    struct mount_point
    {
        fs::path host_path;
        fs::path guest_path;

        bool is_readonly;
        bool do_chown;
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
        for( auto&& im : opts.mount_points | adap::indexed( 0 ) ) {
            os << "    " << im.index() << " ==" << std::endl;

            auto&& mp = im.value();
            os << "      HOST     : " << mp.host_path << std::endl
               << "      GUEST    : " << mp.guest_path << std::endl
               << "      READONLY : " << mp.is_readonly << std::endl
               << "      DO CHOWN : " << mp.do_chown << std::endl
                ;
        }

        os << "  copies: " << std::endl;
        for( auto&& im : opts.copy_points | adap::indexed( 0 ) ) {
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
        for( auto&& im : opts.pipe_redirects | adap::indexed( 0 ) ) {
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

} // namespace awaho
