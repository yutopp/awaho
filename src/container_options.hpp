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
#include <boost/optional.hpp>

#include <sys/resource.h>

namespace awaho
{
    namespace fs = boost::filesystem;

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

    // printer
    std::ostream& operator<<( std::ostream& os, container_options_t const& opts );

} // namespace awaho
