//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//

#include "container_options.hpp"

#include <boost/range/adaptor/indexed.hpp>
#include <boost/algorithm/string.hpp>

namespace awaho
{
    namespace adap = boost::adaptors;

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
