//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <cassert>
#include <sstream>
#include <exception>
#include <cstring>

#include <sys/resource.h>
#include <sys/time.h>
#include <sys/stat.h>


namespace awaho
{
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


    void set_limits( limits_values_t const& limits )
    {
        // set limits
        if ( limits.core ) {
            set_limit( RLIMIT_CORE, *limits.core );
        }
        if ( limits.nofile ) {
            set_limit( RLIMIT_NOFILE, *limits.nofile );
        }
        if ( limits.nproc ) {
            set_limit( RLIMIT_NPROC, *limits.nproc );
        }
        if ( limits.memlock ) {
            set_limit( RLIMIT_MEMLOCK, *limits.memlock );
        }
        if ( limits.cputime ) {
            // CPU can be used only cpu_limit_time(sec)
            set_limit( RLIMIT_CPU, *limits.cputime, *limits.cputime + 3 );
        }
        if ( limits.memory ) {
            // Memory can be used only memory_limit_bytes [be careful!]
            set_limit( RLIMIT_AS, *limits.memory, *limits.memory * 1.2 );
        }
        if ( limits.fsize ) {
            set_limit( RLIMIT_FSIZE, *limits.fsize );
        }
    }

} // namespace awaho
