//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <random>
#include <string>
#include <vector>
#include <memory>
#include <tuple>

#include <boost/range/adaptor/indexed.hpp>

#include <unistd.h>
#include <sys/types.h>


namespace awaho
{
    namespace adap = boost::adaptors;

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

    void expect_root()
    {
        if ( ::geteuid() != 0 ) {
            throw std::runtime_error( "you must run this program as root" );
        }
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

} // namespace awaho
