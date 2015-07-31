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
#include <cstdlib>
#include <vector>
#include <memory>
#include <tuple>
#include <regex>

#include <boost/range/adaptor/indexed.hpp>
#include <boost/algorithm/string/case_conv.hpp>

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
                             std::size_t(0), []( std::size_t const& len, std::string const& r ) {
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

    template<typename Envs>
    auto overwrite_path( Envs const& envs )
        -> void
    {
        // First reset PATH
        if ( ::unsetenv( "PATH" ) == -1 ) {
            throw std::runtime_error( "Failed to unset PATH" );
        }
        if ( ::setenv( "PATH", "", 1 ) == -1 ) {
            throw std::runtime_error( "Failed to reset PATH" );
        }

        std::regex const re("^(.*?)=(.*)$");
        for( auto const& env : envs ) {
            std::smatch sm;
            std::regex_search( env, sm, re );

            // If 'PATH' is specified, set this as new PATH variable
            if ( sm.size() == 3 ) {
                if ( boost::to_upper_copy<std::string>( sm[1] ) == "PATH" ) {
                    std::string const value = sm[2];

                    if ( ::setenv( "PATH", value.c_str(), 1 ) == -1 ) {
                        throw std::runtime_error( "Failed to set PATH" );
                    }
                }
            }
        }
    }

} // namespace awaho
