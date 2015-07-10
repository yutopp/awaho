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

#include <unistd.h>
#include <sys/types.h>


namespace awaho
{
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

} // namespace awaho
