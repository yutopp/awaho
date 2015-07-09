//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <string>
#include <cstdio>
#include <cstdlib>
#include <sstream>

#include <boost/scope_exit.hpp>
#include <boost/optional.hpp>


namespace awaho
{
    namespace linux
    {
        auto simple_exec( std::string const& command ) noexcept
            -> boost::optional<std::string>
        {
            FILE* const fp = ::popen( command.c_str(), "r" );
            if ( fp == nullptr ) {
                return boost::none;
            }

            BOOST_SCOPE_EXIT_ALL(&fp) {
                ::pclose(fp);
            };

            try {
                std::stringstream ss;
                constexpr auto BufferSize = 128;
                char buffer[BufferSize];

                while( !std::feof( fp ) ) {
                    if ( std::fgets( buffer, BufferSize, fp ) != nullptr ) {
                        ss << buffer;
                    }
                }

                return ss.str();

            } catch( std::exception const& e ) {
                // TODO: I want to use "std::expected"...
                return boost::none;
            }
        }

    } // namespace linux
} // namespace awaho
