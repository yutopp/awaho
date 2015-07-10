//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <string>
#include <cstdlib>
#include <iostream>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include "linux_exec.hpp"


namespace awaho
{
    namespace linux
    {
        class user
        {
        public:
            user() = delete;

            // name will NOT be escaped. be careful
            user( std::string const& name ) noexcept
                : name_( name )
                , is_valid_( false )
                , is_user_created_( false )
            {
                auto const stat = std::system( ("useradd --no-create-home " + name_).c_str() );
                if ( stat == -1 || !WIFEXITED(stat) || WEXITSTATUS(stat) != 0 ) {
                    return;
                }
                is_user_created_ = true;

                auto const user_id_s = simple_exec( "id --user " + name_ );
                if ( !user_id_s ) {
                    return;
                }

                auto const group_id_s = simple_exec( "id --group " + name_ );
                if ( !group_id_s ) {
                    return;
                }

                try {
                    user_id_ = boost::lexical_cast<int>( boost::trim_copy( *user_id_s ) );
                    group_id_ = boost::lexical_cast<int>( boost::trim_copy( *group_id_s ) );
                    is_valid_ = true;

                } catch(...) {
                    // TODO: ...

                }
            }

            user( user const& ) = delete;
            user( user&& rhs )
                : name_( std::move( rhs.name_ ) )
                , is_valid_( rhs.is_valid_ )
                , is_user_created_( rhs.is_user_created_ )
                , user_id_( rhs.user_id_ )
                , group_id_( rhs.group_id_ )
            {
                std::cout << "move ctor" << std::endl;
                // set invalid status to moved data
                rhs.is_valid_ = false;
                rhs.is_user_created_ = false;
            }

            ~user()
            {
                if ( is_user_created_ ) {
                    auto const stat = std::system( ("userdel " + name_).c_str() );
                    std::cout << "user / delete stat: " << stat << std::endl;
                }
            }

            auto valid() const
                -> bool
            {
                return is_valid_;
            }

            auto name() const
                -> std::string const&
            {
                return name_;
            }

            auto user_id() const
                -> int
            {
                return user_id_;
            }

            auto group_id() const
                -> int
            {
                return group_id_;
            }

        private:
            std::string name_;

            bool is_valid_;
            bool is_user_created_;

            int user_id_, group_id_;
        };

    } // namespace linux
} // namespace awaho
