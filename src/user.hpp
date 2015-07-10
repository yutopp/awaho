//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <boost/optional.hpp>

#include "linux_user.hpp"
#include "utility.hpp"


namespace awaho
{
    using user = linux::user;

    auto make_anonymous_user() noexcept
        -> boost::optional<user>
    {
        try {
            expect_root();
        } catch( std::runtime_error const& e ) {
            // e...
            return boost::none;
        }

        // retry 5 times
        for( int i=0; i<5; ++i ) {
            user u( make_random_name() );
            if ( u.valid() ) {
                return std::move( u );
            }
        }

        return boost::none;
    }

} // namespace awaho
