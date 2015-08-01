//
// Copyright yutopp 2015 - .
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//

#include <string>
#include <cstring>
#include <algorithm>

#include <boost/program_options.hpp>
#include <boost/range/algorithm_ext/erase.hpp>

#include <sys/resource.h>

#include "awaho.hpp"


int main( int argc, char* argv[] )
{
    namespace po = boost::program_options;

    // Generic options
    po::options_description generic( "Generic options" );
    generic.add_options()
        ( "base-host-path", po::value<std::string>(), "sandbox path will be $base-host-path/$id" )

        ( "start-guest-path", po::value<std::string>(), "cd to $start-guest-path in container at first (Ex. /home/some_user)" )
        ( "mount", po::value<std::vector<std::string>>(), "host:guest(:rw?)(:chown?)" )
        ( "copy", po::value<std::vector<std::string>>(), "host:guest" )

        ( "core", po::value<::rlim_t>(), "setrlimit core" )
        ( "nofile", po::value<::rlim_t>(), "setrlimit nofile" )
        ( "nproc", po::value<::rlim_t>(), "setrlimit nproc" )
        ( "memlock", po::value<::rlim_t>(), "setrlimit memlock" )
        ( "cputime", po::value<::rlim_t>(), "setrlimit cpu time" )
        ( "memory", po::value<::rlim_t>(), "setrlimit memory" )
        ( "fsize", po::value<::rlim_t>(), "setrlimit fsize" )

        ( "stack-size", po::value<std::size_t>(), "stack size" )
        ( "pipe", po::value<std::vector<std::string>>(), "host-fd:guest-fd" )

        // commands is "argv-in-container"
        ( "env", po::value<std::vector<std::string>>(), "env variables" )

        ( "result-fd", po::value<int>(), "fd can get detail of result" )
        ( "result-type", po::value<std::string>(), "type of result [json]" )

        ( "help", "produce help message" )
        ;

    po::options_description hidden( "Hidden options" );
    hidden.add_options()
        ( "argv-in-container", po::value<std::vector<std::string>>(), "argv" )
        ;

    po::options_description cmdline_options;
    cmdline_options
        .add( generic )
        .add( hidden )
        ;

    po::positional_options_description p;
    p.add( "argv-in-container", -1 );

    try {
        po::variables_map vm;
        po::store(
            po::command_line_parser( argc, argv )
                .options( cmdline_options )
                .positional( p )
                .run(),
            vm
            );
        po::notify( vm );

        //
        if ( vm.count( "help" ) ) {
            std::cout << cmdline_options << std::endl;
            return 0;
        }

        // default option
        auto c_opts = awaho::container_options_t{
            "/tmp/containers_tmp",

            "/",                        // start path in container
            {},                         // mounts
            {},                         // copies
            awaho::limits_values_t{},   // no limitation(use system default)

            2 * 1024 * 1024,            // stack size
            {},                         // no pipe redirect

            { "/bin/bash" },            // default comands
            {},                         // default envs

            1,                          // default fd gets result (stdout)
            "json"                      // default result format
        };

        if ( vm.count( "base-host-path" ) ) {
            auto const& base_host_path =
                vm["base-host-path"].as<std::string>();

            c_opts.host_containers_base_dir = base_host_path;
        }

        if ( vm.count( "start-guest-path" ) ) {
            auto const& start_guest_path =
                vm["start-guest-path"].as<std::string>();

            c_opts.in_container_start_path = start_guest_path;
        }

        if ( vm.count( "mount" ) ) {
            auto const& mounts =
                vm["mount"].as<std::vector<std::string>>();
            for( auto&& v : mounts ) {
                std::vector<std::string> d;
                boost::algorithm::split( d, v, boost::is_any_of(":") );

                if ( d.size() < 2 ) {
                    throw std::runtime_error( "invalid mount option" ); // TODO: fix
                }

                auto mp = awaho::mount_point{
                    d[0],   // host
                    d[1],   // guest
                    true,   // readonly(default)
                    false,  // do not chown(default)
                };

                if ( d.size() >= 3 ) {
                    if ( d[2] == "rw" ) {
                        mp.is_readonly = false;

                    } else if ( d[2] == "ro" ) {
                        mp.is_readonly = true;

                    } else {
                        throw std::runtime_error( "unknown mount option[readonly]" );
                    }
                }

                if ( d.size() >= 4 ) {
                    if ( d[3] == "chown" ) {
                        mp.do_chown = true;

                    } else if ( d[3] == "" ) {
                        mp.do_chown = false;

                    } else {
                        throw std::runtime_error( "unknown mount option[do_chown]" );
                    }
                }

                c_opts.mount_points.emplace_back( std::move( mp ) );
            }
        }

        if ( vm.count( "copy" ) ) {
            auto const& copies =
                vm["copy"].as<std::vector<std::string>>();
            for( auto&& v : copies ) {
                std::vector<std::string> d;
                boost::algorithm::split( d, v, boost::is_any_of(":") );

                if ( d.size() < 2 ) {
                    throw std::runtime_error( "invalid copy option" ); // TODO: fix
                }

                auto cp = awaho::copy_point{
                    d[0],   // host
                    d[1],   // guest
                };

                c_opts.copy_points.emplace_back( std::move( cp ) );
            }
        }

        {
            if ( vm.count( "core" ) ) {
                c_opts.limits.core
                    = vm["core"].as<::rlim_t>();
            }

            if ( vm.count( "nofile" ) ) {
                c_opts.limits.nofile
                    = vm["nofile"].as<::rlim_t>();
            }

            if ( vm.count( "nproc" ) ) {
                c_opts.limits.nproc
                    = vm["nproc"].as<::rlim_t>();
            }

            if ( vm.count( "memlock" ) ) {
                c_opts.limits.memlock
                    = vm["memlock"].as<::rlim_t>();
            }

            if ( vm.count( "cputime" ) ) {
                c_opts.limits.cputime
                    = vm["cputime"].as<::rlim_t>();
            }

            if ( vm.count( "memory" ) ) {
                c_opts.limits.memory
                    = vm["memory"].as<::rlim_t>();
            }

            if ( vm.count( "fsize" ) ) {
                c_opts.limits.fsize
                    = vm["fsize"].as<::rlim_t>();
            }
        }

        if ( vm.count( "stack-size" ) ) {
            auto const& stack_size =
                vm["stack-size"].as<std::size_t>();

            c_opts.stack_size = stack_size;
        }

        if ( vm.count( "pipe" ) ) {
            auto const& pipes =
                vm["pipe"].as<std::vector<std::string>>();
            for( auto&& v : pipes ) {
                std::vector<std::string> d;
                boost::algorithm::split( d, v, boost::is_any_of(":") );

                if ( d.size() != 2 ) {
                    throw std::runtime_error( "invalid pipe option" ); // TODO: fix
                }

                auto pr = awaho::pipe_redirect_t{
                    boost::lexical_cast<int>( boost::trim_copy( d[0] ) ),   // host
                    boost::lexical_cast<int>( boost::trim_copy( d[1] ) ),   // guest
                };

                c_opts.pipe_redirects.emplace_back( std::move( pr ) );
            }
        }

        if ( vm.count( "argv-in-container" ) ) {
            auto commands =
                vm["argv-in-container"].as<std::vector<std::string>>();

            c_opts.commands = boost::remove_erase( commands, "" );  // remove empty
        }

        if ( vm.count( "env" ) ) {
            auto envs = vm["env"].as<std::vector<std::string>>();
            c_opts.envs = boost::remove_erase( envs, "" );  // remove empty
        }

        if ( vm.count( "result-fd" ) ) {
            c_opts.result_output_fd =
                vm["result-fd"].as<int>();
        }

        if ( vm.count( "result-type" ) ) {
            c_opts.result_output_type =
                vm["result-type"].as<std::string>();
        }

        // erace all argv
        assert( argc > 0 );
        const auto len_argv0 = std::strlen( argv[0] );
        for( int i=1; i<argc; ++i) {
            const auto len = std::strlen( argv[i] );
            std::fill( argv[i], argv[i] + len, '\0' );
        }
        std::strncpy( argv[0], "d=(^o^)=b", len_argv0 );

        // call sandbox
        return awaho::execute( c_opts );

    } catch( std::exception const& e ) {
        std::cerr << "Exception: " << std::endl
                  << e.what() << std::endl;
        return -10;

    } catch(...) {
        std::cerr << "Unexpected exception: " << std::endl;
        return -20;
    }
}
