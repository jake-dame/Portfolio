/******************************************************************************
 * \brief Command line argument-handling functions definitions
 *
 * \file cmdline.cpp
 * \author Jake Dame
 *****************************************************************************/

#include <iostream> /* Console I/O */

#define CATCH_CONFIG_RUNNER /* Don't move either of these */

#include "catch.h"          /* Catch2 testing framework */

#include "cmdline.h"
#include "Expr.h"
#include "parse.h"
#include "Val.h"

/**
 * Argument handling functions
 * */
void if_help();

void if_test( char ** argv );

void if_interp();

void if_print();

void if_pretty_print();

/**
 * std::cin helper
 * */
void handle_cin( PTR( Expr ) & e );

/******************************************************************************
 * \brief Interprets command line arguments passed from a main() function
 *
 * \param argc The command line argument count
 * \param argv The command line argument vector
 * \return An int return code to return to a main() function
 *
 * Supports handling of --help, --test, --interp, --print, and --pretty-print
 * command line arguments/flags.
 *****************************************************************************/
int use_arguments( int argc, char ** argv )
{
	try
	{
		for ( int i = 1 ; i < argc ; i++ )
		{
			std::string arg = argv[ i ];

			if ( arg == "--help" )
			{
				if_help();
			}
			else if ( arg == "--test" )
			{
				if_test( argv );
			}
			else if ( arg == "--interp" )
			{
				if_interp();
			}
			else if ( arg == "--print" )
			{
				if_print();
			}
			else if ( arg == "--pretty-print" )
			{
				if_pretty_print();
			}
			else
			{
				std::cerr << "Invalid argument: run program with "
							 "\"--help\" flag to list valid arguments"
						  << std::endl;
			}
		}
	}
	catch ( const std::runtime_error & exception )
	{
		std::cerr << "ERROR: " << exception.what() << std::endl;
		return 1;
	}

	return 0;
}

/******************************************************************************
 * \brief Handles "--help" argument; prints list of valid msdscript arguments
 *****************************************************************************/
void if_help()
{
	std::cout <<
			  "--help:\t\tlists valid arguments"
			  "\n--test:\t\truns tests"
			  "\n--interp:\tsimplifies a user-inputted expression"
			  "\n--print:\tprints a user-inputted expression as a basic string"
			  "\n--pretty-print:\tprints a user-inputted expression as a stylized string"
			  "\n"
			  << std::endl;
}

/******************************************************************************
 * \brief Handles "--test" argument
 *
 * \param argv A list of command line arguments.
 *
 * Runs Catch2 tests.
 *****************************************************************************/
void if_test( char ** argv )
{
	int test_session_rc = Catch::Session().run( 1, argv );
	if ( test_session_rc != 0 )
	{
		exit( 1 );
	}
}

/******************************************************************************
 * \brief Handles the "--interp" command line argument
 *
 * Parses a user-inputted expression, converts it to
 * an Expression object, simplifies it, and prints the result.
 *****************************************************************************/
void if_interp()
{
	PTR( Expr ) e;
	handle_cin( e );
//    std::cout << "\ninterp() result:\t" << e->interp()->to_string() << std::endl; // TODO put back (ced out for debugging test_msdscript)
	std::cout << e->interp()->to_string() << std::endl;
}

/******************************************************************************
 * \brief Handles the "--print" command line argument
 *
 * Parses a user-inputted expression, converts it to an Expression
 * object, and then prints it as a string.
 *****************************************************************************/
void if_print()
{
	PTR( Expr ) e;
	handle_cin( e );
//    std::cout << "\nprint() result:\t" << e->to_string() << std::endl; // TODO put back (ced out for debugging test_msdscript)
	std::cout << e->to_string() << std::endl;
}

/******************************************************************************
 * \brief Handles the "--pretty-print" command line argument
 *
 * Parses a user-inputted expression, converts it to an Expression
 * object, and then prints it as a stylized string.
 *****************************************************************************/
void if_pretty_print()
{
	PTR( Expr ) e;
	handle_cin( e );
//    std::cout << "\npretty_print() result:\t" << e->to_pretty_string() << std::endl; // TODO put back (ced out for debugging test_msdscript)
	std::cout << e->to_pretty_string() << std::endl;
}

/******************************************************************************
 * \brief Helper function for argument functions that request user input.
 *****************************************************************************/
void handle_cin( PTR( Expr ) & e )
{
//    std::cout << "Enter an expression:\t"; // TODO put back (ced out for debugging test_msdscript)

	std::string user_string;
	std::string line;

	while ( std::getline( std::cin, line ) )
	{
		user_string += line + '\n';
	}

	if ( !user_string.empty() && user_string.back() == '\n' )
	{
		user_string.pop_back();
	} // Remove eof

	e = parse_expr( user_string );
}