/******************************************************************************
 * \brief A test automation program for the msdscript program
 *
 * \file test_msdscript.cpp
 * \author Jake Dame
 *****************************************************************************/

#include <ctime>        // gets time info
#include <iostream>     // console I/O
#include <fstream>      // std::ofstream
#include <sstream>      // std::stringstream

#include "exec.h"       // includes exec_program()

/**
 * Command line argument handler
 * */
static int use_arguments( int argc, char ** argv );

/**
 * Error-report-building functions
 * */
void write_report_header( std::ofstream & output_file,
                          const std::string & exec_name,
                          const int & error_count );

void write_results( std::stringstream & stream,
                    const std::string & label,
                    const std::vector<ExecResult> & exec_results,
                    const std::string & input,
                    const int & iteration,
                    int & error_count );

/**
 * Testing functions
 * */
void compare_IO( const std::string & exec_name );

void compare_programs( const std::string & exec_name_1,
                       const std::string & exec_name_2 );

/**
 * Input generation functions
 * */
static std::string rand_expr_str( int & depth );
static std::string rand_num();
static std::string rand_var();

/**
 * CONSTANTS
 * */
const std::string EXECS_DIR =
        "/Users/u0858882/Desktop/msdscript/test_msdscript/testers/"
        ; ///< Directory where the executables to test are. USE ABS PATH

const std::string OUTPUT_DIR =
        "/Users/u0858882/Desktop/msdscript/test_msdscript/reports/"
        ; ///< Directory where error reports (.txt) should go. USE ABS PATH

const int TEST_ITER = 30; ///< Number of inputs to test per executable

/******************************************************************************
 * \brief A main() function for the test_msdscript program
 *****************************************************************************/
int main ( int argc, char ** argv )
{
    return use_arguments( argc, argv );
}

/******************************************************************************
 * \brief Handles arguments from the command line
 * 
 * \param argc The command line argument count, passed from main()
 * \param argv The command line argument vector, passed from main()
 *
 * Depending on the command line argument count, controls which test driver
 * is called.
 * Handles invalid arguments.
 * Handles file I/O exceptions.
 * Seeds the PRNG for the program.
 *****************************************************************************/
static int use_arguments( int argc, char ** argv )
{
    // Seed for random number generation for the generation functions
    srand( clock() );

    try
    {
        if ( argc == 2 )
        {
            std::string exec_name = argv[ 1 ];
            compare_IO( exec_name );
        }
        else if ( argc == 3 )
        {
            std::string exec_name_1 = argv[ 1 ];
            std::string exec_name_2 = argv[ 2 ];
            compare_programs( exec_name_1, exec_name_2 );
        }
        else
        {
            std::cerr << "use_arguments(): invalid number of arguments" 
                      <<  std::endl;
            return 1;
        }
        // Error-handling for file I/O for the two testing functions
    }
    catch ( std::runtime_error & exception )
    {
        std::cerr << "ERROR: " << exception.what() << std::endl;
        return 1;
    }

    return 0;
}

/******************************************************************************
 * \brief Writes a header for an "error report"
 * 
 * \param output_file The std::ofstream object to write to
 * \param exec_name The name of the executable to use as a title
 * \param error_count The final error count accumulated during the program
 *
 * This header is written at the end of a test run in order to be able to 
 * use error count information. All error message data -- which has been 
 * written to a separate std::stringstream -- is then written to the output 
 * file as well before it is closed.
 *****************************************************************************/
void write_report_header( std::ofstream & output_file,
                          const std::string & exec_name,
                          const int & error_count )
{
    // Get current time to print
    std::time_t current_time = std::time( nullptr );
    std::string time_str = std::ctime( &current_time );
    if ( !time_str.empty() && time_str[ time_str.length() - 1 ] == '\n' )
        time_str.erase( time_str.length() - 1 );

    /* 
     * If the program returned early due to a thrown exception, 
     * error_count's value will be -1.
     */
    std::string error_count_str;
    if( error_count == -1 )
        error_count_str = "exception thrown in test_msdscript";
    else
        error_count_str = std::to_string( error_count );

    // Write out header information
    output_file << std::string( 80, '#' )                   << std::endl;
    output_file << "\tERROR REPORT FOR:"                    << std::endl;
    output_file << "\n\t\t" << exec_name                    << std::endl;
    output_file << "\n\tFAILED CHECKS: " << error_count_str << std::endl;
    output_file << "\n\t" << time_str                       << std::endl;
    output_file << std::string( 80, '#' )                   << std::endl;
    output_file << std::string( 80, '#' )                   << std::endl;
}

/******************************************************************************
 * \brief Writes data concerning a detected error to a passed stream
 * 
 * \param stream The stream to write to
 * \param label Something to label the results (e.g. the name of variable)
 * \param exec_result The ExecResult object being referenced
 * \param input The input given to the executable
 * \param error_count Int to ++ to represent how many times errors occurred
 *****************************************************************************/
void write_results( std::stringstream & stream,
                    const std::string & label,
                    const ExecResult & er,
                    const std::string & input,
                    int & error_count )
{
    ++error_count;

//    if ( er.exit_code != 0 )
//    {
        stream << "\n/*****    \"" << label << "\"    *****/"   << std::endl;

        stream << "EXIT CODE: " << er.exit_code                 << std::endl;

        stream << "[INPUT]\n" << input                          << std::endl;

        if ( er.out.empty() )
            stream << "\n[OUTPUT]\n" << "~"                     << std::endl;
        else
            stream << "\n[OUTPUT]\n" << er.out                  << std::endl;

        if ( er.err.empty() )
            stream << "\nERR: " << "~"                          << std::endl;
        else
            stream << "\nERR: " << er.err                       << std::endl;
//    }
}

/******************************************************************************
 * \brief Uses a program's own output again as an input as robustness metric
 *
 * \param exec_name The executable to test (see EXECS_DIR constant)
 *****************************************************************************/
void compare_IO( const std::string & exec_name )
{
    // I/O init
    std::stringstream stream;

    std::ofstream output_file( OUTPUT_DIR + exec_name + ".txt" );
    if ( !output_file.is_open() )
        throw std::runtime_error( "compare_IO(): file open failed" );

    // Construct argvs to pass to exec_program
    std::string exec_file_name = EXECS_DIR + exec_name;
    const char * const interp_argv[] = { exec_file_name.c_str(),
                                         "--interp" };
    
    const char * const print_argv[] = { exec_file_name.c_str(), 
                                        "--print" };
    
    const char * const pretty_argv[] = { exec_file_name.c_str(),
                                         "--pretty-print" };

    // Initialize error counter
    int error_count = 0;

    // Run comparisons
    try
    {
        for ( int i = 0 ; i < TEST_ITER ; i++ )
        {
            // Write stuff to output file
            stream << "\tCHECK " << i << "/" << TEST_ITER << std::endl;
            stream << std::string( 80, '#' ) << std::endl;

            // Get random input string
            int init_depth = 0;
            std::string input_str = rand_expr_str( init_depth );

            // Get initial results (x3)
            ExecResult interp = exec_program( 2, interp_argv, input_str );
            write_results( stream, "--interp", interp, input_str, error_count );

            ExecResult print = exec_program( 2, print_argv, input_str );
            write_results( stream, "--print", print, input_str, error_count );

            ExecResult pretty = exec_program( 2, pretty_argv, input_str );
            write_results( stream, "--print", pretty, input_str, error_count );

            // Get I/O results (x2)
            ExecResult interp_print = exec_program( 2, interp_argv, print.out );
            write_results( stream, "--interp + --print", interp_print, input_str, error_count );

            ExecResult interp_p_print = exec_program( 2, interp_argv, pretty.out );
            write_results( stream, "-interp + --pretty-print", interp_p_print, input_str, error_count );

            // Write stuff to output file
            stream << std::string( 80, '#' ) << std::endl;

            /*
             * Compare interp with print
             */
            if ( interp.out != interp_print.out )
            {
                error_count = -1;
                throw std::runtime_error(
                        "different results between interp and print" );
            }

            /*
             * Compare interp with pretty-print
             */
            if ( interp.out != interp_p_print.out )
            {
                error_count = -1;
                throw std::runtime_error(
                        "different results between interp and pretty-print" );
            }
        }
    }
    catch ( std::runtime_error & exception )
    {
        std::string err_msg = "\ntest_msdscript ERROR: " +
                std::string( exception.what() ) + "\n";

        // Write to console
        std::cerr << err_msg;
        // Write to output file too
        stream << err_msg;
    }

    // Build report
    write_report_header( output_file, exec_file_name, error_count );
    output_file << stream.str();

    // I/O close
    output_file.close();
    if ( output_file.fail() )
        throw std::runtime_error( "compare_IO(): file close failed" );
}

/******************************************************************************
 * \brief Compares the results of two programs as a measure of accuracy
 *
 * \param exec_name_1 The first executable (see EXECS_DIR constant)
 * \param exec_name_2 The second executable (see EXECS_DIR constant)
 *****************************************************************************/
void compare_programs( const std::string & exec_name_1, 
                       const std::string & exec_name_2 )
{
    // I/O init
    std::stringstream stream;

    std::ofstream output_file( OUTPUT_DIR + "msdscript_vs_" + exec_name_2 + ".txt" );
    if ( !output_file.is_open() )
        throw std::runtime_error( "compare_programs(): file open failed" );

    // Construct argvs to pass to exec_program
    std::string file_name_1 = EXECS_DIR + exec_name_1;
    std::string file_name_2 = EXECS_DIR + exec_name_2;

    const char * const interp_1_argv[] = { file_name_1.c_str(), "--interp" };
    const char * const interp_2_argv[] = { file_name_2.c_str(), "--interp" };
    const char * const print_1_argv[] = { file_name_1.c_str(), "--print" };
    const char * const print_2_argv[] = { file_name_2.c_str(), "--print" };
    const char * const pretty_1_argv[] = { file_name_1.c_str(), "--pretty-print" };
    const char * const pretty_2_argv[] = { file_name_2.c_str(), "--pretty-print" };

    // Initialize error counter
    int error_count = 0;

    // Run comparisons
    try
    {
        for ( int i = 0 ; i < TEST_ITER ; i++ )
        {
            // For my readability
            std::string label;

            // Write stuff to output file
            stream << "\tCHECK " << i << "/" << TEST_ITER << std::endl;
            stream << std::string( 80, '#' ) << std::endl;

            // Get random input string
            int init_depth = 0;
            std::string input_str = rand_expr_str( init_depth );

            // Get initial results (x2)
            ExecResult interp_1 = exec_program( 2, interp_1_argv, input_str );
            label = exec_name_1 + " " + interp_1_argv[1];
            write_results( stream, label, interp_1, input_str, error_count );

            ExecResult interp_2 = exec_program( 2, interp_2_argv, input_str );
            label = exec_name_2 + " " + interp_2_argv[1];
            write_results( stream, label, interp_2, input_str, error_count );

            ExecResult print_1 = exec_program( 2, print_1_argv, input_str );
            label = exec_name_1 + " " + print_1_argv[1];
            write_results( stream, label, print_1, input_str, error_count );

            ExecResult print_2 = exec_program( 2, print_2_argv, input_str );
            label = exec_name_2 + " " + print_1_argv[1];
            write_results( stream, label, print_2, input_str, error_count );

            ExecResult pretty_1 = exec_program( 2, pretty_1_argv, input_str );
            label = exec_name_1 + " " + pretty_1_argv[1];
            write_results( stream, label, pretty_1, input_str, error_count );

            ExecResult pretty_2 = exec_program( 2, pretty_2_argv, input_str );
            label = exec_name_2 + " " + pretty_1_argv[1];
            write_results( stream, label, pretty_2, input_str, error_count );

            // Write stuff to output file
            stream << std::string( 80, '#' ) << std::endl;

            // Compare results
            if ( interp_1.out != interp_2.out ||
                 print_1.out  != print_2.out  ||
                 pretty_1.out != pretty_2.out )
            {
                error_count = -1;
//                throw std::runtime_error( "different results" );
            }
        }
    }
    catch ( std::runtime_error & exception )
    {
        std::string err_msg =
                "\ntest_msdscript ERROR: " + std::string( exception.what() ) + "\n";

        // Write to: console
        std::cerr << err_msg;
        // Write to output file
        stream << err_msg;
    }

    // Build report
    write_report_header( output_file, file_name_1 +
                        "\n\t\t and \n\t\t" + file_name_2, error_count );

    output_file << stream.str();

    // I/O close
    output_file.close();
    if ( output_file.fail() )
        throw std::runtime_error( "compare_programs(): file close failed" );
}

/******************************************************************************
 * \brief Randomly generates 1 of 4 Expr derived classes, as a string
 *
 * \param depth An int used to keep track of and control recursion depth
 * \return A random Expr as a string
 *
 * Generates a random number between 0 and 9. There is then a 20% chance that
 * the number will meet the condition for 1 of 5 if-statements. If the value
 * of the random number is:
 *
 *      0-1, a random Num string is returned
 *      2-3, a random Add string is returned
 *      5-6, a random Mult string is returned
 *      7-9, a random Let string is returned
 *
 * This recurses until the passed depth exception_ctr matches the MAX_DEPTH
 * constant. This is necessary to prevent infinite recursion.
 *****************************************************************************/
std::string rand_expr_str( int & depth )
{
    const int DEPTH_LIMIT = 5; ///< Max recursion depth for this function

    if ( depth > DEPTH_LIMIT )
        // If recursion depth limit is met, just return a random number
        return std::to_string( rand() % 10000 );

    ++depth;

    // Generate random number between 0-9
    int rand_int = rand() % 10;

    if ( rand_int < 2 )
        return rand_num();                                              // "Num"
    else if ( rand_int < 4 )
        return rand_expr_str( depth ) + " + " + rand_expr_str( depth ); // "Add"
    else if ( rand_int < 6 )
        return rand_expr_str( depth ) + " * " + rand_expr_str( depth ); // "Mult"
    else
    {
        /*
         * This ensures that the Let will *at least* have a
         * matching var from the rhs in its body
         */
        std::string var = rand_var();
        return "_let " + var + " = " + rand_expr_str( depth ) +
               " _in " + var + " + " + rand_expr_str( depth );        // "Let"
    }
}

/******************************************************************************
 * \brief Helper for rand_expr_str() that builds a random pos/neg digit string
 *
 * \param depth An int used to keep track of and control recursion depth
 * \return A random string of random length (see VAR_MAX_LENGTH constant)
 *
 * Numbers are kept under 10,000 to lower the probability of overflow errors
 * when dealing with nested Mult expressions.
 *****************************************************************************/
static std::string rand_num()
{
    std::string str;

    // Generate negative number
    if ( rand() % 2 == 0 )
    {
        str = '-';
        str += std::to_string( rand() % 10000 );
    }
    // Generate positive number
    else
        str = std::to_string( rand() % 10000 );

    return str;
}

/******************************************************************************
 * \brief Helper for rand_expr_str() that builds a random alphabetical var string
 *
 * \param depth An int used to keep track of and control recursion depth
 * \return A random string of random length (see VAR_MAX_LENGTH constant)
 *****************************************************************************/
static std::string rand_var()
{
    const int ASCII_ALPHA_OFFSET = 26;
    const int VAR_MAX_LENGTH = 10;

    // Build random string of VAR_MAX_LENGTH
    std::string rand_string;
    for ( int i = rand() % VAR_MAX_LENGTH ; i < VAR_MAX_LENGTH ; i++ )
    {
        int charac;

        // Choose letter-case probabilistically
        if ( rand() % 2 == 0 )
            charac = rand() % ASCII_ALPHA_OFFSET + 'a';
        else
            charac = rand() % ASCII_ALPHA_OFFSET + 'A';

        rand_string += std::string( 1, static_cast<char> ( charac ) );
    }

    return rand_string;
}