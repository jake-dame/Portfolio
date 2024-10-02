/*******************************************************************************
 * \brief Parsing functions definitions
 *
 * \file parse.cpp
 * \author Jake Dame
 ******************************************************************************/

#include <iostream> /* Console I/O */

#include "parse.h"

PTR( Expr ) parse_expr( std::istream & stream  );
PTR( Expr ) parse_eqs  ( std::istream & stream );
PTR( Expr ) parse_adds ( std::istream & stream );
PTR( Expr ) parse_mults( std::istream & stream );
PTR( Expr ) parse_calls( std::istream & stream );
PTR( Expr ) parse_bases( std::istream & stream );

PTR( Expr ) parse_num( std::istream & stream );
PTR( Expr ) parse_bool( std::istream & stream );
PTR( Expr ) parse_var( std::istream & stream );
PTR( Expr ) parse_let( std::istream & stream );
PTR( Expr ) parse_if ( std::istream & stream );
PTR( Expr ) parse_fun( std::istream & stream );

PTR( Expr ) parse_paren( std::istream & stream );

int build_number( std::istream & stream );
std::string peek_keyword( std::istream & stream );
void consume( std::istream & stream, int expect );
void consume( std::istream & stream,  const std::string & str  );
void consume_whitespace( std::istream & stream );

/******************************************************************************
 * \brief Converts a mathematical expression (string) to an Expr object
 *
 * \param str The string to parse
 * \return An Expr object representing a mathematical expression (string)
 *
 * The parse_expr() function is the entry point for the recursion chain that
 * recursively parses a mathematical expression (string). The recursion
 * follows parses binary expressions, then uses a sort of dispatching function
 * to handle unary and ternary expressions; it is depicted below:
 *
 *      parse_expr() -->  parse_eqs() -->   parse_adds() -->
 *
 *      parse_mults() --> parse_calls() --> parse_bases()
 *
 * parse_bases() employs a number of helper functions that
 * further parse the appropriate expressions. Other helpers that aid in parsing
 * fall in the general category, and aid in reading from the input stream
 * safely, removing whitespace, etc.
 *
 * If the recursion chain has returned to this function and there are still
 * characters in the stream, they were not detected within the recursion chain,
 * meaning they are not valid.
 *
 * \throws std::runtime_error On encountering invalid input that was
 *                            categorically passed over elsewhere in the
 *                            recursion chain
 *****************************************************************************/
PTR( Expr ) parse_expr( const std::string & str )
{
    std::stringstream stream( str );
    PTR( Expr ) e = parse_eqs( stream );

    consume_whitespace( stream );
    if ( !stream.eof()  )
        throw std::runtime_error( "parse_expr(): invalid input" );

    return e;
}

/******************************************************************************
 * \brief An alias function for maintainability
 *
 * \param stream A reference to an input stream to read from
 * \return A pointer to an Expr object
 *****************************************************************************/
PTR( Expr ) parse_expr( std::istream & stream  )
{
    return parse_eqs( stream );
}

/******************************************************************************
 * \brief Constructs Eq objects from parsed comparison expressions
 *
 * \param stream A reference to an input stream to read from
 * \return A pointer to an Eq object
 *****************************************************************************/
PTR( Expr ) parse_eqs  ( std::istream & stream )
{
    PTR( Expr ) e = parse_adds( stream );
    consume_whitespace( stream );

    int first_equals = stream.peek();
    if ( first_equals == '=' )
    {
        consume( stream, first_equals );

        int second_equals = stream.peek();
        if ( second_equals == '=' )
        {
            consume( stream, second_equals );
            return NEW( Eq )( e, parse_eqs( stream ) );
        }
        else
            stream.putback( static_cast<char>( first_equals ) );
    }

    return e;
}

/******************************************************************************
 * \brief Constructs Add objects from parsed addition expressions
 *
 * \param stream A reference to an input stream to read from
 * \return A pointer to a Bool object
 *****************************************************************************/
PTR( Expr ) parse_adds( std::istream & stream )
{
    PTR( Expr ) e = parse_mults( stream );
    consume_whitespace( stream );

    if ( stream.peek() == '+' )
    {
        consume( stream, '+' );
        return NEW( Add )( e, parse_adds( stream ) );
    }

    return e;
}

/******************************************************************************
 * \brief Constructs Mult objects from parsed multiplication expressions
 *
 * \param stream A reference to an input stream to read from
 * \return A pointer to a Bool object
 *****************************************************************************/
PTR( Expr ) parse_mults( std::istream & stream )
{
    PTR( Expr ) e = parse_calls( stream );
    consume_whitespace( stream );

    if ( stream.peek() == '*' )
    {
        consume( stream, '*' );
        e = NEW( Mult )( e, parse_mults( stream ) );
    }
    return e;
}

PTR( Expr ) parse_calls( std::istream & stream )
{
    PTR( Expr ) e = parse_bases( stream );

    PTR( Expr ) actual_arg;
    while ( stream.peek() == '(' )
    {
        consume( stream, '(' );
        actual_arg = parse_expr( stream );
        consume( stream, ')' );
        e = NEW( Call )( e, actual_arg );
    }

    return e;
}

/******************************************************************************
 * \brief Handles unary and ternary expressions in various ways
 *
 * \param stream A reference to an input stream to read from
 * \return A pointer to an Expr object
 *
 * Calls base-case helper functions: parse_num(), parse_var(), or parse_let().
 * Returns to parse_mults().
 *
 * \throws std::runtime_error On encountering characters not valid in any
 *                            unary, binary, or ternary expression
 *****************************************************************************/
PTR( Expr ) parse_bases( std::istream & stream )
{
    consume_whitespace( stream );

    const int c = stream.peek();
    if ( c == '-' || isdigit( c ) )
        return parse_num( stream );
    else if ( isalpha( c ) )
        return parse_var( stream );
    else if  ( c == '(' )
        return parse_paren( stream );
    else if ( c == '_' )
    {
        std::string kw = peek_keyword( stream );
        if ( kw == "LET" )
            return parse_let( stream );
        else if ( kw == "IF" )
            return parse_if( stream );
        else if ( kw == "FUN" )
            return parse_fun( stream );
        else
            return parse_bool( stream );
    }
    else
        throw std::runtime_error( "parse_bases(): "
                                  "invalid input" );
}

/******************************************************************************
 * \brief Helper for parse_bases that handles elements of
 *        mathematical expressions that begin with an underscore
 *
 * \param stream A reference to an input stream to read from
 * \return A string that functions as a label for use in the calling function
 *****************************************************************************/
std::string peek_keyword( std::istream & stream )
{
    consume( stream, '_' );

    std::string res;

    const int first_char = stream.peek();
    if ( first_char == 'l' )
        res = "LET";
    else if ( first_char == 'i' )
        res = "IF";
    else if ( first_char == 't' )
        res = "TRUE";
    else if ( first_char == 'f' )
    {
        consume( stream, first_char );

        int second_char = stream.peek();
        if ( second_char == 'a' )
            res = "FALSE";
        else
            res = "FUN";

        stream.putback( static_cast<char>( first_char ) );
    }
    else
        throw std::runtime_error( "peek_keyword(): "
                                  "invalid keyword" );

    stream.putback( '_' );
    return res;
}

/******************************************************************************
 * \brief Constructs Bool objects from parsed boolean expressions
 *
 * \param stream A reference to an input stream to read from
 * \return A pointer to a Bool object
 *****************************************************************************/
PTR( Expr ) parse_bool( std::istream & stream )
{
    consume( stream, '_' );

    if ( stream.peek() == 't' )
    {
        consume( stream, "true" );
        return NEW( Bool )( true );
    }
    else
    {
        consume( stream, "false" );
        return NEW( Bool )( false );
    }
}

/******************************************************************************
 * \brief Constructs Num objects from parsed numerical expressions
 *
 * \param stream A reference to an input stream to read from
 * \return A pointer to a Num object
 *
 * \throws std::runtime_error On invalid variable expressions
 *****************************************************************************/
PTR( Expr ) parse_num( std::istream & stream )
{
    bool negative = false;

    if ( stream.peek() == '-' )
    {
        negative = true;
        consume( stream, '-' );
        if ( !isdigit( stream.peek() ) )
            throw std::runtime_error( "parse_num(): expecting "
                                      "digit after '-'" );
    }

    int number = build_number( stream );
    if ( negative )
        number *= -1;

    return NEW( Num )( number );
}

/******************************************************************************
 * \brief Helper for parse_num() that builds singular integers from multiple
 *        chars
 *
 * \param stream A reference to an input stream to read from
 * \return A pointer to a Var object
 *
 * \throws std::runtime_error On detecting malformed numbers
 *****************************************************************************/
int build_number( std::istream & stream )
{
    int number = 0;
    while ( true )
    {
        const int c = stream.peek();
        if ( isdigit( c ) )
        {
            consume( stream, c );
            number = number * 10 + ( c - '0' );
        }
        else
        {
            if ( !isspace( c ) &&
                 c != ')' &&
                 c != '*' &&
                 c != '+' &&
                 c != '=' &&
                 !stream.eof() )
                throw std::runtime_error( "build_number(): malformed number" );
            else
                break;
        }
    }
    return number;
}

/******************************************************************************
 * \brief Constructs Var objects from parsed alphabetical expressions
 *
 * \param stream A reference to an input stream to read from
 * \return A pointer to a Var object
 *
 * \throws std::runtime_error On detecting malformed variables
 *****************************************************************************/
PTR( Expr ) parse_var( std::istream & stream )
{
    std::string str;
    while ( true )
    {
        const int c = stream.peek();
        if ( isalpha( c ) )
        {
            consume( stream, c );
            str += std::string( 1, static_cast<char> ( c ) );
        }
        else
        {
            if ( !isspace( c ) && c != ')' && c != '*'
                 && c != '+' && c != '=' && !stream.eof() )
            throw std::runtime_error( "build_variable(): malformed variable" );
            else
                break;
        }
    }
    return NEW( Var )( str );
}

/******************************************************************************
 * \brief Constructs Let objects from parsed let-binding expressions
 *
 * \param stream A reference to an input stream to read from
 * \return A pointer to a Let object
 *
 * \throws std::runtime_error On invalid let bindings
 *****************************************************************************/
PTR( Expr ) parse_let( std::istream & stream )
{
    consume( stream, "_let" );

    PTR( Var ) lhs = CAST( Var )( parse_expr( stream ) );
    if ( lhs == nullptr )
        throw std::runtime_error( "parse_let(): invalid let" );

    consume( stream, '=' );

    PTR( Expr ) rhs = parse_expr( stream );

    consume( stream, "_in" );

    PTR( Expr ) body = parse_expr( stream );
    if ( body->subst( lhs->str_m, rhs )->equals( body ) )
        throw std::runtime_error( "parse_let(): invalid let" );

    return NEW( Let )( lhs->str_m, rhs, body );
}

/******************************************************************************
 * \brief Constructs If objects from parsed condition expressions
 *        (e.g. "_if ... _then ... _else ...")
 *
 * \param stream A reference to an input stream to read from
 * \return A pointer to an If object
 *****************************************************************************/
PTR( Expr ) parse_if ( std::istream & stream )
{
    consume( stream, "_if" );
    PTR( Expr ) test = parse_expr( stream );

    consume( stream, "_then" );
    PTR( Expr ) then = parse_expr( stream );

    consume( stream, "_else" );
    PTR( Expr ) el = parse_expr( stream );

    return NEW( If )( test, then, el );
}

PTR( Expr ) parse_fun( std::istream & stream )
{
    consume( stream, "_fun" );

    PTR( Var ) formal_arg = CAST( Var )( parse_expr( stream ) );
    if ( formal_arg == nullptr )
        throw std::runtime_error( "parse_let(): invalid fun" );

    PTR( Expr ) body = parse_expr( stream );
    if ( body->subst( formal_arg->str_m, body )->equals( body ) )
        throw std::runtime_error( "parse_let(): invalid fun" );

    return NEW( Fun )( formal_arg->str_m, body );
}

/******************************************************************************
 * \brief Handles parentheses and calls new recursive chain for nested
 *        expressions
 *
 * \param stream A reference to an input stream to read from
 * \return An pointer to an Expr object
 *
 * \throws std::runtime_error On missing close parenthesis
 *****************************************************************************/
PTR( Expr ) parse_paren( std::istream & stream )
{
    consume( stream, '(' );

    PTR( Expr ) e = parse_expr( stream );

    if ( stream.peek() != ')' )
        throw std::runtime_error( "parse_paren(): "
                                  "missing closing parenthesis" );
    else
        consume( stream, ')' );

    return e;
}

/******************************************************************************
 * \brief Helper function that safely removes handled tokens from the stream
 *
 * \param stream A reference to an input stream to read from
 * \param expect The element expected to be in the stream's next position
 *
 * The consume() function is the only place within the parsing chain where
 * get() is called on the input stream. The safety mechanism provided by the
 * second parameter ("expect") ensures that the element being removed from the
 * stream is in alignment with what is expected to be removed. With complex
 * recursive parsing using an input stream, this function provides an extra
 * layer of security for the implementation and aids in checking for valid
 * grammar in the user-inputted expression. It is essentially an aid to
 * maintainability and debugging, and also improves readability.
 *
 * \throws std::runtime_error Throws if mismatch between char and expect
 *****************************************************************************/
void consume( std::istream & stream, const int expect )
{
    const int c = stream.get();
    if ( c != expect )
        throw std::runtime_error( "consume(): mismatch" );
}

/******************************************************************************
 * \brief A polymorphic version of consume that accepts std::string inputs
 *
 * \param stream A reference to an input stream to read from
 * \param str The string to consume
 *
 * See consume() description of functionality
 *
 * \throws std::runtime_error Throws if mismatch between any char and expect
 *****************************************************************************/
void consume( std::istream & stream, const std::string & str )
{
    for ( char expect : str )
    {
        const int c = stream.get();
        if ( c != expect )
            throw std::runtime_error( "consume(): mismatch" );
    }
}

/******************************************************************************
 * \brief Helper for parsing that handles whitespace
 *
 * \param stream A reference to an input stream to read from
 *****************************************************************************/
void consume_whitespace( std::istream & stream )
{
    while ( true )
    {
        const int c = stream.peek();
        if ( !isspace( c ) )
            break;
        consume( stream, c );
    }
}