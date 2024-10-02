/******************************************************************************
 * \brief Val bass class and derived class definitions
 *
 * \file Val.cpp
 * \author Jake Dame
 *****************************************************************************/

#include <utility>

#include "Env.h"
#include "Expr.h"
#include "Val.h"

/******************************************************************************
 * \brief Non-virtual: Converts a Val object to a basic, easily-readable string
 *
 * \return An std::string object representing the Val object's value.
 *****************************************************************************/
std::string Val :: to_string()
{
    std::stringstream stream( "" );
    print( stream );
    return stream.str();
}

/******************************************************************************
 * \brief Constructs a NumVal object representing an integer
 *
 * \param val An int to define this NumVal object's integer value
 *****************************************************************************/
NumVal :: NumVal( int val )
{
    int_m = val;
}

/******************************************************************************
 * \brief Converts a NumVal object to a Num object
 *
 * \return A Num object with an equivalent integer value as this NumVal object
 *****************************************************************************/
PTR( Expr ) NumVal :: to_expr()
{
    return NEW( Num )( int_m );
}

/******************************************************************************
 * \brief Compares an object to this NumVal object
 *
 * \param v The object to compare this NumVal object to
 * \return True if the two objects are both NumVal objects and represent
 * equivalent int_m values
 *****************************************************************************/
bool NumVal :: equals( PTR( Val ) v )
{
    PTR( NumVal ) num_cmp = CAST( NumVal )( v );
    return num_cmp != nullptr && int_m == num_cmp->int_m;
}

/******************************************************************************
 * \brief Adds two NumVal object's integer values together
 *
 * \throws std::runtime_error If the objects being added are not NumVals
 * \return A new NumVal object representing the sum of the NumVal objects
 *****************************************************************************/
PTR( Val ) NumVal :: add_to( PTR( Val ) other_val )
{
    PTR( NumVal ) other_num = CAST( NumVal )( other_val );

    if ( other_num == nullptr )
        throw std::runtime_error( "invalid operation on non-number" );

    return NEW( NumVal )( ( unsigned ) int_m + ( unsigned ) other_num->int_m ); // NOLINT( cppcoreguidelines-narrowing-conversions )
}

/******************************************************************************
 * \brief Multiplies two NumVal object's integer values together
 *
 * \throws std::runtime_error If the objects being multiplied are not NumVals
 * \return A new NumVal object representing the product of the NumVal objects
 *****************************************************************************/
PTR( Val ) NumVal :: mult_with( PTR( Val ) other_val )
{
    PTR( NumVal ) other_num = CAST( NumVal )( other_val );

    if ( other_num == nullptr )
        throw std::runtime_error( "invalid operation on non-number" );

    return NEW( NumVal )( ( unsigned )  int_m * ( unsigned ) other_num->int_m ); // NOLINT( cppcoreguidelines-narrowing-conversions )
}

/******************************************************************************
 * \brief This function will always throw an exception. See: BoolVal::is_true()
 *
 * \throws std::runtime_error
 * \return This function will never return.
 *****************************************************************************/
bool NumVal :: is_true()
{
    throw std::runtime_error( "cannot call is_true on NumVal" );
}

/******************************************************************************
 * \brief Writes out a string representation of this NumVal object
 *
 * \param stream A reference to an output stream object to write to
 * Writes this NumVal object's int_m value, as a string, to a passed output
 * stream which is later printed in Val::to_string().
 *****************************************************************************/
void NumVal :: print( std::ostream & stream )
{
    stream << to_expr()->to_string();
}

/******************************************************************************
 * \brief
 *
 * \param actual_arg
 * \return
 *
 * \throws std::runtime_error
 *****************************************************************************/
PTR( Val ) NumVal :: call( PTR( Val ) actual_arg )
{
    throw std::runtime_error( "cannot use call() on this type" );
}

/******************************************************************************
 * \brief Constructs a BoolVal object representing a boolean value
 *
 * \param val A bool to define this BoolVal object's boolean value
 *****************************************************************************/
BoolVal :: BoolVal( bool val )
{
    bool_m = val;
}

/******************************************************************************
 * \brief Converts a BoolVal object to a Bool object
 * \return A Bool object with an equivalent bool value as this BoolVal object
 *****************************************************************************/
PTR( Expr ) BoolVal :: to_expr()
{
    return NEW( Bool )( bool_m );
}

/******************************************************************************
 * \brief Compares an object to this BoolVal object
 *
 * \param v The object to compare this BoolVal object to
 * \return True if the two objects are both BoolVal objects and represent
 * equivalent bool_m values
 *****************************************************************************/
bool BoolVal :: equals( PTR( Val ) v )
{
    PTR( BoolVal ) bool_cmp = CAST( BoolVal )( v );
    return bool_cmp != nullptr && bool_m == bool_cmp->bool_m;
}

/******************************************************************************
 * \brief This function will always throw an exception. See: NumVal::add_to()
 *
 * \throws std::runtime_error If the objects being added are not NumVals
 * \return This function will never return.
 *****************************************************************************/
PTR( Val ) BoolVal :: add_to( PTR( Val) other_val)
{
    throw std::runtime_error( "invalid operation on non-number" );
}

/******************************************************************************
 * \brief This function will always throw an exception. See:
 * NumVal::mult_with()
 *
 * \throws std::runtime_error If the objects being multiplied are not NumVals
 * \return This function will never return.
 *****************************************************************************/
PTR( Val ) BoolVal :: mult_with( PTR( Val ) other_val )
{
    throw std::runtime_error( "invalid operation on non-number" );
}

/******************************************************************************
 * \brief Reveals this BoolVal object's bool_m value.
 *
 * \return True if this BoolVal object's bool_m value is true.
 *****************************************************************************/
bool BoolVal :: is_true()
{
    return bool_m;
}

/******************************************************************************
 * \brief Writes out a string representation of this BoolVal object
 *
 * \param stream A reference to an output stream object to write to
 * Writes this BoolVal object's bool_m value, as a string, to a passed output
 * stream which is later printed in Val::to_string().
 *****************************************************************************/
void BoolVal :: print( std::ostream & stream )
{
    stream << to_expr()->to_string();
}

/******************************************************************************
 * \brief
 *
 * \param actual_arg
 * \return
 *
 * \throws std::runtime_error
 *****************************************************************************/
PTR( Val ) BoolVal :: call( PTR( Val ) actual_arg )
{
    throw std::runtime_error( "cannot use call() on this type" );
}

FunVal :: FunVal( std::string arg, PTR( Expr ) body, PTR( Env ) env )
{
    formal_arg_m = std::move( arg );
    body_m = body;
	env_m = env;
}

PTR( Expr ) FunVal :: to_expr()
{
    return NEW( Fun )( formal_arg_m, body_m );
}

bool FunVal :: equals( PTR( Val ) v )
{
    PTR( FunVal ) funval_cmp = CAST( FunVal )( v );
    return funval_cmp != nullptr &&
           formal_arg_m == funval_cmp->formal_arg_m &&
           body_m->equals( funval_cmp->body_m );
}

PTR( Val ) FunVal :: add_to( PTR( Val ) v )
{
    throw std::runtime_error( "invalid operation on non-number" );
}

PTR( Val ) FunVal :: mult_with( PTR( Val ) v )
{
    throw std::runtime_error( "invalid operation on non-number" );
}

bool FunVal :: is_true()
{
    throw std::runtime_error( "invalid operation on non-number" );
}

void FunVal :: print( std::ostream & stream )
{
    stream << to_expr()->to_string();
}

PTR( Val ) FunVal :: call( PTR( Val ) actual_arg )
{
	return body_m->interp( NEW( ExtendedEnv )( formal_arg_m, actual_arg, env_m ) );
}