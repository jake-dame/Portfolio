/******************************************************************************
 * \brief Catch2 tests for: Expr.cpp, parse.cpp, Val.cpp
 *
 * \file tests.cpp
 * \author Jake Dame
 *****************************************************************************/

#include "catch.h" /* Catch2 testing framework */

#include "Env.h"
#include "Expr.h"
#include "parse.h"
#include "pointers.h"
#include "Val.h"

TEST_CASE( "Properties of Addition/Multiplication" )
{
    SECTION( "Addition" )
    {
        // Associative property
        CHECK(
                ( NEW( Add )( NEW( Add )( NEW( Num )( 4 ), NEW( Num )( 2 ) ), NEW( Num )( 42 ) ) )->interp()->equals(
                        ( NEW( Add )( NEW( Num )( 42 ), NEW( Add )( NEW( Num )( 4 ), NEW( Num )( 2 ) ) ) )->interp() )
        );
        // Commutative property
        CHECK(
                ( NEW( Add )( NEW( Num )( 4 ), NEW( Num )( 2 ) ) )->interp()->equals(
                        ( NEW( Add )( NEW( Num )( 2 ), NEW( Num )( 4 ) ) )->interp() )
        );
        // Identity property
        CHECK( ( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 0 ) ) )->interp()->equals( NEW( NumVal )( 42 ) ) );
    }

    SECTION( "Multiplication" )
    {
        // Associative property
        CHECK(
                ( NEW( Mult )( NEW( Mult )( NEW( Num )( 4 ), NEW( Num )( 2 ) ), NEW( Num )( 42 ) ) )->interp()->equals(
                        ( NEW( Mult )( NEW( Num )( 42 ), NEW( Mult )( NEW( Num )( 4 ), NEW( Num )( 2 ) ) ) )->interp() )
        );
        // Commutative property
        CHECK(
                ( NEW( Mult )( NEW( Num )( 4 ), NEW( Num )( 2 ) ) )->interp()->equals(
                        ( NEW( Mult )( NEW( Num )( 2 ), NEW( Num )( 4 ) ) )->interp() )
        );
        // Distributive property
        CHECK(
                ( ( NEW( Mult )( NEW( Num )( 42 ), NEW( Add )( NEW( Num )( 4 ), NEW( Num )( 2 ) ) ) )->interp() )
                        ->equals(
                                ( NEW( Add )( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 4 ) ),
                                           NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 2 ) ) ) )->interp() )
        );
        CHECK(
                ( NEW( Mult )( NEW( Num )( 42 ), NEW( Add )( NEW( Num )( 4 ), NEW( Num )( -2 ) ) ) )->interp()->equals(
                        ( NEW( Add )( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 4 ) ),
                                   NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( -2 ) ) ) )->interp() ) );
        // Identity property
        CHECK( ( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 1 ) ) )->interp()->equals( NEW( NumVal )( 42 ) ) );
        // Zero property
        CHECK( ( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 0 ) ) )->interp()->equals( NEW( NumVal )( 0 ) ) );
    }
}

TEST_CASE ( "Num class" )
{
    SECTION( "Num::equals()" )
    {
        CHECK( ( NEW( Num )( 0 ) )->equals( NEW( Num )( 0 ) ) );

        CHECK( ( NEW( Num )( 1 ) )->equals( NEW( Num )( 1 ) ) );
        CHECK( ( NEW( Num )( -1 ) )->equals( NEW( Num )( -1 ) ) );

        CHECK( ( NEW( Num )( INT_MAX ) )->equals( NEW( Num )( INT_MAX ) ) );
        CHECK( ( NEW( Num )( INT_MIN ) )->equals( NEW( Num )( INT_MIN ) ) );

        CHECK_FALSE( ( NEW( Num )( 1 ) )->equals( NEW( Num )( -1 ) ) );
    }

    SECTION( "Num::interp()" )
    {
        CHECK( ( NEW( Num )( 0 ) )->interp()->equals( NEW( NumVal )( 0 ) ) );

        CHECK( ( NEW( Num )( 1 ) )->interp()->equals( NEW( NumVal )( 1 ) ) );
        CHECK( ( NEW( Num )( -1 ) )->interp()->equals( NEW( NumVal )( -1 ) ) );

        CHECK( ( NEW( Num )( INT_MIN ) )->interp()->equals( NEW( NumVal )( INT_MIN ) ) );
        CHECK( ( NEW( Num )( INT_MAX ) )->interp()->equals( NEW( NumVal )( INT_MAX ) ) );
    }

    SECTION( "Num::has_variable()" )
    {
        CHECK_FALSE( ( NEW( Num )( 0 ) )->has_variable() );

        CHECK_FALSE( ( NEW( Num )( 1 ) )->has_variable() );
        CHECK_FALSE( ( NEW( Num )( -1 ) )->has_variable() );

        CHECK_FALSE( ( NEW( Num )( INT_MIN ) )->has_variable() );
        CHECK_FALSE( ( NEW( Num )( INT_MAX ) )->has_variable() );
    }

    SECTION( "Num::subst()" )
    {
        CHECK( ( NEW( Num )( 42 ) )->subst( "42", NEW( Num )( 0 ) )->equals( NEW( Num )( 42 ) ) );
        CHECK_FALSE( ( NEW( Num )( 42 ) )->subst( "42", NEW( Num )( 0 ) )->equals( NEW( Num )( 0 ) ) );
    }

    SECTION( "Num::to_string()" )
    {
        CHECK( ( NEW( Num )( 0 ) )->to_string() == "0" );

        CHECK( ( NEW( Num )( 1 ) )->to_string() == "1" );
        CHECK( ( NEW( Num )( -1 ) )->to_string() == "-1" );

        CHECK( ( NEW( Num )( INT_MIN ) )->to_string() == "-2147483648" );
        CHECK( ( NEW( Num )( INT_MAX ) )->to_string() == "2147483647" );

        // This is just to check that Num calls the regular virtual function correctly
        CHECK( ( NEW( Num )( INT_MAX ) )->to_pretty_string() == "2147483647" );
    }
}

TEST_CASE ( "Bool class" )
{
    SECTION( "Bool::equals()" )
    {
        CHECK( ( NEW( Bool )( true ) )->equals( NEW( Bool )( true ) ) );
        CHECK( ( NEW( Bool )( false ) )->equals( NEW( Bool )( false ) ) );

        CHECK_FALSE( ( NEW( Bool )( true ) )->equals( NEW( Bool )( false ) ) );
        CHECK_FALSE( ( NEW( Bool )( false ) )->equals( NEW( Bool )( true ) ) );
    }

    SECTION( "Bool::interp()" )
    {
        CHECK( ( NEW( Bool )( true ) )->interp()->equals( NEW( BoolVal )( true ) ) );
        CHECK( ( NEW( Bool )( false ) )->interp()->equals( NEW( BoolVal )( false ) ) );

        CHECK_FALSE( ( NEW( Bool )( true ) )->interp()->equals( NEW( BoolVal )( false ) ) );
        CHECK_FALSE( ( NEW( Bool )( false ) )->interp()->equals( NEW( BoolVal )( true ) ) );
    }

    SECTION( "Bool::has_variable()" )
    {
        CHECK( ( NEW( Bool )( true ) )->has_variable() != true );
        CHECK( ( NEW( Bool )( false ) )->has_variable() != true );

        CHECK_FALSE( ( NEW( Bool )( true ) )->has_variable() );
        CHECK_FALSE( ( NEW( Bool )( false ) )->has_variable() );
    }

    SECTION( "Bool::subst()" )
    {
        CHECK( ( NEW( Bool )( true ) )->subst( "x", NEW( Bool )( true ) )->equals( NEW( Bool )( true ) ) );
        CHECK( ( NEW( Bool )( false ) )->subst( "x", NEW( Bool )( false ) )->equals( NEW( Bool )( false ) ) );

        CHECK_FALSE( ( NEW( Bool )( true ) )->subst( "x", NEW( Bool )( true ) )->equals( NEW( Bool )( false ) ) );
        CHECK_FALSE( ( NEW( Bool )( false ) )->subst( "x", NEW( Bool )( false ) )->equals( NEW( Bool )( true ) ) );
    }

    SECTION( "Bool::to_string()" )
    {
        CHECK( ( NEW( Bool )( true ) )->to_string() == "_true" );
        CHECK( ( NEW( Bool )( false ) )->to_string() == "_false" );

        // This is just to check that Bool calls the regular virtual function correctly
        CHECK( ( NEW( Bool )( true ) )->to_pretty_string() == "_true" );
        CHECK( ( NEW( Bool )( false ) )->to_pretty_string() == "_false" );
    }
}

TEST_CASE ( "Eq class" )
{
    SECTION ( "Eq::equals()" )
    {
        CHECK( ( NEW( Eq )( NEW( Num )( 0 ), NEW( Num )( 0 ) ) )
                       ->equals( NEW( Eq )( NEW( Num )( 0 ), NEW( Num )( 0 ) ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( 1 ), NEW( Num )( 1 ) ) )
                       ->equals( NEW( Eq )( NEW( Num )( 1 ), NEW( Num )( 1 ) ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( -1 ), NEW( Num )( -1 ) ) )
                       ->equals( NEW( Eq )( NEW( Num )( -1 ), NEW( Num )( -1 ) ) ) );
        CHECK_FALSE( ( NEW( Eq )( NEW( Num )( -1 ), NEW( Num )( -1 ) ) )
                             ->equals( NEW( Eq )( NEW( Num )( 0 ), NEW( Num )( 0 ) ) ) );

        CHECK( ( NEW( Eq )( NEW( Var )( "" ), NEW( Var )( "" ) ) )
                       ->equals( NEW( Eq )( NEW( Var )( "" ), NEW( Var )( "" ) ) ) );
        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Var )( "x" ) ) )
                       ->equals( NEW( Eq )( NEW( Var )( "x" ), NEW( Var )( "x" ) ) ) );
        CHECK_FALSE( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Var )( "x" ) ) )
                             ->equals( NEW( Eq )( NEW( Var )( "X" ), NEW( Var )( "X" ) ) ) );

        CHECK( ( NEW( Eq )( NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "x" ) ), NEW( Mult )( NEW( Bool )( true ), NEW( Bool )( false ) ) ) )
                       ->equals( NEW( Eq )( NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "x" ) ),
                                         NEW( Mult )( NEW( Bool )( true ), NEW( Bool )( false ) ) ) ) );

        CHECK( ( NEW( Eq )( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( -42 ) ) ),
                         NEW( If )( NEW( Eq )( NEW( Var )( "Z" ), NEW( Var )( "Z" ) ), NEW( Num )( 1 ), NEW( Num )( 2 ) ) ) )
                       ->equals( NEW( Eq )( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( -42 ) ) ),
                                         NEW( If )( NEW( Eq )( NEW( Var )( "Z" ), NEW( Var )( "Z" ) ), NEW( Num )( 1 ),
                                                 NEW( Num )( 2 ) ) ) ) );
    }

    SECTION ( "Eq::interp()" )
    {

        /*
         * Annotations are due to the fact that only CHECK is ever used,
         * not CHECK_FALSE. This is to make sure false can be interpreted
         * as a valid BoolVal value, as well as true.
         */

        // TRUE Nums
        CHECK( ( NEW( Eq )( NEW( Num )( 0 ), NEW( Num )( 0 ) ) )->interp()
                       ->equals( NEW( BoolVal )( true ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( 1 ), NEW( Num )( 1 ) ) )->interp()
                       ->equals( NEW( BoolVal )( true ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( -1 ), NEW( Num )( -1 ) ) )->interp()
                       ->equals( NEW( BoolVal )( true ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( INT_MAX ), NEW( Num )( INT_MAX ) ) )->interp()
                       ->equals( NEW( BoolVal )( true ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( INT_MIN ), NEW( Num )( INT_MIN ) ) )->interp()
                       ->equals( NEW( BoolVal )( true ) ) );
        // FALSE Nums
        CHECK( ( NEW( Eq )( NEW( Num )( 1 ), NEW( Num )( 0 ) ) )->interp()
                       ->equals( NEW( BoolVal )( false ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( -1 ), NEW( Num )( 0 ) ) )->interp()
                       ->equals( NEW( BoolVal )( false ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( -1 ), NEW( Num )( 1 ) ) )->interp()
                       ->equals( NEW( BoolVal )( false ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( INT_MAX ), NEW( Num )( INT_MIN ) ) )->interp()
                       ->equals( NEW( BoolVal )( false ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( INT_MIN ), NEW( Num )( INT_MAX ) ) )->interp()
                       ->equals( NEW( BoolVal )( false ) ) );

        // TRUE Bools
        CHECK( ( NEW( Eq )( NEW( Bool )( true ), NEW( Bool )( true ) ) )->interp()
                       ->equals( NEW( BoolVal )( true ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( false ), NEW( Num )( false ) ) )->interp()
                       ->equals( NEW( BoolVal )( true ) ) );
        // FALSE Bools
        CHECK( ( NEW( Eq )( NEW( Bool )( false ), NEW( Bool )( true ) ) )->interp()
                       ->equals( NEW( BoolVal )( false ) ) );
        CHECK( ( NEW( Eq )( NEW( Num )( true ), NEW( Num )( false ) ) )->interp()
                       ->equals( NEW( BoolVal )( false ) ) );

        // FALSE Num and Bool with 0
        CHECK( ( NEW( Eq )( NEW( Num )( 0 ), NEW( Bool )( false ) ) )->interp()
                       ->equals( NEW( BoolVal )( false ) ) );
        // Opposite for good measure
        CHECK_FALSE( ( NEW( Eq )( NEW( Num )( 0 ), NEW( Bool )( false ) ) )->interp()
                             ->equals( NEW( BoolVal )( true ) ) );

        // FALSE Num and Bool with non-zero
        CHECK( ( NEW( Eq )( NEW( Num )( 1 ), NEW( Bool )( true ) ) )->interp()
                       ->equals( NEW( BoolVal )( false ) ) );
        // Opposite for good measure
        CHECK_FALSE( ( NEW( Eq )( NEW( Num )( 1 ), NEW( Bool )( true ) ) )->interp()
                             ->equals( NEW( BoolVal )( true ) ) );

        // TRUE Bool v Bool
        CHECK( ( NEW( Eq )( NEW( Bool )( true ), NEW( Bool )( true ) ) )->interp()->equals( NEW( BoolVal )( true ) ) );
        CHECK( ( NEW( Eq )( NEW( Bool )( false ), NEW( Bool )( false ) ) )->interp()->equals( NEW( BoolVal )( true ) ) );
        // FALSE Bool v Bool
        CHECK( ( NEW( Eq )( NEW( Bool )( true ), NEW( Bool )( false ) ) )->interp()->equals( NEW( BoolVal )( false ) ) );
        CHECK( ( NEW( Eq )( NEW( Bool )( false ), NEW( Bool )( true ) ) )->interp()->equals( NEW( BoolVal )( false ) ) );

        // TRUE Add, Mult
        CHECK( ( NEW( Eq )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                         NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )->interp()->equals( NEW( BoolVal )( true ) ) );
        CHECK( ( NEW( Eq )( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                         NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )->interp()->equals( NEW( BoolVal )( true ) ) );
        // FALSE Add, Mult
        CHECK( ( NEW( Eq )( NEW( Add )( NEW( Num )( 100000 ), NEW( Num )( 42 ) ),
                         NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )->interp()->equals( NEW( BoolVal )( false ) ) );
        CHECK( ( NEW( Eq )( NEW( Mult )( NEW( Num )( 100000 ), NEW( Num )( 42 ) ),
                         NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )->interp()->equals( NEW( BoolVal )( false ) ) );

        // Triple-nested Let
        CHECK( ( NEW( Eq )(

                NEW( Let )( "x", NEW( Num )( 5 ), NEW( Add )(
                        NEW( Let )( "y", NEW( Num )( 3 ), NEW( Add )( NEW( Var )( "y" ),
                                                             NEW( Let )( "z", NEW( Num )( 6 ),
                                                                      NEW( Add )( NEW( Var )( "z" ), NEW( Num )( 8 ) ) ) ) ),
                        NEW( Var )( "x" ) ) ),

                NEW( Let )( "x", NEW( Num )( 5 ), NEW( Add )(
                        NEW( Let )( "y", NEW( Num )( 3 ), NEW( Add )( NEW( Var )( "y" ),
                                                             NEW( Let )( "z", NEW( Num )( 6 ),
                                                                      NEW( Add )( NEW( Var )( "z" ), NEW( Num )( 8 ) ) ) ) ),
                        NEW( Var )( "x" ) ) ) ) )

                       ->interp()->equals( NEW( BoolVal )( true ) ) );
    }

    SECTION ( "Eq::has_variable()" )
    {
        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )->has_variable() );
        CHECK( ( NEW( Eq )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) )->has_variable() );
        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Var )( "x" ) ) )->has_variable() );

        CHECK( ( NEW( Eq )( NEW( Var )( "apple" ), NEW( Num )( 42 ) ) )->has_variable() );
        CHECK( ( NEW( Eq )( NEW( Num )( 42 ), NEW( Var )( "apple" ) ) )->has_variable() );

        CHECK_FALSE( ( NEW( Eq )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )->has_variable() );

        // (((42 + 42) * 42) + (42 * 42)) == (((42 + 42) * 42) + (42 * wildcard))
        CHECK( ( NEW( Eq )( NEW( Add )( NEW( Mult )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Num )( 42 ) ),
                                  NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ),
                         NEW( Add )( NEW( Mult )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Num )( 42 ) ),
                                  NEW( Mult )( NEW( Num )( 42 ), NEW( Var )( "wildcard" ) ) ) ) )->has_variable() );
        // (((42 + 42) * 42) + (42 * 42)) == (((42 + 42) * 42) + (42 * 42))
        CHECK_FALSE( ( NEW( Eq )( NEW( Add )( NEW( Mult )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Num )( 42 ) ),
                                        NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ),
                               NEW( Add )( NEW( Mult )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Num )( 42 ) ),
                                        NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) ) )->has_variable() );
    }

    SECTION ( "Eq::subst()" )
    {
        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )
                       ->subst( "x", NEW( Num )( 42 ) )
                       ->equals( NEW( Eq )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) );

        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )
                       ->subst( "x", NEW( Eq )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )
                       ->equals( NEW( Eq )( NEW( Eq )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Num )( 42 ) ) ) );

        // replace both LHS and RHS when same value
        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Var )( "x" ) ) )
                       ->subst( "x", NEW( Var )( "y" ) )
                       ->equals( NEW( Eq )( NEW( Var )( "y" ), NEW( Var )( "y" ) ) ) );

        // replace selectively when both LHS and RHS are of type Var
        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Var )( "y" ) ) )
                       ->subst( "y", NEW( Var )( "z" ) )
                       ->equals( NEW( Eq )( NEW( Var )( "x" ), NEW( Var )( "z" ) ) ) );

        // replace selectively when !both LHS and RHS are of type Var
        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )
                       ->subst( "x", NEW( Var )( "y" ) )
                       ->equals( NEW( Eq )( NEW( Var )( "y" ), NEW( Num )( 42 ) ) ) );

        CHECK_FALSE( ( NEW( Eq )( NEW( Var )( "apple" ), NEW( Num )( 10 ) ) )
                             ->subst( "x", NEW( Eq )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) )
                             ->equals( NEW( Eq )( NEW( Num )( 10 ), NEW( Eq )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) ) ) );
    }

    SECTION ( "Eq::to_string()" )
    {
        // Nums
        CHECK( ( NEW( Eq )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )->to_string() == "(42==42)" );

        // Vars
        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Var )( "x" ) ) )->to_string() == "(x==x)" );

        // Bools
        CHECK( ( NEW( Eq )( NEW( Bool )( true ), NEW( Bool )( true ) ) )->to_string() == "(_true==_true)" );
        CHECK( ( NEW( Eq )( NEW( Bool )( false ), NEW( Bool )( false ) ) )->to_string() == "(_false==_false)" );
        CHECK( ( NEW( Eq )( NEW( Bool )( true ), NEW( Bool )( false ) ) )->to_string() == "(_true==_false)" );
        CHECK( ( NEW( Eq )( NEW( Bool )( false ), NEW( Bool )( true ) ) )->to_string() == "(_false==_true)" );

        // Num and Bool
        CHECK( ( NEW( Eq )( NEW( Num )( 1 ), NEW( Bool )( true ) ) )->to_string() == "(1==_true)" );

        // Num and Var
        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )->to_string() == "(x==42)" );

        // Add/Mult, Add/Mult with Bools
        CHECK( ( NEW( Eq )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                         NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )->to_string() == "((42+42)==(42+42))" );
        CHECK( ( NEW( Eq )( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                         NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )->to_string() == "((42*42)==(42*42))" );
        CHECK( ( NEW( Eq )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Bool )( true ) ) )->to_string() ==
               "((42+42)==_true)" );
        CHECK( ( NEW( Eq )( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Bool )( true ) ) )->to_string() ==
               "((42*42)==_true)" );

        // Let
        CHECK( ( NEW( Eq )( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Var )( "x" ) ),
                         NEW( Let )( "x", NEW( Num )( 42 ), NEW( Var )( "x" ) ) ) )->to_string() ==
               "((_let x=42 _in x)==(_let x=42 _in x))" );
    }

    SECTION ( "Eq::to_pretty_string()" )
    {
        // Nums
        CHECK( ( NEW( Eq )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )->to_pretty_string() == "42 == 42" );

        // Vars
        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Var )( "x" ) ) )->to_pretty_string() == "x == x" );

        // Bools
        CHECK( ( NEW( Eq )( NEW( Bool )( true ), NEW( Bool )( true ) ) )->to_pretty_string() == "_true == _true" );
        CHECK( ( NEW( Eq )( NEW( Bool )( false ), NEW( Bool )( false ) ) )->to_pretty_string() == "_false == _false" );
        CHECK( ( NEW( Eq )( NEW( Bool )( true ), NEW( Bool )( false ) ) )->to_pretty_string() == "_true == _false" );
        CHECK( ( NEW( Eq )( NEW( Bool )( false ), NEW( Bool )( true ) ) )->to_pretty_string() == "_false == _true" );

        // Num and Bool
        CHECK( ( NEW( Eq )( NEW( Num )( 1 ), NEW( Bool )( true ) ) )->to_pretty_string() == "1 == _true" );

        // Num and Var
        CHECK( ( NEW( Eq )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )->to_pretty_string() == "x == 42" );

        // Add/Mult, Add/Mult with Bools
        CHECK( ( NEW( Eq )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                         NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )->to_pretty_string() == "42 + 42 == 42 + 42" );
        CHECK( ( NEW( Eq )( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                         NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )->to_pretty_string() == "42 * 42 == 42 * 42" );
        CHECK( ( NEW( Eq )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Bool )( true ) ) )->to_pretty_string() ==
               "42 + 42 == _true" );
        CHECK( ( NEW( Eq )( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Bool )( true ) ) )->to_pretty_string() ==
               "42 * 42 == _true" );
    }
}

TEST_CASE ( "Add class" )
{
    SECTION( "Add::equals()" )
    {
        CHECK( ( NEW( Add )( NEW( Num )( 0 ), NEW( Num )( 0 ) ) )
                       ->equals( NEW( Add )( NEW( Num )( 0 ), NEW( Num )( 0 ) ) ) );

        CHECK( ( NEW( Add )( NEW( Num )( 1 ), NEW( Num )( 1 ) ) )
                       ->equals( NEW( Add )( NEW( Num )( 1 ), NEW( Num )( 1 ) ) ) );
        CHECK( ( NEW( Add )( NEW( Num )( -1 ), NEW( Num )( -1 ) ) )
                       ->equals( NEW( Add )( NEW( Num )( -1 ), NEW( Num )( -1 ) ) ) );
        CHECK( ( NEW( Add )( NEW( Num )( 1 ), NEW( Num )( -1 ) ) )
                       ->equals( NEW( Add )( NEW( Num )( 1 ), NEW( Num )( -1 ) ) ) );

        CHECK( ( NEW( Add )( NEW( Num )( 123456789 ), NEW( Num )( 123456789 ) ) )
                       ->equals( NEW( Add )( NEW( Num )( 123456789 ), NEW( Num )( 123456789 ) ) ) );
        CHECK( ( NEW( Add )( NEW( Num )( -123456789 ), NEW( Num )( -123456789 ) ) )
                       ->equals( NEW( Add )( NEW( Num )( -123456789 ), NEW( Num )( -123456789 ) ) ) );
        CHECK( ( NEW( Add )( NEW( Num )( 123456789 ), NEW( Num )( -123456789 ) ) )
                       ->equals( NEW( Add )( NEW( Num )( 123456789 ), NEW( Num )( -123456789 ) ) ) );
    }

    SECTION ( "Add::interp()" )
    {
        CHECK( ( NEW( Add )( NEW( Num )( 0 ), NEW( Num )( 0 ) ) )->interp()->equals( NEW( NumVal )( 0 ) ) );
        CHECK( ( NEW( Add )( NEW( Num )( 0 ), NEW( Num )( 1 ) ) )->interp()->equals( NEW( NumVal )( 1 ) ) );
        CHECK( ( NEW( Add )( NEW( Num )( 0 ), NEW( Num )( -1 ) ) )->interp()->equals( NEW( NumVal )( -1 ) ) );

        CHECK( ( NEW( Add )( NEW( Num )( 1 ), NEW( Num )( 1 ) ) )->interp()->equals( NEW( NumVal )( 2 ) ) );
        CHECK( ( NEW( Add )( NEW( Num )( -1 ), NEW( Num )( -1 ) ) )->interp()->equals( NEW( NumVal )( -2 ) ) );
        CHECK( ( NEW( Add )( NEW( Num )( 1 ), NEW( Num )( -1 ) ) )->interp()->equals( NEW( NumVal )( 0 ) ) );

        CHECK( ( NEW( Add )( NEW( Num )( 123456789 ), NEW( Num )( 123456789 ) ) )->interp()->equals( NEW( NumVal )( 246913578 ) ) );

        CHECK( ( NEW( Add )( NEW( Num )( INT_MAX ), NEW( Num )( -INT_MAX ) ) )->interp()->equals( NEW( NumVal )( 0 ) ) );

        CHECK( ( NEW( Add )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )
                       ->interp()->equals( NEW( NumVal )( 168 ) ) );

        CHECK_THROWS_WITH( ( NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )->interp(), "Var cannot call interp()" );
        CHECK_THROWS_WITH( ( NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) )->interp(), "Var cannot call interp()" );
        CHECK_THROWS_WITH( ( NEW( Add )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                                      NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                                   ->interp(), "Var cannot call interp()" );
    }

    SECTION( "Add::has_variable()")
    {
        CHECK( ( NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )->has_variable() == true );
        CHECK( ( NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) )->has_variable() == true );
        CHECK( ( NEW( Add )( NEW( Var )( "x" ), NEW( Var )( "x" ) ) )->has_variable() == true );

        CHECK( ( NEW( Add )( NEW( Var )( "apple" ), NEW( Num )( 42 ) ) )->has_variable() == true );
        CHECK( ( NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "apple" ) ) )->has_variable() == true );

        CHECK( ( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )->has_variable() == false );
    }

    SECTION( "Add::subst()" )
    {

        CHECK( ( NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )
                       ->subst( "x", NEW( Num )( 42 ) )
                       ->equals( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) == true );

        CHECK( ( NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )
                       ->subst( "x", NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )
                       ->equals( NEW( Add )( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Num )( 42 ) ) ) == true );

        // replace both LHS and RHS when same value
        CHECK( ( NEW( Add )( NEW( Var )( "x" ), NEW( Var )( "x" ) ) )
                       ->subst( "x", NEW( Var )( "y" ) )
                       ->equals( NEW( Add )( NEW( Var )( "y" ), NEW( Var )( "y" ) ) ) == true );

        // replace selectively when both LHS and RHS are of type Var
        CHECK( ( NEW( Add )( NEW( Var )( "x" ), NEW( Var )( "y" ) ) )
                       ->subst( "y", NEW( Var )( "z" ) )
                       ->equals( NEW( Add )( NEW( Var )( "x" ), NEW( Var )( "z" ) ) ) == true );

        // replace selectively when !both LHS and RHS are of type Var
        CHECK( ( NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )
                       ->subst( "x", NEW( Var )( "y" ) )
                       ->equals( NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 42 ) ) ) == true );

        CHECK( ( NEW( Add )( NEW( Var )( "apple" ), NEW( Num )( 10 ) ) )
                       ->subst( "x", NEW( Add )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) )
                       ->equals( NEW( Add )( NEW( Num )( 10 ), NEW( Add )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) ) ) == false );
    }

    SECTION( "Add::to_string()" )
    {
        CHECK( ( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )->to_string() == "(42+42)" );
        CHECK( ( NEW( Add )( NEW( Num )( -42 ), NEW( Num )( -42 ) ) )->to_string() == "(-42+-42)" );

        CHECK( ( NEW( Add )( NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "x" ) ), NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) ) )
                       ->to_string() == "((42+x)+(42+x))" );
        CHECK( ( NEW( Add )( NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_string() == "((x+42)+(x+42))" );

        CHECK( ( NEW( Add )( NEW( Add )( NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ),
                          NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_string() == "(((x+42)+(x+42))+(x+42))" );
    }

    SECTION ( "Add::to_pretty_string()" )
    {
        CHECK( ( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )->to_pretty_string() == "42 + 42" );
        CHECK( ( NEW( Add )( NEW( Num )( -42 ), NEW( Num )( -42 ) ) )->to_pretty_string() == "-42 + -42" );

        CHECK( ( NEW( Add )( NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "x" ) ), NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) ) )
                       ->to_pretty_string() == "(42 + x) + 42 + x" );

        CHECK( ( NEW( Add )( NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_pretty_string() == "(x + 42) + x + 42" );

        CHECK( ( NEW( Add )( NEW( Add )( NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ),
                          NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_pretty_string() == "((x + 42) + x + 42) + x + 42" );
    }
}

TEST_CASE ( "Mult class" )
{
    SECTION( "Mult::equals()" )
    {
        CHECK( ( NEW( Mult )( NEW( Num )( 0 ), NEW( Num )( 0 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( 0 ), NEW( Num )( 0 ) ) ) == true );

        CHECK( ( NEW( Mult )( NEW( Num )( 1 ), NEW( Num )( 1 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( 1 ), NEW( Num )( 1 ) ) ) == true );
        CHECK( ( NEW( Mult )( NEW( Num )( -1 ), NEW( Num )( -1 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( -1 ), NEW( Num )( -1 ) ) ) == true );
        CHECK( ( NEW( Mult )( NEW( Num )( 1 ), NEW( Num )( -1 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( 1 ), NEW( Num )( -1 ) ) ) == true );

        CHECK( ( NEW( Mult )( NEW( Num )( 123456789 ), NEW( Num )( 123456789 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( 123456789 ), NEW( Num )( 123456789 ) ) ) == true );
        CHECK( ( NEW( Mult )( NEW( Num )( -123456789 ), NEW( Num )( -123456789 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( -123456789 ), NEW( Num )( -123456789 ) ) ) == true );
        CHECK( ( NEW( Mult )( NEW( Num )( 123456789 ), NEW( Num )( -123456789 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( 123456789 ), NEW( Num )( -123456789 ) ) ) == true );
    }

    SECTION ( "Mult::interp()" )
    {
        CHECK( ( NEW( Mult )( NEW( Num )( 0 ), NEW( Num )( 0 ) ) )->interp()->equals( NEW( NumVal )( 0 ) ) );
        CHECK( ( NEW( Mult )( NEW( Num )( 0 ), NEW( Num )( 1 ) ) )->interp()->equals( NEW( NumVal )( 0 ) ) );
        CHECK( ( NEW( Mult )( NEW( Num )( 0 ), NEW( Num )( -1 ) ) )->interp()->equals( NEW( NumVal )( 0 ) ) );

        CHECK( ( NEW( Mult )( NEW( Num )( 1 ), NEW( Num )( 1 ) ) )->interp()->equals( NEW( NumVal )( 1 ) ) );
        CHECK( ( NEW( Mult )( NEW( Num )( -1 ), NEW( Num )( -1 ) ) )->interp()->equals( NEW( NumVal )( 1 ) ) );
        CHECK( ( NEW( Mult )( NEW( Num )( 1 ), NEW( Num )( -1 ) ) )->interp()->equals( NEW( NumVal )( -1 ) ) );

        CHECK( ( NEW( Mult )( NEW( Num )( 100000 ), NEW( Num )( -10 ) ) )->interp()->equals( NEW( NumVal )( -1000000 ) ) );

        CHECK( ( NEW( Mult )( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )
                       ->interp()->equals( NEW( NumVal )( 3111696 ) ) );

        CHECK_THROWS_WITH( ( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )->interp(), "Var cannot call interp()" );
        CHECK_THROWS_WITH( ( NEW( Mult )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) )->interp(), "Var cannot call interp()" );
        CHECK_THROWS_WITH( ( NEW( Mult )( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                                      NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                                   ->interp(), "Var cannot call interp()" );
    }

    SECTION( "Mult::has_variable()")
    {
        CHECK( ( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )->has_variable() == true );
        CHECK( ( NEW( Mult )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) )->has_variable() == true );
        CHECK( ( NEW( Mult )( NEW( Var )( "x" ), NEW( Var )( "x" ) ) )->has_variable() == true );

        CHECK( ( NEW( Mult )( NEW( Var )( "apple" ), NEW( Num )( 42 ) ) )->has_variable() == true );
        CHECK( ( NEW( Mult )( NEW( Num )( 42 ), NEW( Var )( "apple" ) ) )->has_variable() == true );

        CHECK( ( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )->has_variable() == false );
    }

    SECTION( "Mult::subst()" )
    {

        CHECK( ( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )
                       ->subst( "x", NEW( Num )( 42 ) )
                       ->equals( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) == true );

        CHECK( ( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )
                       ->subst( "x", NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )
                       ->equals( NEW( Mult )( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Num )( 42 ) ) ) == true );

        // replace both LHS and RHS when same value
        CHECK( ( NEW( Mult )( NEW( Var )( "x" ), NEW( Var )( "x" ) ) )
                       ->subst( "x", NEW( Var )( "y" ) )
                       ->equals( NEW( Mult )( NEW( Var )( "y" ), NEW( Var )( "y" ) ) ) == true );

        // replace selectively when both LHS and RHS are of type Var
        CHECK( ( NEW( Mult )( NEW( Var )( "x" ), NEW( Var )( "y" ) ) )
                       ->subst( "y", NEW( Var )( "z" ) )
                       ->equals( NEW( Mult )( NEW( Var )( "x" ), NEW( Var )( "z" ) ) ) == true );

        // replace selectively when !both LHS and RHS are of type Var
        CHECK( ( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) )
                       ->subst( "x", NEW( Var )( "y" ) )
                       ->equals( NEW( Mult )( NEW( Var )( "y" ), NEW( Num )( 42 ) ) ) == true );

        CHECK( ( NEW( Mult )( NEW( Var )( "apple" ), NEW( Num )( 10 ) ) )
                       ->subst( "x", NEW( Mult )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( 10 ), NEW( Mult )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) ) ) == false );
    }

    SECTION( "Mult::to_string()" )
    {
        CHECK( ( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )->to_string() == "(42*42)" );
        CHECK( ( NEW( Mult )( NEW( Num )( -42 ), NEW( Num )( -42 ) ) )->to_string() == "(-42*-42)" );

        CHECK( ( NEW( Mult )( NEW( Mult )( NEW( Num )( 42 ), NEW( Var )( "x" ) ), NEW( Mult )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) ) )
                       ->to_string() == "((42*x)*(42*x))" );
        CHECK( ( NEW( Mult )( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_string() == "((x*42)*(x*42))" );

        CHECK( ( NEW( Mult )(
                NEW( Mult )( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ),
                NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_string() == "(((x*42)*(x*42))*(x*42))" );
    }

    SECTION ( "Mult::to_pretty_string()" )
    {
        CHECK( ( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) )->to_pretty_string() == "42 * 42" );
        CHECK( ( NEW( Mult )( NEW( Num )( -42 ), NEW( Num )( -42 ) ) )->to_pretty_string() == "-42 * -42" );

        CHECK( ( NEW( Mult )( NEW( Mult )( NEW( Num )( 42 ), NEW( Var )( "x" ) ), NEW( Mult )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) ) )
                       ->to_pretty_string() == "(42 * x) * 42 * x" );

        CHECK( ( NEW( Mult )( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_pretty_string() == "(x * 42) * x * 42" );

        CHECK( ( NEW( Mult )(
                NEW( Mult )( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ),
                NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_pretty_string() == "((x * 42) * x * 42) * x * 42" );

        // Debugging-necessitated test 3/7/24
        CHECK( ( NEW( Mult )( NEW( Num )( 123456789 ), NEW( Let )( "abcdefghijklmnop", NEW( Num )( 123456789 ), NEW( Let )( "y", NEW( Num )( 21 ), NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 42 ) ) ) ) ) )

        ->to_pretty_string() ==

        "123456789 * (_let abcdefghijklmnop = 123456789\n"
        "             _in  _let y = 21\n"
        "                  _in  y + 42)"
             );

        // Debugging-necessitated test 3/7/24
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Mult )( NEW( Num )( -1234567890 ), NEW( Let )( "y" , NEW( Num )( 84 ), NEW( Var )( "y" ) ) ) ) )
        ->to_pretty_string() ==

        "_let x = 42\n"
        "_in  -1234567890 * (_let y = 84\n"
        "                    _in  y)"

        );


    }
}

TEST_CASE ( "Var class" )
{
    SECTION( "Var::equals()" )
    {
        CHECK( ( NEW( Var )( "" ) )->equals( NEW( Var )( "" ) ) == true );

        CHECK( ( NEW( Var )( "c" ) )->equals( NEW( Var )( "c" ) ) == true );
        CHECK( ( NEW( Var )( "C" ) )->equals( NEW( Var )( "C" ) ) == true );

        CHECK( ( NEW( Var )( "cat" ) )->equals( NEW( Var )( "cat" ) ) == true );
        CHECK( ( NEW( Var )( "CAT" ) )->equals( NEW( Var )( "CAT" ) ) == true );
        CHECK( ( NEW( Var )( "racecar" ) )->equals( NEW( Var )( "racecar" ) ) == true );

        CHECK( ( NEW( Var )( "" ) )->equals( NEW( Var )( "c" ) ) == false );
        CHECK( ( NEW( Var )( "c" ) )->equals( NEW( Var )( "" ) ) == false );
        CHECK( ( NEW( Var )( "C" ) )->equals( NEW( Var )( "c" ) ) == false );
        CHECK( ( NEW( Var )( "c" ) )->equals( NEW( Var )( "C" ) ) == false );
        CHECK( ( NEW( Var )( "cat" ) )->equals( NEW( Num )( 42 ) ) == false );
        CHECK( ( NEW( Var )( "cat" ) )->equals( nullptr ) == false );
    }

    SECTION( "Var::interp()" )
    {
        CHECK_THROWS_WITH( ( NEW( Var )( "x" ) )->interp(), "Var cannot call interp()" );
    }


    SECTION( "Var::has_variable()")
    {
        CHECK( ( NEW( Var )( "x" ) )->has_variable() == true );
    }

    SECTION( "Var::subst()" )
    {
        CHECK( ( NEW( Var )( "a" ) )->subst( "a", NEW( Num )( 42 ) )->equals( NEW( Num )( 42 ) ) == true );

        CHECK( ( NEW( Var )( "a" ) )->subst( "a", NEW( Var )( "a" ) )->equals( NEW( Var )( "a" ) ) == true );

        CHECK( ( NEW( Var )( "a" ) )->subst( "a", NEW( Add )( NEW( Var )( "a" ), NEW( Num )( 7 ) ) )
                       ->equals( NEW( Add )( NEW( Var )( "a" ), NEW( Num )( 7 ) ) ) == true );

        CHECK( ( NEW( Var )( "a" ) )->subst( "a", NEW( Mult )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) ) == true );

        CHECK( ( NEW( Var )( "a" ) )->subst( "a", NEW( Add )( NEW( Var )( "a" ), NEW( Var )( "a" ) ) )
                       ->equals( NEW( Add )( NEW( Var )( "a" ), NEW( Var )( "a" ) ) ) == true );

        CHECK( ( NEW( Var )( "a" ) )->subst( "A", NEW( Mult )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) ) == false );
        CHECK( ( NEW( Var )( "a" ) )->subst( "", NEW( Mult )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) ) == false );
        CHECK( ( NEW( Var )( "" ) )->subst( "a", NEW( Mult )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) )
                       ->equals( NEW( Mult )( NEW( Num )( 7 ), NEW( Num )( 3 ) ) ) == false );
    }

    SECTION ( "Var::to_string()" )
    {
        CHECK( ( NEW( Var )( "" ) )->to_string().empty() );

        CHECK( ( NEW( Var )( "a" ) )->to_string() == "a" );
        CHECK( ( NEW( Var )( "A" ) )->to_string() == "A" );

        CHECK( ( NEW( Var )( "apple" ) )->to_string() == "apple" );
        CHECK( ( NEW( Var )( "APPLE" ) )->to_string() == "APPLE" );
        CHECK( ( NEW( Var )( "Apple" ) )->to_string() == "Apple" );

        CHECK( !( NEW( Var )( "a" ) )->to_string().empty() );
        CHECK( ( NEW( Var )( "A" ) )->to_string() != "a" );
        CHECK( ( NEW( Var )( "a" ) )->to_string() != "A" );

        CHECK( ( NEW( Var )( "apple" ) )->to_string() != "APPLE" );
        CHECK( ( NEW( Var )( "APPLE" ) )->to_string() != "apple" );
        CHECK( ( NEW( Var )( "Apple" ) )->to_string() != "apple" );
    }
}

TEST_CASE( "Let class" )
{
    SECTION( "Let::equals()" )
    {
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Var )( "x" ) ) )
                       ->equals( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Var )( "x" ) ) ) );

        // let with Add
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->equals( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) ) );
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) ) )
                       ->equals( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) ) ) );

        // let with Mult
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->equals( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) ) == true );
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Mult )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) ) )
                       ->equals( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Mult )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) ) ) == true );

        // let with triple-nested expression "_let x = 42 _in ((x * 42) * x * 42) + x * 42
        CHECK( ( NEW( Let ) ( "x", NEW( Num )( 42), NEW( Add )(
                NEW( Mult )( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ),
                NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) ) )
                ->equals(NEW( Let ) ( "x", NEW( Num )( 42), NEW( Add )(
                NEW( Mult )( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ),
                NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) ) ) );
    }

    SECTION( "Let::has_variable()" )
    {
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->has_variable() == true );
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "x" ) ) ) )
                       ->has_variable() == true );

        // as RHS
        CHECK( ( NEW( Let )( "x", NEW( Var )( "y" ), NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42) ) ) )
                       ->has_variable() == true );

        // variable nested in RHS
        CHECK( ( NEW( Let )( "x", NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 42 ) ), NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )
                       ->has_variable() == true );

        // variable nested in body
        CHECK( ( NEW( Let )( "x", NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ), NEW( Mult )( NEW( Var )( "y" ), NEW( Num )( 42 ) ) ) )
                       ->has_variable() == true );

        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) )
                       ->has_variable() == false );
    }

    SECTION( "Let::interp()" )
    {
        // Var as body
        CHECK( ( NEW( Let )( "x", NEW( Add )( NEW( Num )(2), NEW( Num )(40) ), NEW( Var )( "x" ) ) )
                       ->interp()->equals( NEW( NumVal )( 42 ) ) );
        // Add as body
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->interp()->equals( NEW( NumVal )( 84 ) ) );
        // Mult as body
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->interp()->equals( NEW( NumVal )( 1764 ) ) );
        // Var as RHS
        CHECK_THROWS_WITH(
                ( NEW( Let )( "x", NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 42 ) ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                        ->interp(), "Var cannot call interp()" );
        // Add as RHS
        CHECK( ( NEW( Let )( "x", NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                          NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )->interp()->equals( NEW( NumVal )( 3528 ) ) );
        // Mult as RHS
        CHECK( ( NEW( Let )( "x", NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                          NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )->interp()->equals( NEW( NumVal )( 1806 ) ) );
        // Let as RHS "_let x=(_let y=5 _in y+6) _in x+7"
        CHECK( ( NEW( Let )( "x",
                          NEW( Let )( "y", NEW( Num )( 5 ), NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 6 ) ) ),
                          NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 7 ) ) ) )
                       ->interp()->equals( NEW( NumVal )( 18 ) ) );

        // triple-nested Let "_let x = 5 _in  (_let y = 3 _in  y + _let z = 6 _in  z + 8) + x" (22<-17<-14)
        CHECK( (NEW( Let )( "x", NEW( Num )( 5 ), NEW( Add )(
                    NEW( Let )( "y", NEW( Num )( 3 ), NEW( Add )( NEW( Var )( "y" ),
                                                         NEW( Let )( "z", NEW( Num )( 6 ),
                                                                  NEW( Add )( NEW( Var )( "z" ), NEW( Num )( 8 ) ) ) ) ),
                NEW( Var )( "x" ) ) ) )->interp()->equals( NEW( NumVal )( 22 ) ) );
    }

    SECTION( "Let::to_string()" )
    {
        // Var as body
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Var )( "x" ) ) )
                       ->to_string() == "(_let x=42 _in x)" );
        // Add as body
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_string() == "(_let x=42 _in (x+42))" );
        // Mult as body
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_string() == "(_let x=42 _in (x*42))" );
        // Add as RHS
        CHECK( ( NEW( Let )( "x", NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                          NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )->to_string() == "(_let x=(42+42) _in (x*42))" );
        // Mult as RHS
        CHECK( ( NEW( Let )( "x", NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                          NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )->to_string() == "(_let x=(42*42) _in (x+42))" );
        // Let as RHS
        CHECK( (    NEW( Let )( "x", NEW( Num )( 5 ), NEW( Add )(
                NEW( Let )( "y", NEW( Num )( 3 ), NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 2 ) ) ),
                NEW( Var )( "x" ) ) ) )
                       ->to_string() == "(_let x=5 _in ((_let y=3 _in (y+2))+x))" );

        // triple-nested Let "_let x = 5 _in  (_let y = 3 _in  y + _let z = 6 _in  z + 8) + x" (22<-17<-14)
        CHECK( (NEW( Let )( "x", NEW( Num )( 5 ), NEW( Add )(
                    NEW( Let )( "y", NEW( Num )( 3 ), NEW( Add )( NEW( Var )( "y" ),
                                                         NEW( Let )( "z", NEW( Num )( 6 ),
                                                                  NEW( Add )( NEW( Var )( "z" ), NEW( Num )( 8 ) ) ) ) ),
                NEW( Var )( "x" ) ) ) )->to_string() == "(_let x=5 _in ((_let y=3 _in (y+(_let z=6 _in (z+8))))+x))" );
    }

    SECTION( "_let::to_pretty_string()" )
    {
        // Var as body
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Var )( "x" ) ) )
                       ->to_pretty_string() == "_let x = 42\n"
                                               "_in  x" );
        // Add as body
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_pretty_string() == "_let x = 42\n"
                                               "_in  x + 42" );
        // Mult as body
        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )
                       ->to_pretty_string() == "_let x = 42\n"
                                               "_in  x * 42" );
        // Add as RHS
        CHECK( ( NEW( Let )( "x", NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                          NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )->to_pretty_string() == "_let x = 42 + 42\n"
                                                                                               "_in  x * 42" );
        // Mult as RHS
        CHECK( ( NEW( Let )( "x", NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                          NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) )->to_pretty_string() == "_let x = 42 * 42\n"
                                                                                              "_in  x + 42" );
        // Let as RHS "_let x = _let y = 5 _in y+6 _in x+7"
        CHECK( (NEW( Let )( "x",
                         NEW( Let )( "y", NEW( Num )( 5 ), NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 6 ) ) ),
                         NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 7 ) ) ) )
                       ->to_pretty_string() == "_let x = _let y = 5\n"
                                               "         _in  y + 6\n"
                                               "_in  x + 7" );

        // double-nested Let
        CHECK( (NEW( Let )( "x", NEW( Num )( 5 ), NEW( Add )(
                    NEW( Let )( "y", NEW( Num )( 3 ), NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 2 ) ) ),
                NEW( Var )( "x" ) ) ) )
                       ->to_pretty_string() == "_let x = 5\n"
                                               "_in  (_let y = 3\n"
                                               "      _in  y + 2) + x" );

        // triple-nested Let
        CHECK( (NEW( Let )( "x", NEW( Num )( 5 ), NEW( Add )(
                    NEW( Let )( "y", NEW( Num )( 3 ), NEW( Add )( NEW( Var )( "y" ),
                                                         NEW( Let )( "z", NEW( Num )( 6 ),
                                                                  NEW( Add )( NEW( Var )( "z" ), NEW( Num )( 8 ) ) ) ) ),
                NEW( Var )( "x" ) ) ) )
                       ->to_pretty_string() == "_let x = 5\n"
                                               "_in  (_let y = 3\n"
                                               "      _in  y + _let z = 6\n"
                                               "               _in  z + 8) + x" );
    }
}

TEST_CASE ( "If class" )
{
    SECTION ( "If::equals()" )
    {
        CHECK( ( NEW( If )( NEW( Eq )( NEW( Var )("x"), NEW( Num )(42)), NEW( Num )(43), NEW( Num )(44) ) )
        ->equals(NEW( If )( NEW( Eq )( NEW( Var )("x"), NEW( Num )(42)), NEW( Num )(43), NEW( Num )(44) ) ) );

        CHECK_FALSE( ( NEW( If )( NEW( Eq )( NEW( Var )("x"), NEW( Num )(42)), NEW( Num )(43), NEW( Num )(1000000) ) )
              ->equals(NEW( If )( NEW( Eq )( NEW( Var )("x"), NEW( Num )(42)), NEW( Num )(43), NEW( Num )(44) ) ) );
    }

    SECTION ( "If::interp()" )
    {
        // check then_m is returned correctly
        CHECK( ( NEW( If )( NEW( Eq )( NEW( Num )(42), NEW( Num )(42) ), NEW( Num )(1), NEW( Num )(-1) ) )->interp()->equals( NEW( NumVal )(1) ) );
        CHECK_FALSE( ( NEW( If )( NEW( Eq )( NEW( Num )(0), NEW( Num )(1000) ), NEW( Num )(1), NEW( Num )(-1) ) )->interp()->equals( NEW( NumVal )(1) ) );

        // check else_m is returned correctly
        CHECK( ( NEW( If )( NEW( Eq )( NEW( Num )(0), NEW( Num )(1000) ), NEW( Num )(1), NEW( Num )(-1) ) )->interp()->equals( NEW( NumVal )(-1) ) );
        CHECK_FALSE( ( NEW( If )( NEW( Eq )( NEW( Num )(42), NEW( Num )(42) ), NEW( Num )(1), NEW( Num )(-1) ) )->interp()->equals( NEW( NumVal )(-1) ) );

        CHECK_THROWS_WITH( ( NEW( If )( NEW( Num )(42), NEW( Var )("X"), NEW( Var )("Y") ) )->interp()->equals( NEW( NumVal )(-1) ), "cannot call is_true on NumVal" );
    }

    SECTION ( "If::has_variable()" )
    {
        // check test_m
        CHECK( ( NEW( If )( NEW( Eq )( NEW( Var )("x"), NEW( Num )(42) ), NEW( Num )(42), NEW( Num )(42) )  )->has_variable() );

        // check then_m
        CHECK( ( NEW( If )( NEW( Eq )( NEW( Num )(42), NEW( Num )(42) ), NEW( Var )("x"), NEW( Num )(42) )  )->has_variable() );

        // check else_m
        CHECK( ( NEW( If )( NEW( Eq )( NEW( Num )(42), NEW( Num )(42) ), NEW( Num )(42), NEW( Var )("x") )  )->has_variable() );

        // FALSE
        CHECK_FALSE( ( NEW( If )( NEW( Eq )( NEW( Num )(42), NEW( Num )(42) ), NEW( Num )(42), NEW( Num )(42) )  )->has_variable() );
    }

    SECTION ( "If::subst()" )
    {
        // check test_m and then_m
        CHECK( ( NEW( If )( NEW( Eq )( NEW( Var )("x"), NEW( Var )("x") ), NEW( Var )("x"), NEW( Var )("no") ) )->subst("x", NEW( Num )(42) )->interp()->equals( NEW( NumVal )(42) ) );

        // check else_m
        CHECK( ( NEW( If )( NEW( Eq )( NEW( Var )("x"), NEW( Num )(-1) ), NEW( Var )("no"), NEW( Var )("x") ) )->subst("x", NEW( Num )(42) )->interp()->equals( NEW( NumVal )(42) ) );

        // FALSE
        CHECK_FALSE( ( NEW( If )( NEW( Eq )( NEW( Var )("x"), NEW( Num )(-1) ), NEW( Var )("no"), NEW( Var )("x") ) )->subst("x", NEW( Num )(42) )->interp()->equals( NEW( NumVal )(-1) ) );
    }

    SECTION ( "If::to_string()" )
    {
        CHECK( ( NEW( If )( NEW( Eq )( NEW( Var )( "x" ), NEW( Num )( 3 ) ),
                         NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                         NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 0 ) ) ) )
                         ->to_string() ==
                                            "(_if (x==3) _then (42*42) _else (x+0))"
        );
    }

    SECTION ( "If::to_pretty_string()" )
    {
        CHECK( ( NEW( If )( NEW( Eq )( NEW( Var )( "x" ), NEW( Num )( 3 ) ),
                         NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                         NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 0 ) ) ) )
                         ->to_pretty_string() ==
                                                   "_if   x == 3\n"
                                                   "_then 42 * 42\n"
                                                   "_else x + 0"
        );

        CHECK( ( NEW( Let )( "x", NEW( Num )( 42 ), NEW( If )( NEW( Eq )( NEW( Var )( "x" ), NEW( Num )( 3 ) ),
                                                      NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ),
                                                      NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 0 ) ) ) ) )
                                                      ->to_pretty_string() ==
                                                                               "_let x = 42\n"
                                                                               "_in  _if   x == 3\n"
                                                                               "     _then 42 * 42\n"
                                                                               "     _else x + 0"
        );
    }
}

TEST_CASE ( "NumVal class" )
{
    SECTION( "NumVal::to_expr()" )
    {
        // Expr::equals()
        CHECK( ( NEW( NumVal )( 0 ) )->to_expr()->equals( NEW( Num )( 0 ) ) );

        CHECK( ( NEW( NumVal )( 1 ) )->to_expr()->equals( NEW( Num )( 1 ) ) );
        CHECK( ( NEW( NumVal )( -1 ) )->to_expr()->equals( NEW( Num )( -1 ) ) );

        CHECK( ( NEW( NumVal )( INT_MAX ) )->to_expr()->equals( NEW( Num )( INT_MAX ) ) );
        CHECK( ( NEW( NumVal )( INT_MIN ) )->to_expr()->equals( NEW( Num )( INT_MIN ) ) );

        CHECK_FALSE( ( NEW( NumVal )( 1 ) )->to_expr()->equals( NEW( Num )( -1 ) ) );
    }

    SECTION( "NumVal::equals()" )
    {
        CHECK( ( NEW( NumVal )( 0 ) )->equals( NEW( NumVal )( 0 ) ) );

        CHECK( ( NEW( NumVal )( 1 ) )->equals( NEW( NumVal )( 1 ) ) );
        CHECK( ( NEW( NumVal )( -1 ) )->equals( NEW( NumVal )( -1 ) ) );

        CHECK( ( NEW( NumVal )( INT_MAX ) )->equals( NEW( NumVal )( INT_MAX ) ) );
        CHECK( ( NEW( NumVal )( INT_MIN ) )->equals( NEW( NumVal )( INT_MIN ) ) );

        CHECK_FALSE( ( NEW( NumVal )( 1 ) )->equals( NEW( NumVal )( -1 ) ) );
    }

    SECTION( "NumVal::add_to()" )
    {
        CHECK( ( NEW( NumVal )( 0 ) )->add_to( NEW( NumVal )( 0 ) )->equals( NEW( NumVal )( 0 ) ) );
        CHECK( ( NEW( NumVal )( 0 ) )->add_to( NEW( NumVal )( 1 ) )->equals( NEW( NumVal )( 1 ) ) );
        CHECK( ( NEW( NumVal )( 0 ) )->add_to( NEW( NumVal )( -1 ) )->equals( NEW( NumVal )( -1 ) ) );

        CHECK( ( NEW( NumVal )( 1 ) )->add_to( NEW( NumVal )( 1 ) )->equals( NEW( NumVal )( 2 ) ) );
        CHECK( ( NEW( NumVal )( -1 ) )->add_to( NEW( NumVal )( -1 ) )->equals( NEW( NumVal )( -2 ) ) );
        CHECK( ( NEW( NumVal )( 1 ) )->add_to( NEW( NumVal )( -1 ) )->equals( NEW( NumVal )( 0 ) ) );

        CHECK( ( NEW( NumVal )( 123456789 ) )->add_to( NEW( NumVal )( 123456789 ) )->equals( NEW( NumVal )( 246913578 ) ) );

        CHECK( ( NEW( NumVal )( INT_MAX ) )->add_to( NEW( NumVal )( -INT_MAX ) )->equals( NEW( NumVal )( 0 ) ) );

        CHECK( ( ( NEW( NumVal )( 42 ) )->add_to( NEW( NumVal )( 42 ) )->add_to( NEW( NumVal )(42) ) )->equals( NEW( NumVal )( 126 ) ) );

        CHECK_THROWS_WITH( ( NEW( NumVal )( -1 ) )->add_to( NEW( BoolVal )( true ) ), "invalid operation on non-number" );
        CHECK_THROWS_WITH( ( NEW( NumVal )( 0 ) )->add_to( NEW( BoolVal )( true ) ), "invalid operation on non-number" );
        CHECK_THROWS_WITH( ( NEW( NumVal )( 1 ) )->add_to( NEW( BoolVal )( true ) ), "invalid operation on non-number" );
    }

    SECTION( "NumVal::mult_with()" )
    {
        CHECK( ( NEW( NumVal )( 0 ) )->mult_with( NEW( NumVal )( 0 ) )->equals( NEW( NumVal )( 0 ) ) );
        CHECK( ( NEW( NumVal )( 0 ) )->mult_with( NEW( NumVal )( 1 ) )->equals( NEW( NumVal )( 0 ) ) );
        CHECK( ( NEW( NumVal )( 0 ) )->mult_with( NEW( NumVal )( -1 ) )->equals( NEW( NumVal )( 0 ) ) );

        CHECK( ( NEW( NumVal )( 1 ) )->mult_with( NEW( NumVal )( 1 ) )->equals( NEW( NumVal )( 1 ) ) );
        CHECK( ( NEW( NumVal )( -1 ) )->mult_with( NEW( NumVal )( -1 ) )->equals( NEW( NumVal )( 1 ) ) );
        CHECK( ( NEW( NumVal )( 1 ) )->mult_with( NEW( NumVal )( -1 ) )->equals( NEW( NumVal )( -1 ) ) );

        CHECK( ( NEW( NumVal )( 100000 ) )->mult_with( NEW( NumVal )( -10 ) )->equals( NEW( NumVal )( -1000000 ) ) );

        CHECK( ( ( NEW( NumVal )( 42 ) )->mult_with( NEW( NumVal )( 42 ) )->mult_with( NEW( NumVal )(42) ) )->equals( NEW( NumVal )( 74088 ) ) );

        CHECK_THROWS_WITH( ( NEW( NumVal )( -1 ) )->mult_with( NEW( BoolVal )( true ) ), "invalid operation on non-number" );
        CHECK_THROWS_WITH( ( NEW( NumVal )( 0 ) )->mult_with( NEW( BoolVal )( true ) ), "invalid operation on non-number" );
        CHECK_THROWS_WITH( ( NEW( NumVal )( 1 ) )->mult_with( NEW( BoolVal )( true ) ), "invalid operation on non-number" );
    }

    SECTION( "NumVal::is_true()" )
    {
        CHECK_THROWS_WITH( ( NEW( NumVal )( 0 ) )->is_true(), "cannot call is_true on NumVal" );

        CHECK_THROWS_WITH( ( NEW( NumVal )( 1 ) )->is_true(), "cannot call is_true on NumVal" );
        CHECK_THROWS_WITH( ( NEW( NumVal )( -1 ) )->is_true(), "cannot call is_true on NumVal" );

        CHECK_THROWS_WITH( ( NEW( NumVal )( INT_MIN ) )->is_true(), "cannot call is_true on NumVal" );
        CHECK_THROWS_WITH( ( NEW( NumVal )( INT_MAX ) )->is_true(), "cannot call is_true on NumVal" );
    }

    SECTION( "NumVal::to_string()" )
    {
        CHECK( ( NEW( NumVal )( 0 ) )->to_string() == "0" );

        CHECK( ( NEW( NumVal )( 1 ) )->to_string() == "1" );
        CHECK( ( NEW( NumVal )( -1 ) )->to_string() == "-1" );

        CHECK( ( NEW( NumVal )( INT_MAX ) )->to_string() == "2147483647" );
        CHECK( ( NEW( NumVal )( INT_MIN ) )->to_string() == "-2147483648" );
    }

    SECTION( "NumVal::call()" )
    {
        CHECK_THROWS_WITH( ( NEW( NumVal )(42) )
                         ->call( NEW( NumVal )(42) ), "cannot use call() on this type" );
    }
}

TEST_CASE ( "BoolVal class" )
{
    SECTION( "BoolVal::to_expr()" )
    {
        // Expr::equals()
        CHECK( ( NEW( BoolVal )( true ) )->to_expr()->equals( NEW( Bool )( true ) ) );
        CHECK( ( NEW( BoolVal )( false ) )->to_expr()->equals( NEW( Bool )( false ) ) );

        CHECK_FALSE( ( NEW( BoolVal )( true ) )->to_expr()->equals( NEW( Bool )( false ) ) );
        CHECK_FALSE( ( NEW( BoolVal )( false ) )->to_expr()->equals( NEW( Bool )( true ) ) );

        CHECK_FALSE( ( NEW( BoolVal )( true ) )->to_expr()->equals( nullptr ) );
        CHECK_FALSE( ( NEW( BoolVal )( false ) )->to_expr()->equals( nullptr ) );
    }

    SECTION( "BoolVal::equals()" )
    {
        CHECK( ( NEW( BoolVal )( true ) )->equals( NEW( BoolVal )( true ) ) );
        CHECK( ( NEW( BoolVal )( false ) )->equals( NEW( BoolVal )( false ) ) );

        CHECK_FALSE( ( NEW( BoolVal )( true ) )->equals( NEW( BoolVal )( false ) ) );
        CHECK_FALSE( ( NEW( BoolVal )( false ) )->equals( NEW( BoolVal )( true ) ) );

        CHECK_FALSE( ( NEW( BoolVal )( true ) )->equals( nullptr ) );
        CHECK_FALSE( ( NEW( BoolVal )( false ) )->equals( nullptr ) );
    }

    SECTION( "BoolVal::add_to()" )
    {
        CHECK_THROWS_WITH( ( NEW( BoolVal )( true ) )->add_to( NEW( BoolVal )( true ) ), "invalid operation on non-number" );
        CHECK_THROWS_WITH( ( NEW( BoolVal )( false ) )->add_to( NEW( BoolVal )( true ) ), "invalid operation on non-number" );
        CHECK_THROWS_WITH( ( NEW( BoolVal )( true ) )->add_to( NEW( NumVal )( 42 ) ), "invalid operation on non-number" );
        CHECK_THROWS_WITH( ( NEW( BoolVal )( false ) )->add_to( NEW( NumVal )( 42 ) ), "invalid operation on non-number" );
    }

    SECTION( "BoolVal::mult_with()" )
    {
        CHECK_THROWS_WITH( ( NEW( BoolVal )( true ) )->mult_with( NEW( BoolVal )( true ) ),
                           "invalid operation on non-number" );
        CHECK_THROWS_WITH( ( NEW( BoolVal )( false ) )->mult_with( NEW( BoolVal )( true ) ),
                           "invalid operation on non-number" );
        CHECK_THROWS_WITH( ( NEW( BoolVal )( true ) )->mult_with( NEW( NumVal )( 42 ) ), "invalid operation on non-number" );
        CHECK_THROWS_WITH( ( NEW( BoolVal )( false ) )->mult_with( NEW( NumVal )( 42 ) ), "invalid operation on non-number" );
    }

    SECTION( "BoolVal::is_true()" )
    {
        CHECK( ( NEW( BoolVal )( true ) )->is_true() );
        CHECK_FALSE( ( NEW( BoolVal )( false ) )->is_true() );
    }

    SECTION( "BoolVal::to_string()" )
    {
        CHECK( ( NEW( BoolVal )( true ) )->to_string() == "_true" );
        CHECK( ( NEW( BoolVal )( false ) )->to_string() == "_false" );
    }

    SECTION( "BoolVal::call()" )
    {
        CHECK_THROWS_WITH( ( NEW( BoolVal )( true ) )
                         ->call( NEW( BoolVal )( true ) ), "cannot use call() on this type" );
    }
}

TEST_CASE( "Parsing functions" )
{
    SECTION( "Test parse_expr with: Num" )
    {
        CHECK( parse_expr( "56780" )->equals( NEW( Num )( 56780 ) ) );
        CHECK( parse_expr( "-56780" )->equals( NEW( Num )( -56780 ) ) );

        CHECK( parse_expr( "     56780" )->equals( NEW( Num )( 56780 ) ) );
        CHECK( parse_expr( "     -56780" )->equals( NEW( Num )( -56780 ) ) );

        CHECK( parse_expr( "\n\n\t     56780" )->equals( NEW( Num )( 56780 ) ) );
        CHECK( parse_expr( "\n\n\t     -56780" )->equals( NEW( Num )( -56780 ) ) );

        CHECK( parse_expr( "     56780     " )->equals( NEW( Num )( 56780 ) ) );
        CHECK( parse_expr( "     -56780     " )->equals( NEW( Num )( -56780 ) ) );

        CHECK( parse_expr( "\n\n\t     56780\n\n\t     " )->equals( NEW( Num )( 56780 ) ) );
        CHECK( parse_expr( "\n\n\t     -56780\n\n\t     " )->equals( NEW( Num )( -56780 ) ) );

        CHECK_THROWS_WITH( parse_expr( "5 6780" ), "parse_expr(): invalid input" );
        CHECK_THROWS_WITH( parse_expr( "56780-" ), "build_number(): malformed number" );
        CHECK_THROWS_WITH( parse_expr( "-56780x" ), "build_number(): malformed number" );
        CHECK_THROWS_WITH( parse_expr( "-56780-" ), "build_number(): malformed number" );
        CHECK_THROWS_WITH( parse_expr( "-" ), "parse_num(): expecting digit after '-'" );
        CHECK_THROWS_WITH( parse_expr( "- 5" ), "parse_num(): expecting digit after '-'" );
    }

    SECTION( "Test parse_expr with: Bool" )
    {
        CHECK( parse_expr( "_true" )->equals( NEW( Bool )( true ) ) );
        CHECK( parse_expr( "_false" )->equals( NEW( Bool )( false ) ) );
    }

    SECTION( "Test parse_expr with: Var" )
    {
        CHECK( parse_expr( "x" )->equals( NEW( Var )( "x" ) ) );
        CHECK( parse_expr( "variable" )->equals( NEW( Var )( "variable" ) ) );

        CHECK( parse_expr( "X" )->equals( NEW( Var )( "X" ) ) );
        CHECK( parse_expr( "mRkrAbS" )->equals( NEW( Var )( "mRkrAbS" ) ) );

        CHECK( parse_expr( "     var" )->equals( NEW( Var )( "var" ) ) );
        CHECK( parse_expr( "     VAR" )->equals( NEW( Var )( "VAR" ) ) );

        CHECK( parse_expr( "\n\n\t     var" )->equals( NEW( Var )( "var" ) ) );
        CHECK( parse_expr( "\n\n\t     VAR" )->equals( NEW( Var )( "VAR" ) ) );

        CHECK( parse_expr( "     var     " )->equals( NEW( Var )( "var" ) ) );
        CHECK( parse_expr( "     VAR     " )->equals( NEW( Var )( "VAR" ) ) );

        CHECK( parse_expr( "\n\n\t     var\n\n\t     " )->equals( NEW( Var )( "var" ) ) );
        CHECK( parse_expr( "\n\n\t     VAR\n\n\t     " )->equals( NEW( Var )( "VAR" ) ) );

        CHECK_THROWS_WITH( parse_expr( "x x" ), "parse_expr(): invalid input" );
        CHECK_THROWS_WITH( parse_expr( "x1" ), "build_variable(): malformed variable" );
        CHECK_THROWS_WITH( parse_expr( "x_" ), "build_variable(): malformed variable" );
        CHECK_THROWS_WITH( parse_expr( "x-" ), "build_variable(): malformed variable" );
        CHECK_THROWS_WITH( parse_expr( "-x" ), "parse_num(): expecting digit after '-'" );
        CHECK_THROWS_WITH( parse_expr( "2x" ), "build_number(): malformed number" );
    }

    SECTION( "Test parse_expr with: Eq" )
    {
        CHECK( parse_expr( "42==42" )->equals( NEW( Eq )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) );
        CHECK( parse_expr( "-42==-42" )->equals( NEW( Eq )( NEW( Num )( -42 ), NEW( Num )( -42 ) ) ) );
        CHECK( parse_expr( "42*42" )->equals( NEW( Eq )( NEW( Num )( -42 ), NEW( Num )( -42 ) ) ) == false );

        CHECK( parse_expr( "x==y" )->equals( NEW( Eq )( NEW( Var )( "x" ), NEW( Var )( "y" ) ) ) );
        CHECK( parse_expr( "X==Y" )->equals( NEW( Eq )( NEW( Var )( "X" ), NEW( Var )( "Y" ) ) ) );

        CHECK( parse_expr( "  \n\t  42  \n\t  == \n\t  X  \n\t  " )
                       ->equals( NEW( Eq )( NEW( Num )( 42 ), NEW( Var )( "X" ) ) ) );

        CHECK( parse_expr( "x == 42" )->equals( NEW( Eq )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) );

        CHECK_THROWS_WITH( parse_expr( "- 42 == 42" ), "parse_num(): expecting digit after '-'" );
        CHECK_THROWS_WITH( parse_expr( "42 == - 42" ), "parse_num(): expecting digit after '-'" );
        CHECK_THROWS_WITH( parse_expr( "==" ), "parse_bases(): invalid input" );
        CHECK_THROWS_WITH( parse_expr( "42 = 42" ), "parse_expr(): invalid input" );
        CHECK_THROWS_WITH( parse_expr( "42 = = 42" ), "parse_expr(): invalid input" );
    }

    SECTION( "Test parse_expr with: Add" )
    {
        CHECK( parse_expr( "42+42" )->equals( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) );
        CHECK( parse_expr( "-42+-42" )->equals( NEW( Add )( NEW( Num )( -42 ), NEW( Num )( -42 ) ) ) );
        CHECK( parse_expr( "42*42" )->equals( NEW( Add )( NEW( Num )( -42 ), NEW( Num )( -42 ) ) ) == false );

        CHECK( parse_expr( "x+y" )->equals( NEW( Add )( NEW( Var )( "x" ), NEW( Var )( "y" ) ) ) );
        CHECK( parse_expr( "X+Y" )->equals( NEW( Add )( NEW( Var )( "X" ), NEW( Var )( "Y" ) ) ) );

        CHECK( parse_expr( "  \n\t  42  \n\t  + \n\t  X  \n\t  " )
                       ->equals( NEW( Add )( NEW( Num )( 42 ), NEW( Var )( "X" ) ) ) );

        CHECK( parse_expr( "x + 42" )->equals( NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) );

        CHECK_THROWS_WITH( parse_expr( "- 42 + 42" ), "parse_num(): expecting digit after '-'" );
        CHECK_THROWS_WITH( parse_expr( "42 + - 42" ), "parse_num(): expecting digit after '-'" );
        CHECK_THROWS_WITH( parse_expr( "+" ), "parse_bases(): invalid input" );
        CHECK_THROWS_WITH( parse_expr( "42 - 42" ), "parse_expr(): invalid input" );
    }

    SECTION( "Test parse_expr with: Mult" )
    {
        CHECK( parse_expr( "42 * 42" )->equals( NEW( Mult )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) );
        CHECK( parse_expr( "-42 * -42" )->equals( NEW( Mult )( NEW( Num )( -42 ), NEW( Num )( -42 ) ) ) );

        CHECK( parse_expr( "x * y" )->equals( NEW( Mult )( NEW( Var )( "x" ), NEW( Var )( "y" ) ) ) );
        CHECK( parse_expr( "X * Y" )->equals( NEW( Mult )( NEW( Var )( "X" ), NEW( Var )( "Y" ) ) ) );

        CHECK( parse_expr( "x * 42" )->equals( NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 42 ) ) ) );

        CHECK( parse_expr( "  \n\t  42  \n\t  *  \n\t  X  \n\t  " )
                       ->equals( NEW( Mult )( NEW( Num )( 42 ), NEW( Var )( "X" ) ) ) );

        CHECK_THROWS_WITH( parse_expr( "- 42 * 42" ), "parse_num(): expecting digit after '-'" );
        CHECK_THROWS_WITH( parse_expr( "42 * - 42" ), "parse_num(): expecting digit after '-'" );
        CHECK_THROWS_WITH( parse_expr( "*" ), "parse_bases(): invalid input" );
    }

    SECTION( "Test parse_expr with: Let" )
    {
        CHECK( parse_expr( "_let x = 5 _in x + 5" )
                       ->equals( NEW( Let )( "x", NEW( Num )( 5 ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 5 ) ) ) ) );

        CHECK( parse_expr( "_let x = (_let y = 5 _in y+6) _in x+7" )
                       ->equals( NEW( Let )( "x",
                                          NEW( Let )( "y", NEW( Num )( 5 ), NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 6 ) ) ),
                                          NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 7 ) ) ) ) );

        CHECK( parse_expr( "_let x = 5 _in (_let y = 3 _in y + _let z = 6 _in z + 8) + x" )
                       ->equals( (  NEW( Let )( "x", NEW( Num )( 5 ), NEW( Add )(
                                        NEW( Let )( "y", NEW( Num )( 3 ), NEW( Add )( NEW( Var )( "y" ),
                                                                             NEW( Let )( "z", NEW( Num )( 6 ), NEW( Add )( NEW( Var )( "z" ),
                                                                                                                  NEW( Num )( 8 ) ) ) ) ),
                                    NEW( Var )( "x" ) ) ) ) ) );

        CHECK( parse_expr( "  \n\t  _let  \n\t  x  \n\t  =  5  \n\t  _in  \n\t"
                           "  (  \n\t  _let  \n\t  y  \n\t  =  \n\t  3  \n\t"
                           "  _in  \n\t  y   \n\t  +  \n\t  _let  \n\t  z"
                           "  \n\t  =  \n\t  6  \n\t   _in  \n\t  z  \n\t "
                           " +  \n\t  8  \n\t  )  \n\t  +  \n\t  x  \n\t  " )
                       ->equals( (  NEW( Let )( "x", NEW( Num )( 5 ), NEW( Add )(
                                        NEW( Let )( "y", NEW( Num )( 3 ), NEW( Add )( NEW( Var )( "y" ),
                                                                             NEW( Let )( "z", NEW( Num )( 6 ), NEW( Add )( NEW( Var )( "z" ),
                                                                                                                  NEW( Num )( 8 ) ) ) ) ),
                                    NEW( Var )( "x" ) ) ) ) ) );

        CHECK_THROWS_WITH( parse_expr( "_42" ), "peek_keyword(): invalid keyword" );
        CHECK_THROWS_WITH( parse_expr( "_let x = 5 _42" ), "consume(): mismatch" );
        CHECK_THROWS_WITH( parse_expr( "_ let" ), "peek_keyword(): invalid keyword" );
        CHECK_THROWS_WITH( parse_expr( "_let x = 5 _ in" ), "consume(): mismatch" );
        CHECK_THROWS_WITH( parse_expr( "_let x = 5 _in" ), "parse_bases(): invalid input" );
        CHECK_THROWS_WITH( parse_expr( "_let x = 5 _in y + 3" ), "parse_let(): invalid let" );
        CHECK_THROWS_WITH( parse_expr( "_let x = 5 _in 3" ), "parse_let(): invalid let" );
        CHECK_THROWS_WITH( parse_expr( "_let 3 = 5 _in y + 3" ), "parse_let(): invalid let" );
        CHECK_THROWS_WITH( parse_expr( "_let 3 = 5 _in y + " ), "parse_let(): invalid let" );
    }

    SECTION( "Test parse_expr with: If" )
    {
        CHECK( parse_expr("_if x==3 _then 42+x _else 84*x")
                       ->equals( NEW( If )( NEW( Eq )( NEW( Var )("x"), NEW( Num )(3) ),
                                         NEW( Add )( NEW( Num )(42), NEW( Var )("x") ),
                                         NEW( Mult )( NEW( Num )(84), NEW( Var )("x") ) ) )
        );

        CHECK( parse_expr("  \n\t  _if  \n\t  x  \n\t  ==  \n\t  3  \n\t  _then  \n\t  42  \n\t  +  \n\t  x  "
                          "\n\t  _else  \n\t  84  \n\t  *  \n\t  x  \n\t  ")
                       ->equals( NEW( If )( NEW( Eq )( NEW( Var )("x"), NEW( Num )(3) ),
                                         NEW( Add )( NEW( Num )(42), NEW( Var )("x") ),
                                         NEW( Mult )( NEW( Num )(84), NEW( Var )("x") ) ) )
        );

        PTR( Expr ) leviathan = NEW( Let )( "A", ( NEW( Let )( "B", NEW( Num )(1), ( NEW( If )( NEW( Eq )( NEW( Var )("x"), (
                           NEW( If )( NEW( Eq )( NEW( Var )("y"), NEW( Num )(2)), NEW( Num )(3), NEW( Num )(4) ) ) ),
                           NEW( Num )(11), NEW( Var )("B") ) ) ) ), ( NEW( If )( NEW( Eq )( ( NEW( Let )( "C", NEW( Num )(5),
                           NEW( Add )( NEW( Var )("C"), NEW( Num )(6) ) ) ), ( NEW( Let )( "D", NEW( Num )(7), NEW( Add )( NEW( Var )("D"),
                           NEW( Num )(8) ) ) ) ), NEW( Num )(4), ( NEW( Let )( "E", NEW( Num )(9), NEW( Add )( NEW( Var )("E"),
                           NEW( Var )("A") ) ) ) ) ) );

        CHECK( parse_expr(               "_let A = _let B = 1\n"
                                         "         _in  _if   x == (_if   y == 2\n"
                                         "                          _then 3\n"
                                         "                          _else 4)\n"
                                         "              _then 11\n"
                                         "              _else B\n"
                                         "_in  _if   (_let C = 5\n"
                                         "            _in  C + 6) == (_let D = 7\n"
                                         "                            _in  D + 8)\n"
                                         "     _then 4\n"
                                         "     _else _let E = 9\n"
                                         "           _in  E + A"
        )->equals( leviathan ) );

    }

    SECTION( "Test parse_expr with: parentheses" )
    {
        CHECK( parse_expr( "(42+42)" )->equals( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) );
        CHECK( parse_expr( "((42))" )->equals( NEW( Num )( 42 ) ) );
        CHECK( parse_expr( "  \n\t  (  \n\t  42  \n\t  +  \n\t  42  \n\t  )  \n\t  " )
                       ->equals( NEW( Add )( NEW( Num )( 42 ), NEW( Num )( 42 ) ) ) );

        CHECK_THROWS_WITH( parse_expr( "()" ), "parse_bases(): invalid input" );
        CHECK_THROWS_WITH( parse_expr( "(" ), "parse_bases(): invalid input" );
        CHECK_THROWS_WITH( parse_expr( "(4" ), "parse_paren(): missing closing parenthesis" );
        CHECK_THROWS_WITH( parse_expr( "(4+2" ), "parse_paren(): missing closing parenthesis" );
        CHECK_THROWS_WITH( parse_expr( "( (4+2)" ), "parse_paren(): missing closing parenthesis" );
        CHECK_THROWS_WITH( parse_expr( "2 * ((4+2)" ), "parse_paren(): missing closing parenthesis" );
    }

    SECTION( "Test parse_expr with: --interp" )
    {
        CHECK( parse_expr( "(3 + 5) * 6 * 1" )
                       ->interp()->equals( NEW( NumVal )( 48 ) ) );
        CHECK( parse_expr( "(7 * 7) * (9 + 2)" )
                       ->interp()->equals( NEW( NumVal )( 539 ) ) );
        CHECK( parse_expr( "_let x = 5 _in x + 5" )
                       ->interp()->equals( NEW( NumVal )( 10 ) ) );
        CHECK( parse_expr( "_let x = (_let y = 5 _in y+6) _in x+7" )
                       ->interp()->equals( NEW( NumVal )( 18 ) ) );
        CHECK( parse_expr( "_let x = 5 _in (_let y = 3 _in y + _let z = 6 _in z + 8) + x" )
                       ->interp()->equals( NEW( NumVal )( 22 ) ) );

        CHECK( parse_expr( "1==2+3" )->interp()->equals( NEW( BoolVal )( false ) ) );
        CHECK( parse_expr( "1+1==2+0" )->interp()->equals( NEW( BoolVal )( true ) ) );
        CHECK_THROWS_WITH( parse_expr( "(1==2)+3" )->interp()->equals( NEW( NumVal )(3) ), "invalid operation on non-number" );
    }

    SECTION( "Test parse_expr with: --print" )
    {
        CHECK( parse_expr( "1 * (2 + 3)" )
                       ->to_string() == "(1*(2+3))" );
        CHECK( parse_expr( "(8 * 1) * y" )
                       ->to_string() == "((8*1)*y)" );
        CHECK( parse_expr( "(3 + 5) * 6 * 1" )
                       ->to_string() == "((3+5)*(6*1))" );
        CHECK( parse_expr( "(7 * 7) * (9 + 2)" )
                       ->to_string() == "((7*7)*(9+2))" );
        CHECK( parse_expr( "_let x = (_let y = 5 _in y+6) _in x+7" )
                       ->to_string() == "(_let x=(_let y=5 _in (y+6)) _in (x+7))" );
        CHECK( parse_expr( "_let x = 5 _in (_let y = 3 _in y + _let z = 6 _in z + 8) + x" )
                       ->to_string() == "(_let x=5 _in ((_let y=3 _in (y+(_let z=6 _in (z+8))))+x))" );

    }

    SECTION( "Test parse_expr with: --pretty-print" )
    {
        CHECK( parse_expr( "1 * (2 + 3)" )
                       ->to_pretty_string() == "1 * (2 + 3)" );
        CHECK( parse_expr( "(8 * 1) * y" )
                       ->to_pretty_string() == "(8 * 1) * y" );
        CHECK( parse_expr( "(3 + 5) * 6 * 1" )
                       ->to_pretty_string() == "(3 + 5) * 6 * 1" );
        CHECK( parse_expr( "(7 * 7) * (9 + 2)" )
                       ->to_pretty_string() == "(7 * 7) * (9 + 2)" );
        CHECK( parse_expr( "_let x = 5 _in (_let y = 3 _in y + _let z = 6 _in z + 8) + x" )
                       ->to_pretty_string() == "_let x = 5\n"
                                               "_in  (_let y = 3\n"
                                               "      _in  y + _let z = 6\n"
                                               "               _in  z + 8) + x" );
    }
}

TEST_CASE( "Comprehensive tests" )
{
    SECTION( "equals()" )
    {
        CHECK( ( NEW( Mult )( NEW( Add )( NEW( Num )( 2 ), NEW( Num )( 2 ) ), NEW( Add )( NEW( Num )( 2 ), NEW( Num )( 2 ) ) ) )
                       ->equals( NEW( Mult )( NEW( Add )( NEW( Num )( 2 ), NEW( Num )( 2 ) ),
                                           NEW( Add )( NEW( Num )( 2 ), NEW( Num )( 2 ) ) ) ) );
        CHECK( ( NEW( Mult )( NEW( Add )( NEW( Num )( 0 ), NEW( Num )( 0 ) ), NEW( Add )( NEW( Num )( 2 ), NEW( Num )( 2 ) ) ) )
                       ->equals( NEW( Mult )( NEW( Add )( NEW( Num )( 0 ), NEW( Num )( 0 ) ),
                                           NEW( Add )( NEW( Num )( 2 ), NEW( Num )( 2 ) ) ) ) );
    }

    SECTION( "subst()" )
    {
        // 3 * (4 * x) + -2 * ( 8 + x )->subst( 3 * ( 4 * (y + 7) ) + -2 * ( 8 + (y + 7) ) )
        CHECK( ( NEW( Add )( NEW( Mult )( NEW( Num )( 3 ), NEW( Mult )( NEW( Num )( 4 ), NEW( Var )( "x" ) ) ),
                          NEW( Mult )( NEW( Num )( -2 ), NEW( Add )( NEW( Num )( 8 ), NEW( Var )( "x" ) ) ) ) )->subst( "x", NEW( Add )(
                NEW( Var )( "y" ), NEW( Num )( 7 ) ) )->equals(
                NEW( Add )( NEW( Mult )( NEW( Num )( 3 ), NEW( Mult )( NEW( Num )( 4 ), NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 7 ) ) ) ),
                         NEW( Mult )( NEW( Num )( -2 ),
                                   NEW( Add )( NEW( Num )( 8 ), NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 7 ) ) ) ) ) ) );
    }

    SECTION( "parse_expr()" )
    {
        CHECK( parse_expr( "1 * (2 + 3)" )
                       ->equals( NEW( Mult )( NEW( Num )( 1 ), NEW( Add )( NEW( Num )( 2 ), NEW( Num )( 3 ) ) ) ) );
        CHECK( parse_expr( "(8 * 1) * y" )
                       ->equals( NEW( Mult )( NEW( Mult )( NEW( Num )( 8 ), NEW( Num )( 1 ) ), NEW( Var )( "y" ) ) ) );
        CHECK( parse_expr( "(3 + 5) * 6 * 1" )
                       ->equals( NEW( Mult )( NEW( Add )( NEW( Num )( 3 ), NEW( Num )( 5 ) ),
                                           NEW( Mult )( NEW( Num )( 6 ), NEW( Num )( 1 ) ) ) ) );
        CHECK( parse_expr( "(7 * 7) * (9 + 2)" )
                       ->equals( NEW( Mult )( NEW( Mult )( NEW( Num )( 7 ), NEW( Num )( 7 ) ),
                                           NEW( Add )( NEW( Num )( 9 ), NEW( Num )( 2 ) ) ) ) );
        CHECK( parse_expr( "  \n\t  (  \n\t  8  \n\t   *   \n\t  1)  \n\t   *   \n\t  y  \n\t  " )
                       ->equals( NEW( Mult )( NEW( Mult )( NEW( Num )( 8 ), NEW( Num )( 1 ) ), NEW( Var )( "y" ) ) ) );
    }

    SECTION( "The void" )
    {
        ///// leviathan in broken up form
//    Expr * If2 = new If( new Eq( new Var("y"), new Num(2)), new Num(3), new Num(4) );
//    Expr * If1 = new If( new Eq( new Var("x"), If2 ), new Num(11), new Var("B") );
//
//    Expr * let2 = new Let( "B", new Num(1), If1 );
//
//    Expr * let3 = new Let( "C", new Num(5), new Add( new Var("C"), new Num(6) ) );
//    Expr * let4 = new Let( "D", new Num(7), new Add( new Var("D"), new Num(8) ) );
//    Expr * let5 = new Let( "E", new Num(9), new Add( new Var("E"), new Var("A") ) );
//
//    Expr * If3 = new If( new Eq( let3, let4 ), new Num(4), let5 );
//
//    Expr * let1 = new Let( "A", let2, If3 );

        PTR( Expr ) leviathan = NEW( Let )( "A", ( NEW( Let )( "B", NEW( Num )(1), ( NEW( If )( NEW( Eq )( NEW( Var )("x"), (
                            NEW( If )( NEW( Eq )( NEW( Var )("y"), NEW( Num )(2)), NEW( Num )(3), NEW( Num )(4) ) ) ),
                            NEW( Num )(11), NEW( Var )("B") ) ) ) ), ( NEW( If )( NEW( Eq )( ( NEW( Let )( "C", NEW( Num )(5),
                            NEW( Add )( NEW( Var )("C"), NEW( Num )(6) ) ) ), ( NEW( Let )( "D", NEW( Num )(7), NEW( Add )( NEW( Var )("D"),
                            NEW( Num )(8) ) ) ) ), NEW( Num )(4), ( NEW( Let )( "E", NEW( Num )(9), NEW( Add )( NEW( Var )("E"),
                            NEW( Var )("A") ) ) ) ) ) );

        CHECK( ( leviathan )

                       ->to_pretty_string() ==

               "_let A = _let B = 1\n"
               "         _in  _if   x == _if   y == 2\n"
               "                         _then 3\n"
               "                         _else 4\n"
               "              _then 11\n"
               "              _else B\n"
               "_in  _if   (_let C = 5\n"
               "            _in  C + 6) == _let D = 7\n"
               "                           _in  D + 8\n"
               "     _then 4\n"
               "     _else _let E = 9\n"
               "           _in  E + A"
        );

        // Quintuple-nested Let, with Let as RHS in all nested Lets, and every operation in Expr class as Body
        CHECK( (
                       NEW( Let )( "add",
                                NEW( Let )("mult",
                                        NEW( Let )( "eq",
                                                 NEW( Let )( "if", NEW( Num )(1), NEW( If )( NEW( Eq )( NEW( Num )(2), NEW( Num )(3) ), NEW( Num ) (4), NEW( Num )(5) ) ),
                                                 NEW( Eq )( NEW( Num )(6), NEW( Num )(7) ) ),
                                        NEW( Mult )( NEW( Num )(8), NEW( Num )(9) ) ),
                                NEW( Add )( NEW( Num )(10), NEW( Num )(11) ) ) )

                       ->to_pretty_string() ==

               "_let add = _let mult = _let eq = _let if = 1\n"
               "                                 _in  _if   2 == 3\n"
               "                                      _then 4\n"
               "                                      _else 5\n"
               "                       _in  6 == 7\n"
               "           _in  8 * 9\n"
               "_in  10 + 11"

        );

        // Quadruple-nested Let, with Let as RHS in all nested Lets
        CHECK( (
                       NEW( Let )( "add",
                                NEW( Let )("mult",
                                        NEW( Let )( "eq",
                                                 NEW( Let )( "if", NEW( Num )(1), NEW( Add )( NEW( Num ) (4), NEW( Num )(5) ) ),
                                                 NEW( Mult )( NEW( Num )(6), NEW( Num )(7) ) ),
                                        NEW( Mult )( NEW( Num )(8), NEW( Num )(9) ) ),
                                NEW( Add )( NEW( Num )(10), NEW( Num )(11) ) ) )

                       ->to_pretty_string() ==

               "_let add = _let mult = _let eq = _let if = 1\n"
               "                                 _in  4 + 5\n"
               "                       _in  6 * 7\n"
               "           _in  8 * 9\n"
               "_in  10 + 11"

        );

        CHECK( ( NEW( Eq )( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Var )( "x" ) ), NEW( Let )( "y", NEW( Num )( 84 ), NEW( Var )( "y" ) ) ) )

                       ->to_pretty_string() == "(_let x = 42\n"
                                               " _in  x) == _let y = 84\n"
                                               "            _in  y" );

        CHECK( ( NEW( Mult )( NEW( Let )( "x", NEW( Num )( 42 ), NEW( Var )( "x" ) ), NEW( Let )( "y", NEW( Num )( 84 ), NEW( Var )( "y" ) ) ) )

                       ->to_pretty_string() == "(_let x = 42\n"
                                               " _in  x) * (_let y = 84\n"
                                               "            _in  y)" );

        CHECK( ( NEW( If )( NEW( Eq )( NEW( Var )( "x" ), NEW( Num )( 1 ) ),
                         NEW( If )( NEW( Num )( 2 ), NEW( Num )( 3 ), NEW( Num )( 4 ) ),
                         NEW( If )( NEW( Num )( 5 ), NEW( Num )( 6 ), NEW( Num )( 7 ) ) ) )

                       ->to_pretty_string() ==

               "_if   x == 1\n"
               "_then _if   2\n"
               "      _then 3\n"
               "      _else 4\n"
               "_else _if   5\n"
               "      _then 6\n"
               "      _else 7"
        );
    }
}

TEST_CASE( "Fun/FunVal/Call" )
{
    SECTION( "Fun" )
    {

        SECTION( "Fun::equals" )
        {
            //True check
            CHECK( ( NEW( Fun )( "x", NEW( Add )( NEW( Num )( 5 ), NEW( Num )( 3 ) ) ) )->equals(
                    NEW( Fun )( "x", NEW( Add )( NEW( Num )( 5 ), NEW( Num )( 3 ) ) ) ) );
            //False check
            CHECK( !( NEW( Fun )( "y", NEW( Mult )( NEW( Num )( 9 ), NEW( Num )( 0 ) ) ) )->equals(
                    NEW( Fun )( "x", NEW( Add )( NEW( Num )( 5 ), NEW( Num )( 3 ) ) ) ) );
        }

        SECTION( "Fun::interp" )
        {
            //Fun with Num body
            CHECK( ( NEW( Fun )( "x", NEW( Num )( 5 ) ) )->interp()->equals( NEW( FunVal )( "x", NEW( Num )( 5 ) ) ) );
            //Fun with Add body
            CHECK( ( NEW( Fun )( "y", NEW( Add )( NEW( Num )( 2 ), NEW( Num )( 3 ) ) ) )->interp()->equals(
                    NEW( FunVal )( "y", NEW( Add )( NEW( Num )( 2 ), NEW( Num )( 3 ) ) ) ) );
            //Fun with Mult body
            CHECK( ( NEW( Fun )( "z", NEW( Mult )( NEW( Num )( 8 ), NEW( Num )( 12 ) ) ) )->interp()->equals(
                    NEW( FunVal )( "z", NEW( Mult )( NEW( Num )( 8 ), NEW( Num )( 12 ) ) ) ) );
            //Fun with Let body
            CHECK( ( NEW( Fun )( "x", NEW( Let )( "f", NEW( Num )( 4 ),
                                            NEW( Add )( NEW( Var )( "f" ), NEW( Num )( 8 ) ) ) ) )->interp()->equals(
                    NEW( FunVal )( "x", NEW( Let )( "f", NEW( Num )( 4 ), NEW( Add )( NEW( Var )( "f" ), NEW( Num )( 8 ) ) ) ) ) );
            //Fun with If body
            CHECK( ( NEW( Fun )( "x", NEW( If )( NEW( Eq )( NEW( Num )( 1 ), NEW( Num )( 2 ) ), NEW( Num )( 5 ),
                                           NEW( Num )( 6 ) ) ) )->interp()->equals(
                    NEW( FunVal )( "x", NEW( If )( NEW( Eq )( NEW( Num )( 1 ), NEW( Num )( 2 ) ), NEW( Num )( 5 ), NEW( Num )( 6 ) ) ) ) );
        }

        SECTION( "Fun::subst" )
        {
            //Fun can be substituted
            ( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Var )( "y" ) ) ) )->subst( "x", NEW( Num )( 4 ) )->equals(
                    NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 4 ) ) ) );
            //Fun cannot be substituted
            ( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 7 ) ) ) )->subst( "x", NEW( Num )( 4 ) )->equals(
                    NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 7 ) ) ) );
            //Successful substitution when valToSub is nested in Fun->body
            CHECK( ( NEW( Fun )( "x", NEW( Add )( NEW( Num )( 3 ),
                                            NEW( If )( NEW( Bool )( true ), NEW( Add )( NEW( Var )( "x" ), NEW( Var )( "y" ) ),
                                                    NEW( Num )( 4 ) ) ) ) )
                           ->subst( "y", NEW( Num )( 3 ) )->equals
                    ( NEW( Fun )( "x", NEW( Add )( NEW( Num )( 3 ),
                                             NEW( If )( NEW( Bool )( true ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 3 ) ),
                                                     NEW( Num )( 4 ) ) ) ) ) );
            //Unsuccessful substitution when valToSub is nested in Fun->body
            CHECK( ( NEW( Fun )( "x", NEW( Add )( NEW( Num )( 3 ),
                                            NEW( If )( NEW( Bool )( true ), NEW( Add )( NEW( Var )( "x" ), NEW( Var )( "y" ) ),
                                                    NEW( Num )( 4 ) ) ) ) )
                           ->subst( "x", NEW( Num )( 3 ) )->equals
                    ( NEW( Fun )( "x", NEW( Add )( NEW( Num )( 3 ),
                                             NEW( If )( NEW( Bool )( true ), NEW( Add )( NEW( Var )( "x" ), NEW( Var )( "y" ) ),
                                                     NEW( Num )( 4 ) ) ) ) ) );
            //Unsuccessful substitution when Fun has valToSub in multiple locations
            CHECK( ( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ),
                                            NEW( If )( NEW( Bool )( true ), NEW( Add )( NEW( Var )( "x" ), NEW( Var )( "y" ) ),
                                                    NEW( Num )( 4 ) ) ) ) )->subst( "x", NEW( Num )( 5 ) )->equals(
                    NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ),
                                           NEW( If )( NEW( Bool )( true ), NEW( Add )( NEW( Var )( "x" ), NEW( Var )( "y" ) ),
                                                   NEW( Num )( 4 ) ) ) ) ) );
        }

        SECTION( "Fun::print" )
        {
            //Basic Fun
            CHECK( ( NEW( Fun )( "x", NEW( Add )( NEW( Num )( 2 ), NEW( Var )( "x" ) ) ) )->to_string() ==
                   "(_fun (x) (2+x))" );
            //Pretty Fun
            CHECK( ( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Let )( "y", NEW( Num )( 5 ), NEW( Add )( NEW( Var )( "y" ),
                                                                                                 NEW( Num )(
                                                                                                         6 ) ) ) ) ) )->to_string() ==
                   "(_fun (x) (x+(_let y=5 _in (y+6))))" );
            //Buckwild Fun
            CHECK( ( NEW( Add )( NEW( Num )( 4 ), NEW( Fun )( "x", NEW( Mult )( NEW( Num )( 5 ), NEW( Var )( "x" ) ) ) ) )->to_string() ==
                   "(4+(_fun (x) (5*x)))" );
            //Zonkers Fun
            CHECK( ( NEW( Let )( "x", NEW( Num )( 3 ),
                              NEW( Fun )( "y", NEW( Add )( NEW( Var )( "y" ), NEW( Var )( "x" ) ) ) ) )->to_string() ==
                   "(_let x=3 _in (_fun (y) (y+x)))" );
            //Maybe just a glass of hot chocolate and go to bed at 7:30
            CHECK( ( NEW( Fun )( "x", NEW( Mult )( NEW( Var )( "x" ), NEW( Fun )( "y", NEW( Add )( NEW( Num )( 4 ), NEW( Var )(
                    "y" ) ) ) ) ) )->to_string() ==
                   "(_fun (x) (x*(_fun (y) (4+y))))" );
        }

        SECTION( "Fun::pretty_print" )
        {
            //Basic Fun
            CHECK( ( NEW( Fun )( "x", NEW( Add )( NEW( Num )( 2 ), NEW( Var )( "x" ) ) ) )->to_pretty_string() ==
                   "_fun (x)\n"
                   "  2 + x" );
            //Fun with nested Let
            CHECK( ( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Let )( "y", NEW( Num )( 5 ), NEW( Add )( NEW( Var )( "y" ),
                                                                                                 NEW( Num )(
                                                                                                         6 ) ) ) ) ) )->to_pretty_string() ==
                   "_fun (x)\n"
                   "  x + _let y = 5\n"
                   "      _in  y + 6" );
            //Fun nested within Add
            CHECK( ( NEW( Add )( NEW( Num )( 4 ),
                              NEW( Fun )( "x", NEW( Mult )( NEW( Num )( 5 ), NEW( Var )( "x" ) ) ) ) )->to_pretty_string() ==
                   "4 + _fun (x)\n"
                   "      5 * x" );
            //Fun nested within Let
            CHECK( ( NEW( Let )( "x", NEW( Num )( 3 ),
                              NEW( Fun )( "y", NEW( Add )( NEW( Var )( "y" ), NEW( Var )( "x" ) ) ) ) )->to_pretty_string() ==
                   "_let x = 3\n"
                   "_in  _fun (y)\n"
                   "       y + x" );
            //Fun nested within Fun
            CHECK( ( NEW( Fun )( "x", NEW( Mult )( NEW( Var )( "x" ), NEW( Fun )( "y", NEW( Add )( NEW( Num )( 4 ), NEW( Var )(
                    "y" ) ) ) ) ) )->to_pretty_string() ==
                   "_fun (x)\n"
                   "  x * (_fun (y)\n"
                   "         4 + y)" );
        }
    }

    SECTION( "Call" )
    {

        SECTION( "Call::Equals" )
        {
            //True check
            CHECK( ( NEW( Call )( NEW( Num )( 5 ), NEW( Num )( 7 ) ) )->equals( NEW( Call )( NEW( Num )( 5 ), NEW( Num )( 7 ) ) ) );
            //False check
            CHECK( !( NEW( Call )( NEW( Var )( "t" ), NEW( Num )( 7 ) ) )->equals( NEW( Call )( NEW( Num )( 5 ), NEW( Num )( 7 ) ) ) );
        }

        SECTION( "Call::Interp" )
        {
            //Error handle for NumVal
            CHECK_THROWS_WITH( ( NEW( Call )( NEW( Num )( 5 ), NEW( Num )( 9 ) ) )->interp(), "cannot use call() on this type" );
            //Error handle for BoolVal
            CHECK_THROWS_WITH( ( NEW( Call )( NEW( Bool )( true ), NEW( Num )( 9 ) ) )->interp(),
                               "cannot use call() on this type" );
            //Interp on Fun when substituting to_be_called with a Num
            CHECK( ( NEW( Call )( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 1 ) ) ),
                               NEW( Num )( 4 ) ) )->interp()->equals( NEW( NumVal )( 5 ) ) );
            //Interp on Fun when substituting to_be_called with an Add
            CHECK( ( NEW( Call )( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 9 ) ) ),
                               NEW( Add )( NEW( Num )( 3 ), NEW( Num )( 7 ) ) ) )->interp()->equals( NEW( NumVal )( 19 ) ) );
            //Interp on Fun when substituting to_be_called with a Mult
            CHECK( ( NEW( Call )( NEW( Fun )( "x", NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 3 ) ) ),
                               NEW( Mult )( NEW( Num )( 6 ), NEW( Num )( 2 ) ) ) )->interp()->equals( NEW( NumVal )( 36 ) ) );
            //Interp on Fun when substituting to_be_called with a Let
            CHECK( ( NEW( Call )( NEW( Fun )( "x", NEW( Mult )( NEW( Var )( "x" ), NEW( Num )( 6 ) ) ), NEW( Let )( "y", NEW( Num )( 4 ),
                                                                                                  NEW( Add )( NEW( Var )(
                                                                                                                   "y" ),
                                                                                                           NEW( Num )(
                                                                                                                   8 ) ) ) ) )->interp()->equals(
                    NEW( NumVal )( 72 ) ) );
        }

        SECTION( "Call::subst" )
        {
            //Successful substitution on basic Call
            CHECK( ( NEW( Call )( NEW( Num )( 3 ), NEW( Var )( "x" ) ) )->subst( "x", NEW( Num )( 7 ) )->equals(
                    NEW( Call )( NEW( Num )( 3 ), NEW( Num )( 7 ) ) ) );
            //Unsuccessful substitution on basic Call
            CHECK( ( NEW( Call )( NEW( Num )( 3 ), NEW( Num )( 4 ) ) )->subst( "x", NEW( Num )( 7 ) )->equals(
                    NEW( Call )( NEW( Num )( 3 ), NEW( Num )( 4 ) ) ) );
            //Successful substitution when valToSub is nested in to_be_called expression
            CHECK( ( NEW( Call )( NEW( Add )( NEW( Num )( 4 ), NEW( Var )( "x" ) ), NEW( Num )( 5 ) ) )->subst( "x",
                                                                                                 NEW( Num )( 8 ) )->equals(
                    NEW( Call )( NEW( Add )( NEW( Num )( 4 ), NEW( Num )( 8 ) ), NEW( Num )( 5 ) ) ) );
            //Successful substitution when valToSub nested in actual_arg expression
            CHECK( ( NEW( Call )( NEW( Num )( 4 ), NEW( Mult )( NEW( Var )( "y" ), NEW( Num )( 0 ) ) ) )->subst( "y", NEW( Num )(
                    9 ) )->equals( NEW( Call )( NEW( Num )( 4 ), NEW( Mult )( NEW( Num )( 9 ), NEW( Num )( 0 ) ) ) ) );
            //Unsuccessful substitution when valToSub is not in tested actual_arg expression
            CHECK( ( NEW( Call )( NEW( Num )( 4 ), NEW( Mult )( NEW( Var )( "y" ), NEW( Num )( 0 ) ) ) )->subst( "z", NEW( Num )(
                    9 ) )->equals( NEW( Call )( NEW( Num )( 4 ), NEW( Mult )( NEW( Var )( "y" ), NEW( Num )( 0 ) ) ) ) );
        }

        SECTION( "Call::print" )
        {
            //Fun with Var
            CHECK( ( NEW( Call )( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 4 ) ) ),
                               NEW( Var )( "x" ) ) )->to_string() ==
                   "(_fun (x) (x+4)) x" );
            //Fun with Add
            CHECK( ( NEW( Call )( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 4 ) ) ),
                               NEW( Add )( NEW( Num )( 3 ), NEW( Num )( 8 ) ) ) )->to_string() ==
                   "(_fun (x) (x+4)) (3+8)" );
            //Fun with Mult
            CHECK( ( NEW( Call )( NEW( Fun )( "y", NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 7 ) ) ),
                               NEW( Mult )( NEW( Num )( 1 ), NEW( Num )( 5 ) ) ) )->to_string() ==
                   "(_fun (y) (y+7)) (1*5)" );
            //Fun with Let
            CHECK( ( NEW( Call )( NEW( Fun )( "y", NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 7 ) ) ),
                               NEW( Let )( "x", NEW( Num )( 9 ), NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 4 ) ) ) ) )->to_string() ==
                   "(_fun (y) (y+7)) (_let x=9 _in (x+4))" );
            //Fun with Num
            CHECK( ( NEW( Call )( NEW( Fun )( "y", NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 7 ) ) ), NEW( Num )( 0 ) ) )->to_string() ==
                   "(_fun (y) (y+7)) 0" );
        }

        SECTION( "Call::pretty_print" )
        {
            //Fun with Var
            CHECK( ( NEW( Call )( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 4 ) ) ),
                               NEW( Var )( "x" ) ) )->to_pretty_string() ==
                   "_fun (x)\n"
                   "  x + 4(x)" );
            //Fun with Add
            CHECK( ( NEW( Call )( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 4 ) ) ),
                               NEW( Add )( NEW( Num )( 3 ), NEW( Num )( 8 ) ) ) )->to_pretty_string() ==
                   "_fun (x)\n"
                   "  x + 4(3 + 8)" );
            //Fun with Mult
            CHECK( ( NEW( Call )( NEW( Fun )( "y", NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 7 ) ) ),
                               NEW( Mult )( NEW( Num )( 1 ), NEW( Num )( 5 ) ) ) )->to_pretty_string() ==
                   "_fun (y)\n"
                   "  y + 7(1 * 5)" );
            //Fun with Let
            CHECK( ( NEW( Call )( NEW( Fun )( "y", NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 7 ) ) ), NEW( Let )( "x", NEW( Num )( 9 ),
                                                                                                 NEW( Add )(
                                                                                                         NEW( Var )( "x" ),
                                                                                                         NEW( Num )(
                                                                                                                 4 ) ) ) ) )->to_pretty_string() ==
                   "_fun (y)\n"
                   "  y + 7(_let x = 9\n"
                   "        _in  x + 4)" );
            //Fun with Num
            CHECK( ( NEW( Call )( NEW( Fun )( "y", NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 7 ) ) ),
                               NEW( Num )( 0 ) ) )->to_pretty_string() ==
                   "_fun (y)\n"
                   "  y + 7(0)" );
        }
    }

    SECTION ( "FunVal" )
    {
        SECTION( "FunVal::to_expr()" )
        {
            //FunVal with Num
            CHECK( ( NEW( FunVal )( "x", NEW( Num )( 7 ) ) )->to_expr()->equals( NEW( Fun )( "x", NEW( Num )( 7 ) ) ) );
            //FunVal with Add
            CHECK( ( NEW( FunVal )( "x", NEW( Add )( NEW( Num )( 2 ), NEW( Var )( "x" ) ) ) )->to_expr()->equals(
                    NEW( Fun )( "x", NEW( Add )( NEW( Num )( 2 ), NEW( Var )( "x" ) ) ) ) );
            //FunVal with Mult
            CHECK( ( NEW( FunVal )( "x", NEW( Mult )( NEW( Num )( 2 ), NEW( Var )( "x" ) ) ) )->to_expr()->equals(
                    NEW( Fun )( "x", NEW( Mult )( NEW( Num )( 2 ), NEW( Var )( "x" ) ) ) ) );
            //FunVal with nested Let
            CHECK( ( NEW( FunVal )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Let )( "y", NEW( Num )( 5 ), NEW( Add )( NEW( Var )( "y" ),
                                                                                                    NEW( Num )(
                                                                                                            6 ) ) ) ) ) )->to_expr()->equals(
                    NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Let )( "y", NEW( Num )( 5 ),
                                                                    NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 6 ) ) ) ) ) ) );
            //FunVal nested within Fun
            CHECK( ( NEW( FunVal )( "x", NEW( Mult )( NEW( Var )( "x" ), NEW( Fun )( "y", NEW( Add )( NEW( Num )( 4 ), NEW( Var )(
                    "y" ) ) ) ) ) )->to_expr()->equals( NEW( Fun )( "x", NEW( Mult )( NEW( Var )( "x" ), NEW( Fun )( "y", NEW( Add )(
                    NEW( Num )( 4 ), NEW( Var )( "y" ) ) ) ) ) ) );
        }

        SECTION( "FunVal::Equals" )
        {
            //True check
            CHECK( ( NEW( FunVal )( "x", NEW( Add )( NEW( Num )( 5 ), NEW( Num )( 3 ) ) ) )->equals(
                    NEW( FunVal )( "x", NEW( Add )( NEW( Num )( 5 ), NEW( Num )( 3 ) ) ) ) );
            //False check
            CHECK_FALSE( ( NEW( FunVal )( "y", NEW( Mult )( NEW( Num )( 9 ), NEW( Num )( 0 ) ) ) )->equals(
                    NEW( FunVal )( "x", NEW( Add )( NEW( Num )( 5 ), NEW( Num )( 3 ) ) ) ) );
        }

        SECTION( "FunVal::add_to()" )
        {
            CHECK_THROWS_WITH( ( NEW( FunVal )( "x", NEW( Add )( NEW( Num )( 5 ), NEW( Num )( 3 ) ) ) )->add_to( NEW( NumVal )( 7 ) ),
                               "invalid operation on non-number" );
            CHECK_THROWS_WITH(
                    ( NEW( FunVal )( "x", NEW( Add )( NEW( Num )( 5 ), NEW( Num )( 3 ) ) ) )->add_to( NEW( BoolVal )( true ) ),
                    "invalid operation on non-number" );
        }

        SECTION( "FunVal::mult_with()" )
        {
            CHECK_THROWS_WITH(
                    ( NEW( FunVal )( "x", NEW( Add )( NEW( Num )( 5 ), NEW( Num )( 3 ) ) ) )->mult_with( NEW( NumVal )( 7 ) ),
                    "invalid operation on non-number" );
            CHECK_THROWS_WITH(
                    ( NEW( FunVal )( "x", NEW( Add )( NEW( Num )( 5 ), NEW( Num )( 3 ) ) ) )->mult_with( NEW( BoolVal )( 7 ) ),
                    "invalid operation on non-number" );
        }

        SECTION( "FunVal::is_true()" )
        {
            CHECK_THROWS_WITH( ( NEW( FunVal )( "x", NEW( Add )( NEW( Num )( 5 ), NEW( Num )( 3 ) ) ) )->is_true(),
                               "invalid operation on non-number" );
        }

        SECTION( "FunVal::Print" )
        {
            //FunVal with Num
            CHECK( ( NEW( FunVal )( "x", NEW( Num )( 7 ) ) )->to_string() ==
                   "(_fun (x) 7)" );
            //FunVal with Add
            CHECK( ( NEW( FunVal )( "x", NEW( Add )( NEW( Num )( 2 ), NEW( Var )( "x" ) ) ) )->to_string() ==
                   "(_fun (x) (2+x))" );
            //FunVal with Mult
            CHECK( ( NEW( FunVal )( "x", NEW( Mult )( NEW( Num )( 2 ), NEW( Var )( "x" ) ) ) )->to_string() ==
                   "(_fun (x) (2*x))" );
            //FunVal with nested Let
            CHECK( ( NEW( FunVal )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Let )( "y", NEW( Num )( 5 ), NEW( Add )( NEW( Var )( "y" ),
                                                                                                    NEW( Num )(
                                                                                                            6 ) ) ) ) ) )->to_string() ==
                   "(_fun (x) (x+(_let y=5 _in (y+6))))" );
            //FunVal nested within Fun
            CHECK( ( NEW( FunVal )( "x", NEW( Mult )( NEW( Var )( "x" ), NEW( Fun )( "y", NEW( Add )( NEW( Num )( 4 ), NEW( Var )(
                    "y" ) ) ) ) ) )->to_string() ==
                   "(_fun (x) (x*(_fun (y) (4+y))))" );
        }

        SECTION( "FunVal::Call" )
        {

            //FunVal with Num with unsuccessful call substitution
            CHECK( ( NEW( FunVal )( "x", NEW( Num )( 7 ) ) )->call( NEW( NumVal )( 6 ) )->equals( NEW( NumVal )( 7 ) ) );
            //FunVal with Add calling an Add
            CHECK( ( NEW( FunVal )( "x", NEW( Add )( NEW( Num )( 2 ), NEW( Var )( "x" ) ) ) )->call(
                    ( NEW( Add )( NEW( Num )( 4 ), NEW( Num )( 9 ) ) )->interp() )->equals( NEW( NumVal )( 15 ) ) );
            //FunVal with Mult calling a Mult
            CHECK( ( NEW( FunVal )( "x", NEW( Mult )( NEW( Num )( 2 ), NEW( Var )( "x" ) ) ) )->call(
                    ( NEW( Mult )( NEW( Num )( 4 ), NEW( Num )( 9 ) ) )->interp() )->equals( NEW( NumVal )( 72 ) ) );
            //FunVal with nested Let calling a Let
            CHECK( ( NEW( FunVal )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Let )( "y", NEW( Num )( 5 ), NEW( Add )( NEW( Var )( "y" ),
                                                                                                    NEW( Num )(
                                                                                                            6 ) ) ) ) ) )->call(
                    ( NEW( Let )( "y", NEW( Num )( 5 ), NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 6 ) ) ) )->interp() )->equals(
                    NEW( NumVal )( 22 ) ) );
            //FunVal nested within Val that throws exception
            CHECK_THROWS_WITH( ( NEW( FunVal )( "x", NEW( Mult )( NEW( Var )( "x" ), NEW( Fun )( "y", NEW( Add )( NEW( Num )( 4 ),
                                                                                                   NEW( Var )(
                                                                                                           "y" ) ) ) ) ) )->call(
                    NEW( NumVal )( 4 ) ), "invalid operation on non-number" );
            //Trying to call with BoolVal to throw exception
            CHECK_THROWS_WITH(
                    ( NEW( FunVal )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 6 ) ) ) )->call( NEW( BoolVal )( false ) ),
                    "invalid operation on non-number" );
        }

        SECTION( "Parsing" )
        {
            SECTION( "Fun" )
            {
                CHECK( parse_expr( "_fun (x) x + 2" )->equals(
                        NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 2 ) ) ) ) );

                //Fun with Add
                CHECK( parse_expr( "_fun (x)\n"
                                   "  2 + x" )->equals(
                        NEW( Fun )( "x", NEW( Add )( NEW( Num )( 2 ), NEW( Var )( "x" ) ) ) ) );

                //Fun with nested Let
                CHECK( parse_expr( "_fun (x)\n  x + _let y = 5\n      _in  y + 6" )->equals( NEW( Fun )( "x", NEW( Add )(
                        NEW( Var )( "x" ),
                        NEW( Let )( "y", NEW( Num )( 5 ), NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 6 ) ) ) ) ) ) );

                //Fun nested within Add
                CHECK( parse_expr( "4 + _fun (x)\n5 * x" )->equals( NEW( Add )( NEW( Num )( 4 ), NEW( Fun )( "x",
                                                                                                    NEW( Mult )(
                                                                                                            NEW( Num )(
                                                                                                                    5 ),
                                                                                                            NEW( Var )(
                                                                                                                    "x" ) ) ) ) ) );

                //Fun nested within Let
                CHECK( parse_expr( "_let x = 3\n_in  _fun (y)\ny + x" )->equals( NEW( Let )( "x", NEW( Num )( 3 ),
                                                                                          NEW( Fun )( "y", NEW( Add )(
                                                                                                  NEW( Var )( "y" ),
                                                                                                  NEW( Var )(
                                                                                                          "x" ) ) ) ) ) );

                //FunExp nested within Fun
                CHECK( parse_expr( "_fun (x)\n      x * (_fun (y)\n  \n \n 4 + y)" )->equals( NEW( Fun )( "x", NEW( Mult )(
                        NEW( Var )( "x" ), NEW( Fun )( "y", NEW( Add )( NEW( Num )( 4 ), NEW( Var )( "y" ) ) ) ) ) ) );
            }

            SECTION( "Call" )
            {
                //Call with Fun and Var
                CHECK( parse_expr( "(_fun (x)\nx + 4)(x)" )->equals(
                        NEW( Call )( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 4 ) ) ),
                                  NEW( Var )( "x" ) ) ) );

                //Call with Fun and Add
                CHECK( parse_expr( "(_fun (x)\nx + 4)(3 + 8)" )->equals(
                        NEW( Call )( NEW( Fun )( "x", NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 4 ) ) ),
                                  NEW( Add )( NEW( Num )( 3 ), NEW( Num )( 8 ) ) ) ) );

                //Call with Fun and Mult
                CHECK( parse_expr( "(_fun (y)\n y + 7)(1 * 5)" )->equals(
                        NEW( Call )( NEW( Fun )( "y", NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 7 ) ) ),
                                  NEW( Mult )( NEW( Num )( 1 ), NEW( Num )( 5 ) ) ) ) );

                //Call with Fun and Let
                CHECK( parse_expr( "(_fun (y)\n y + 7)(_let x = 9\n   \n  \n _in  x + 4)" )->equals(
                        NEW( Call )( NEW( Fun )( "y", NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 7 ) ) ),
                                  NEW( Let )( "x", NEW( Num )( 9 ),
                                           NEW( Add )( NEW( Var )( "x" ), NEW( Num )( 4 ) ) ) ) ) );

                //Call with Fun and Num
                CHECK( parse_expr( "(_fun (y)\n   \n \n  \n \n \n y + 7)(0)" )->equals(
                        NEW( Call )( NEW( Fun )( "y", NEW( Add )( NEW( Var )( "y" ), NEW( Num )( 7 ) ) ),
                                  NEW( Num )( 0 ) ) ) );
            }
        }
    }
}