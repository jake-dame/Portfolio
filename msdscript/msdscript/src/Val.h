/******************************************************************************
 * \brief Val bass class + derived class declarations
 *
 * \file Val.h
 * \author Jake Dame
 *****************************************************************************/

#pragma once

#include "pointers.h"

class Expr; /* Expr class for Val::to_expr() */
class Env;

/******************************************************************************
 * \class Val
 * \brief An abstract, base class representing a the value of an expression
 *
 * The Val class is an abstract class that defines regular and
 * virtual functions that can be used to represent two mathematical
 * values -- boolean values (BoolVal class) and integer values (NumVal class)
 * -- of mathematical expressions (Expr class in Expr.h); calling interp() on
 * an Expr object returns a Val object.
 *
 * The Val class  handles base-level addition ( add_to() )and multiplication
 * ( mult_with() ); it supports comparison between Val objects ( equals() ),
 * and conversion to analogous Expr objects as well ( to_expr() ).
 *****************************************************************************/
CLASS( Val )
{

public:

    /*
     * Non-virtual methods
     */
    std::string to_string();

    /*
     * Pure virtual methods
     */
    virtual PTR( Expr ) to_expr() = 0;

    virtual bool equals( PTR( Val ) v ) = 0;

    virtual PTR( Val ) add_to( PTR( Val ) v ) = 0;

    virtual PTR( Val ) mult_with( PTR( Val ) v ) = 0;

    virtual bool is_true() = 0;

    virtual void print( std::ostream & stream ) = 0;

    virtual PTR( Val ) call( PTR( Val ) actual_arg ) = 0;

    /*
     * Regular virtual methods
     */
    virtual ~Val() = default; // TODO
};

/******************************************************************************
 * \class NumVal
 * \brief A Val derived class representing an integer value
 *
 * A NumVal object represents an integer value of a mathematical expression.
 *****************************************************************************/
class NumVal : public Val
{

public:

    int int_m;

    explicit NumVal( int val );

    PTR( Expr ) to_expr() override;

    bool equals( PTR( Val ) v ) override;

    PTR( Val ) add_to( PTR( Val ) other_val ) override;

    PTR( Val ) mult_with( PTR( Val ) other_val ) override;

    bool is_true() override;

    void print( std::ostream & ostream ) override;

    PTR( Val ) call( PTR( Val ) actual_arg ) override;
};

/******************************************************************************
 * \class BoolVal
 * \brief A Val derived class representing a boolean value
 *
 * A BoolVal object represents a boolean value of a mathematical expression.
 *****************************************************************************/
class BoolVal : public Val
{

public:

    bool bool_m;

    explicit BoolVal( bool val );

    PTR( Expr ) to_expr() override;

    bool equals( PTR( Val ) v ) override;

    PTR( Val ) add_to( PTR( Val ) other_val ) override;

    PTR( Val ) mult_with( PTR( Val ) other_val ) override;

    bool is_true() override;

    void print( std::ostream & ostream ) override;

    PTR( Val ) call( PTR( Val ) actual_arg ) override;
};

class FunVal : public Val
{

public:

    std::string formal_arg_m;
    PTR( Expr ) body_m;
	PTR( Env ) env_m;

    FunVal( std::string arg, PTR( Expr ) body, PTR( Env ) env = nullptr );

    PTR( Expr ) to_expr() override;

    bool equals( PTR( Val ) v ) override;

    PTR( Val ) add_to( PTR( Val ) v ) override;

    PTR( Val ) mult_with( PTR( Val ) v ) override;

    bool is_true() override;

    void print( std::ostream & stream ) override;

    PTR( Val ) call( PTR( Val ) actual_arg ) override;
};