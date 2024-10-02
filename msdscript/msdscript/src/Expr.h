/******************************************************************************
 * \brief Expr bass class + derived class declarations
 *
 * \file Expr.h
 * \author Jake Dame
 *****************************************************************************/

#pragma once

#include <sstream>      /* std::stringstream */
#include <utility>      /* std::move (for Var constructor) */

#include "pointers.h"   /* Macros for msdscript */

class Val;              /* Val class for Expr::interp() */
class Env;              /* Env class for Expr::interp() */

/******************************************************************************
 * \typedef precedence_t
 * \brief Assists in nested/parenthetical expression precedence typing
 *****************************************************************************/
typedef enum
{
    NONE = 0,  ///< default precedence for Num and Var
    ADD = 1,     ///< default precedence for Add
    MULT = 2      ///< default precedence for Mult
} prec_t;

/******************************************************************************
 * \class Expr
 * \brief An abstract, base class representing a mathematical expression.
 *
 * The Expression class is an abstract class that defines regular and
 * virtual functions used to perform various mathematical operations. These
 * include basic number and variable expressions, as well as operational
 * expressions such as addition, multiplication, and let substitution. All
 * classes that inherit from the Expression class are also able to print as a
 * string in two different styles.
 *****************************************************************************/
CLASS( Expr )
{
public:

    /*
     * Non-virtual methods
     */
    std::string to_string();

    std::string to_pretty_string();

    /*
     * Pure virtual methods
     */
    virtual bool equals( PTR( Expr ) e ) = 0;

    virtual PTR( Val ) interp( PTR( Env ) env = nullptr ) = 0;

    virtual bool has_variable() = 0;

    virtual PTR( Expr ) subst( std::string str, PTR( Expr ) e ) = 0;

    virtual void print( std::ostream & stream ) = 0;

    /*
     * Regular virtual methods
     */
    virtual ~Expr() = default;

    virtual void pretty_print( std::ostream & stream )
    {
        print( stream );
    }

    virtual void pretty_print_at( std::ostream & stream,
                                  prec_t caller_prec,
                                  std::streampos & caller_pos,
                                  bool has_paren )
    {
        pretty_print( stream );
    }
};

/******************************************************************************
 * \class Num
 * \brief An Expr derived class representing a basic integer
 *****************************************************************************/
class Num : public Expr
{

public:

    int int_m; ///< The integer value of the Num object

    explicit Num( int val );

    bool equals( PTR( Expr ) e ) override;

    PTR( Val ) interp( PTR( Env ) env = nullptr ) override;

    bool has_variable() override;

    PTR( Expr ) subst( std::string str, PTR( Expr ) e ) override;

private:

    void print( std::ostream & stream ) override;
};

/******************************************************************************
 * \class Bool
 * \brief An Expr derived class representing a basic boolean value
 *****************************************************************************/
class Bool : public Expr
{

public:

    bool bool_m; ///< The boolean value of the Bool object

    explicit Bool( bool val );

    bool equals( PTR( Expr ) e ) override;

    PTR( Val ) interp( PTR( Env ) env = nullptr ) override;

    bool has_variable() override;

    PTR( Expr ) subst( std::string str, PTR( Expr ) e ) override;

private:

    void print( std::ostream & stream ) override;
};

/******************************************************************************
 * \class Eq
 * \brief An Expr derived class representing an equality operation/comparison
 *
 * The Eq class compares two other Expr objects, and checks for equality. Its
 * value is defined by a BoolVal object. E.g. "Expr == Expr". If the Expr
 * objects are equal, an Eq object will have a BoolVal of "_true". If they are
 * not, it will be "_false."
 *****************************************************************************/
class Eq : public Expr
{

public:

    PTR( Expr ) lhs_m;     ///< The lhs operand of an equality operation
    PTR( Expr ) rhs_m;     ///< The rhs operand of an equality operation

    Eq( PTR( Expr ) lhs, PTR( Expr ) rhs );

    bool equals( PTR( Expr ) e ) override;

    PTR( Val ) interp( PTR( Env ) env = nullptr ) override;

    bool has_variable() override;

    PTR( Expr ) subst( std::string str, PTR( Expr ) e ) override;

private:

    void print( std::ostream & stream ) override;

    void pretty_print( std::ostream & stream ) override;

    void pretty_print_at( std::ostream & stream,
                          prec_t caller_prec,
                          std::streampos & caller_pos,
                          bool has_paren ) override;
};

/******************************************************************************
 * \class Add
 * \brief An Expr derived class representing an addition operation
 *
 * The Add class is constructed with two values: a left-hand side (lhs) value,
 * and a right-hand side (rhs) value. These values can be either a Number
 * (object), or a Variable (object), or another Add or Multiplication object
 * (nested). If both values are Numbers, they can be interpreted to be their
 * sum. The Add object supports Variable substitution, and precedence-based
 * printing of parentheses.
 *****************************************************************************/
class Add : public Expr
{

public:

    PTR( Expr ) lhs_m; ///< The lhs operand of an addition operation
    PTR( Expr ) rhs_m; ///< The rhs operand of an addition operation

    Add( PTR( Expr ) lhs, PTR( Expr ) rhs );

    bool equals( PTR( Expr ) e ) override;

    PTR( Val ) interp( PTR( Env ) env = nullptr ) override;

    bool has_variable() override;

    PTR( Expr ) subst( std::string str, PTR( Expr ) e ) override;

private:

    void print( std::ostream & stream ) override;

    void pretty_print( std::ostream & stream ) override;

    void pretty_print_at( std::ostream & stream,
                          prec_t caller_prec,
                          std::streampos & caller_pos,
                          bool has_paren ) override;
};

/******************************************************************************
 * \class Mult
 * \brief An Expr derived class representing a multiplication operation
 *
 * The Multiplication class is constructed with two values: a left-hand side
 * (lhs) value, and a right-hand side (rhs) value. These values can be either
 * a Number (object), or a Variable (object), or another Add or Multiplication
 * object (nested). If both values are Numbers, they can be interpreted to be
 * their product. The Multiplication object supports Variable substitution,
 * and precedence-based printing of parentheses.
 *****************************************************************************/
class Mult : public Expr
{

public:

    PTR( Expr ) lhs_m; ///< The lhs operand of a multiplication operation
    PTR( Expr ) rhs_m; ///< The rhs operand of an multiplication operation

    Mult( PTR( Expr ) lhs, PTR( Expr ) rhs );

    bool equals( PTR( Expr ) e ) override;

    PTR( Val ) interp( PTR( Env ) env = nullptr ) override;

    bool has_variable() override;

    PTR( Expr ) subst( std::string str, PTR( Expr ) e ) override;

private:

    void print( std::ostream & stream ) override;

    void pretty_print( std::ostream & stream ) override;

    void pretty_print_at( std::ostream & stream,
                          prec_t caller_prec,
                          std::streampos & caller_pos,
                          bool has_paren ) override;
};

/******************************************************************************
 * \class Var
 * \brief An Expr derived class representing a string placeholder (variable)
 *
 * The Variable class is ultimately a representation of the value
 * of it's int_m member variable. It can be wrapped in other Expression
 * classes when performing operations such as addition and multiplication,
 * but cannot be interpreted to an integer value -- unless it is substituted.
 *****************************************************************************/
class Var : public Expr
{

public:

    std::string str_m; ///< The string value of the Var object

    explicit Var( std::string str );

    bool equals( PTR( Expr ) e ) override;

    PTR( Val ) interp( PTR( Env ) env = nullptr ) override;

    bool has_variable() override;

    PTR( Expr ) subst( std::string str, PTR( Expr ) e ) override;

private:

    void print( std::ostream & stream ) override;
};

/******************************************************************************
 * \class Let
 * \brief An Expr derived class supporting let binding
 *
 * The Let class allows for let binding, which allows for the declaration
 * of a variable and its definition with an Expression, within the scope of
 * Let's "body" Expression. This can be utilized in Expressions that have
 * variables to declare/define a variable, without calling any other functions
 * for substitution, etc. Example: _let x = 5 _in 3 * x
 *****************************************************************************/
class Let : public Expr
{

public:

    std::string lhs_m;    ///< The Let object's variable name
    PTR( Expr ) rhs_m;    ///< The Let object's variable definition
    PTR( Expr ) body_m;   ///< The expression in which the variable
                          ///< declaration/definition applies

    Let( std::string lhs, PTR( Expr ) rhs, PTR( Expr ) body );

    bool equals( PTR( Expr ) e ) override;

    PTR( Val ) interp( PTR( Env ) env = nullptr ) override;

    bool has_variable() override;

    PTR( Expr ) subst( std::string str, PTR( Expr ) e ) override;

private:

    void print( std::ostream & stream ) override;

    void pretty_print( std::ostream & stream ) override;

    void pretty_print_at( std::ostream & stream,
                          prec_t caller_prec,
                          std::streampos & caller_pos,
                          bool has_paren ) override;
};

/******************************************************************************
 * \class If
 * \brief An Expr derived class representing a conditional operation expression
 *
 * An If object has a condition operand, and two branch operands (i.e. "then"
 * and "else"). It can "evaluate" the condition operand, and then embody a
 * value based on the result of that evaluation. If the condition has a BoolVal
 * of "_true", the If object will come to have a value equal to its then_m
 * operand; the opposite is true for the else_m operand.
 *****************************************************************************/
class If : public Expr
{

public:

    PTR( Expr ) test_m; ///< The condition operand of an If expression
    PTR( Expr ) then_m; ///< Branch 1 operand of an If expression
    PTR( Expr ) else_m; ///< Branch 2 operand of an If expression

    If( PTR( Expr ) condition, PTR( Expr ) first_branch, PTR( Expr ) second_branch );

    bool equals( PTR( Expr ) e ) override;

    PTR( Val ) interp( PTR( Env ) env = nullptr ) override;

    bool has_variable() override;

    PTR( Expr ) subst( std::string str, PTR( Expr ) e ) override;

private:

    void print( std::ostream & stream ) override;

    void pretty_print( std::ostream & stream ) override;

    void pretty_print_at( std::ostream & stream,
                          prec_t caller_prec,
                          std::streampos & caller_pos,
                          bool has_paren ) override;
};

class Fun : public Expr
{

public:

    std::string formal_arg_m;
    PTR( Expr ) body_m;

    Fun( std::string formal_arg, PTR( Expr ) body );

    bool equals( PTR( Expr ) e ) override;

    PTR( Val ) interp( PTR( Env ) env = nullptr ) override;

    bool has_variable() override;

    PTR( Expr ) subst( std::string str, PTR( Expr ) e ) override;

private:

    void print( std::ostream & stream ) override;

    void pretty_print( std::ostream & stream ) override;

    void pretty_print_at( std::ostream & stream,
                          prec_t caller_prec,
                          std::streampos & caller_pos,
                          bool has_paren ) override;
};

class Call : public Expr
{

public:

    PTR( Expr ) to_be_called_m;
    PTR( Expr ) actual_arg_m;

    Call( PTR( Expr ) to_be_called, PTR( Expr ) actual_arg );

    bool equals( PTR( Expr ) e ) override;

    PTR( Val ) interp( PTR( Env ) env = nullptr ) override;

    bool has_variable() override;

    PTR( Expr ) subst( std::string str, PTR( Expr ) e ) override;

private:

    void print( std::ostream & stream ) override;

    void pretty_print( std::ostream & stream ) override;

    void pretty_print_at( std::ostream & stream,
                          prec_t caller_prec,
                          std::streampos & caller_pos,
                          bool has_paren ) override;
};