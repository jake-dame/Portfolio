/******************************************************************************
 * \brief Expr bass class and derived class definitions
 *
 * \file Expr.cpp
 * \author Jake Dame
 *****************************************************************************/

#include <iostream>     /* Console I/O */
#include <stdexcept>    /* exceptions handling */

#include "Env.h"
#include "Expr.h"
#include "Val.h"

/******************************************************************************
 * \brief Non-virtual: Converts an Expr object to a basic, easily-readable
 * string
 *
 * \return A basic std::string version of an Expr object
 *
 * By calling the print() method of the Expr class, the to_string()
 * method constructs and returns an accurate string representation of an
 * Expr object. All Add and Mult expressions are surrounded
 * by parentheses; there is no spacing between any characters.
 *****************************************************************************/
std :: string Expr::to_string()
{
    std::stringstream stream( "" );
    print( stream );
    return stream.str();
}

/******************************************************************************
 * \brief Non-virtual: Converts an Expr object to a stylized, easily-readable
 * string
 *
 * \return A stylized std::string version of an Expr object
 *
 * By calling the pretty_print() method of the Expr class, the
 * to_string() method constructs and returns an accurate and conventionally
 * styled (i.e. spacing added, parentheses added only selectively) string
 * representation of an Expr object.
 *****************************************************************************/
std :: string Expr::to_pretty_string()
{
    std::stringstream stream( "" );
    pretty_print( stream );
    return stream.str();
}

/******************************************************************************
 * \brief Constructs a Num object representing an integer expression
 *
 * \param val An int to define this Num object's int_m value
 *****************************************************************************/
Num :: Num( int val )
{
    int_m = val;
}

/******************************************************************************
 * \brief Compares an object to this Num object
 *
 * \param v The object to compare this Num object to
 * \return True if the two objects are both Num objects and represent
 * equivalent int_m values
 *****************************************************************************/
bool Num :: equals( PTR( Expr ) e )
{
    PTR( Num ) num_cmp = CAST( Num )( e );
    return num_cmp != nullptr && int_m == num_cmp->int_m;
}

/******************************************************************************
 * \brief Simplifies a Num object to its NumVal object equivalent
 *
 * \return A NumVal object representing this Num object's integer value
 *****************************************************************************/
PTR( Val ) Num :: interp( PTR( Env ) env )
{
    return NEW( NumVal )( int_m );
}

/******************************************************************************
 * \brief This function always returns false. See: Var::has_variable()
 *
 * \return Always false, for objects of this type
 *****************************************************************************/
bool Num :: has_variable()
{
    return false;
}

/******************************************************************************
 * \brief This function will always return an object equivalent to itself
 *
 * \param str N/A
 * \param e N/A
 * \return A new Num object, with an identical value as the caller
 *
 * The Num class must implement this, but simply returns an identical copy of
 * itself, as nothing can be substituted.
 *****************************************************************************/
PTR( Expr ) Num :: subst( std::string str, PTR( Expr ) e )
{
    return NEW( Num )( int_m );
}

/******************************************************************************
 * \brief Writes a Num object's string representation to an output stream
 *
 * \param stream A reference to an output stream to write to
 *
 * For the Num class, this simply means writing this object's int_m value, as a
 * string, to the output stream. No parentheses or spaces are added.
 *****************************************************************************/
void Num :: print( std::ostream & stream )
{
    stream << std::to_string( int_m );
}

/******************************************************************************
 * \brief Constructs a Bool object representing a boolean expression
 *
 * \param val A bool to define this Bool object's bool_m value
 *****************************************************************************/
Bool :: Bool( bool val )
{
    bool_m = val;
}

/******************************************************************************
 * \brief Compares an object to this Bool object
 *
 * \param v The object to compare this Bool object to
 * \return True if the two objects are both Bool objects and represent
 * equivalent bool_m values
 *****************************************************************************/
bool Bool :: equals( PTR( Expr ) e )
{
   PTR( Bool ) bool_cmp = CAST( Bool )( e );
    return bool_cmp != nullptr && bool_m == bool_cmp->bool_m;
}

/******************************************************************************
 * \brief Simplifies a Bool object to its BoolVal object equivalent
 *
 * \return A BoolVal object representing this Bool object's boolean value
 *****************************************************************************/
PTR( Val ) Bool :: interp( PTR( Env ) env )
{
    return NEW( BoolVal )( bool_m );
}

/******************************************************************************
 * \brief This function always returns false. See: Var::has_variable()
 *
 * \return Always false, for objects of this type
 *****************************************************************************/
bool Bool :: has_variable()
{
    return false;
}

/******************************************************************************
 * \brief This function will always return an object equivalent to itself
 *
 * \param str N/A
 * \param e N/A
 * \return A new Bool object, with an identical value as the caller
 *
 * The Bool class must implement this, but simply returns an identical copy of
 * itself, as nothing can be substituted.
 *****************************************************************************/
PTR( Expr ) Bool :: subst( std::string str, PTR( Expr ) e )
{
    return NEW( Bool )( bool_m );
}

/******************************************************************************
 * \brief Writes a Bool object's string representation to an output stream
 *
 * \param stream A reference to an output stream to write to
 *
 * For the Bool class, this simply means writing this object's bool_m value, as a
 * string, to the output stream. No parentheses or spaces are added.
 *****************************************************************************/
void Bool :: print( std::ostream & stream )
{
    stream << ( bool_m ? "_true" : "_false" );
}

/******************************************************************************
 * \brief Constructs an Eq object representing two Exprs to be compared
 *
 * \param lhs An Expr to define this Eq object's lhs (operand)
 * \param rhs An Expr to define this Eq object's rhs (operand)
 *
 * Any Expr class object can be used as a parameter. Nums and Vars act as
 * terminal operands/expression, while Add/Mult objects act as nested
 * expressions.
 *****************************************************************************/
Eq :: Eq( PTR( Expr ) lhs, PTR( Expr ) rhs )
{
    lhs_m = lhs;
    rhs_m = rhs;
}

/******************************************************************************
 * \brief Compares two Eq objects
 *
 * \param e The Expr object to compare this object to
 * \return True if the two objects are both Eq objects and represent
 * equivalent lhs and rhs values
 *
 * Calls equals() recursively on both lhs and rhs values of this object. All
 * calls to equals(), including on nested expressions, must return true each
 * time for an Eq object to be considered equal to another Eq object.
 *****************************************************************************/
bool Eq :: equals( PTR( Expr ) e )
{
   PTR( Eq ) eq_cmp = CAST( Eq )( e );
    return eq_cmp != nullptr &&
           lhs_m->equals( eq_cmp->lhs_m ) &&
           rhs_m->equals( eq_cmp->rhs_m );
}

/******************************************************************************
 * \brief Simplifies an Eq object to its boolean value
 *
 * \return A BoolVal object representing the this Eq object's boolean value
 *
 * Calls interp() recursively on the lhs and rhs of an Eq, until it
 * reaches either a Num or a Var. Nums call Num::interp(), which returns a
 * NumVal object. If Vars are encountered, an exception is thrown
 * ( See: Var::interp() ).
 *****************************************************************************/
PTR( Val ) Eq :: interp( PTR( Env ) env )
{
    bool res = ( lhs_m->interp( env ) )->equals( rhs_m->interp( env ) );
    return NEW( BoolVal )( res );
}

/******************************************************************************
 * \brief Evaluates whether an Eq object includes a Var as an operand
 *
 * \return True if an Eq object's lhs or rhs is a Var object (at any level),
 * or false if there are none.
 *
 * Employed recursively, this method returns true if this Expr object (or any
 * Expr object nested within it) have a lhs or rhs of type Var.
 *****************************************************************************/
bool Eq :: has_variable()
{
    return lhs_m->has_variable() || rhs_m->has_variable();
}

/******************************************************************************
 * \brief Replaces a Var within an Eq object with another Expr object
 *
 * \param str The string value, or "variable", to replace
 * \param e The Expr object to replace the "variable" with
 * \return A new Eq object, with the necessary substitutions
 *
 * If an Eq contains a user-inputted string, the string will be replaced where
 * it occurs with another user-inputted parameter. The Var class is responsible
 * for checking whether the string that is searched for is actually contained
 * by the Expression calling it. (See: Var::subst() ). This method is called
 * recursively on both the lhs and rhs values of an Eq object. The "variable"
 * in question is replaced at all levels of nesting.
 *****************************************************************************/
PTR( Expr ) Eq :: subst( std::string str, PTR( Expr ) e )
{
    return NEW( Eq )( lhs_m->subst( str, e ), rhs_m->subst( str, e ) );
}

/******************************************************************************
 * \brief Writes an Eq's basic string representation to an output stream
 *
 * \param stream A reference to an output stream to write to
 *
 * Called recursively on both the lhs and rhs Exprs of this
 * object. No spaces are added. One pair of parentheses surrounds the
 * outermost characters of each Eq object.
 *****************************************************************************/
void Eq :: print( std::ostream & stream )
{
    stream << "(";
    lhs_m->print( stream );
    stream << "==";
    rhs_m->print( stream );
    stream << ")";
}

/******************************************************************************
 * \brief Driver method for pretty_print_at()
 *
 * \param stream A reference to an output stream to write to
 *****************************************************************************/
void Eq :: pretty_print( std::ostream & stream )
{
    prec_t         driver_prec = NONE;
    std::streampos driver_cursor_pos = 0;
    bool           driver_paren = false;

    pretty_print_at( stream, driver_prec, driver_cursor_pos, driver_paren );
}

/******************************************************************************
 * \brief Writes an Eq's stylized string representation to an output stream
 *
 * \param stream A reference to an output stream to write to
 * \param caller_prec The precedence level that this object should have,
 *                    which is determined by the caller
 * \param caller_pos The cursor position passed by the caller indicating
 *                   where the callee should begin printing
 * \param has_paren A boolean used to apply parentheses selectively
 *
 * Called recursively on both the lhs and rhs Exprs of this Eq
 * object. Spaces are added between operators and operands. Pairs of
 * parentheses are added on a precedence and right-associative basis.
 *****************************************************************************/
void Eq :: pretty_print_at( std::ostream & stream, prec_t caller_prec,
                            std::streampos & caller_pos, bool has_paren )
{
    bool close_paren = false;
    if ( caller_prec > NONE && !has_paren )
    {
        stream << "(";
        close_paren = true;
    }

    lhs_m->pretty_print_at( stream, static_cast<prec_t>( NONE + 1 ),
                            caller_pos, has_paren );

    stream << " == ";

    rhs_m->pretty_print_at( stream, NONE, caller_pos, has_paren );

    if( close_paren )
        stream << ")";
}

/******************************************************************************
 * \brief Constructs an Add object representing two Exprs to be added
 *
 * \param lhs An Expression to define this Addition object's lhs (operand)
 * \param rhs An Expression to define this Addition object's rhs (operand)
 *
 * Any Expression class object can be used as a parameter. Numbers and
 * Variables act as terminal operands/Expressions, while
 * Addition/Multiplication objects act as nested Expressions.
 *****************************************************************************/
Add :: Add( PTR( Expr ) lhs, PTR( Expr ) rhs )
{
    lhs_m = lhs;
    rhs_m = rhs;
}

/******************************************************************************
 * \brief Compares two Add objects
 *
 * \param e The Expression to compare this object to
 * \return True if the Addition objects represent equivalent values; false
 * if not, or if the two objects compared are not both of type Add.
 *
 * Calls equals() recursively on both lhs and rhs values of this object. All
 * calls to equals(), including on nested expressions, must return true each
 * time for an Add object to be considered equal to another Addition object.
 *****************************************************************************/
bool Add :: equals( PTR( Expr ) e )
{
    PTR( Add ) add_cmp = CAST( Add )( e );
    return add_cmp != nullptr &&
           lhs_m->equals( add_cmp->lhs_m ) &&
           rhs_m->equals( add_cmp->rhs_m );
}

/******************************************************************************
 * \brief Simplifies an Addition object to its integer value
 *
 * \return A Val object representing the sum of this Add object's lhs and rhs
 *
 * Calls interp() recursively on the lhs and rhs of an Expression, until it
 * reaches either a Number or a Variable. Number values are summed, and this
 * call ultimately returns all values of the Expression (including
 * nested Expressions) summed. If Variables are encountered, an exception is
 * thrown (see: Var::interp()).
 *****************************************************************************/
PTR( Val ) Add :: interp( PTR( Env ) env )
{
	if ( env == nullptr )
	{
		env = Env::empty;
	}

    return lhs_m->interp( env )->add_to( rhs_m->interp( env ) );
}

/******************************************************************************
 * \brief Evaluates whether an Add object includes a Variable as an operand
 *
 * \return True if an Add object's lhs or rhs is a Var object (at any level),
 * or false if there are none.
 *
 * Employed recursively, this method returns true if this Expression (or any
 * Expression nested within it) have a lhs or rhs of type Variable.
 *****************************************************************************/
bool Add :: has_variable()
{
    return lhs_m->has_variable() || rhs_m->has_variable();
}

/******************************************************************************
 * \brief Replaces a Var within an Add object with another Expression
 *
 * \param str The string value, or Variable, to replace.
 * \param e The Expression to replace the Variable with.
 * \return A new Addition object, with the requested Expression substitution.
 *
 * If an Expression contains a user-inputted string value (e.g. Variable
 * value), the string will be re-assigned with another user-inputted
 * Expression value where it occurs. The Variable class is responsible for
 * checking whether the string that is searched for is actually contained by
 * the Expression calling it. If it is, its value is re-assigned. If not, it
 * simply returns a copy of itself. This method is called recursively on both
 * the lhs and rhs values of an Addition object. The Variable in question is
 * replaced at all levels of nesting.
 *****************************************************************************/
PTR( Expr ) Add :: subst( std::string str, PTR( Expr ) e )
{
    return NEW( Add )( lhs_m->subst( str, e ), rhs_m->subst( str, e ) );
}

/******************************************************************************
 * \brief Writes an Add's basic string representation to an output stream
 *
 * \param stream A reference to an output stream to write to
 *
 * Called recursively on both the lhs and rhs Expressions of this Addition
 * object. No spaces are added. One pair of parentheses surrounds the
 * outermost characters of each Addition expression.
 *****************************************************************************/
void Add :: print( std::ostream & stream )
{
    stream << "(";
    lhs_m->print( stream );
    stream << "+";
    rhs_m->print( stream );
    stream << ")";
}

/******************************************************************************
 * \brief Driver method for pretty_print_at()
 *
 * \param stream A reference to an output stream to write to
 *****************************************************************************/
void Add :: pretty_print( std::ostream & stream )
{
    prec_t         driver_prec = ADD;
    std::streampos driver_cursor_pos = 0;
    bool           driver_paren = false;

    pretty_print_at( stream, driver_prec, driver_cursor_pos, driver_paren );
}

/******************************************************************************
 * \brief Writes an Add's stylized string representation to an output stream
 *
 * \param stream A reference to an output stream to write to.
 * \param caller_prec The precedence level that this object should have,
 *                    which is determined by the caller
 * \param caller_pos The cursor position passed by the caller indicating
 *                   where the callee should begin printing
 * \param has_paren A boolean used to apply parentheses selectively.
 *
 * Called recursively on both the lhs and rhs Expressions of this Addition
 * object. Spaces are added between operators and operands. Pairs of
 * parentheses are added on a precedence basis (operands associate to the
 * right; PEMDAS rules are followed).
 *****************************************************************************/
void Add :: pretty_print_at( std::ostream & stream, prec_t caller_prec,
                             std::streampos & caller_pos, bool has_paren )
{
    bool close_paren = false;
    if ( caller_prec > ADD )
    {
        stream << "(";
        close_paren = true;
    }

    lhs_m->pretty_print_at( stream, static_cast<prec_t>( ADD + 1 ),
                            caller_pos, has_paren );

    stream << " + ";

    rhs_m->pretty_print_at( stream, NONE, caller_pos, has_paren );

    if ( close_paren )
        stream << ")";
}

/******************************************************************************
 * \brief Constructs a Mult object representing two Exprs to be multiplied
 *
 * \param lhs An Expression to define this Multiplication object's lhs operand
 * \param rhs An Expression to define this Multiplication object's rhs operand
 *
 * Any Expression class object can be used as a parameter. Numbers and
 * Variables act as terminal operands/Expressions, while
 * Addition/Multiplication objects act as nested Expressions.
 *****************************************************************************/
Mult :: Mult( PTR( Expr ) lhs, PTR( Expr ) rhs )
{
    lhs_m = lhs;
    rhs_m = rhs;
}

/******************************************************************************
 * \brief Compares two Mult objects
 *
 * \param e The Expression to compare this object to
 * \return True if the Multiplication objects represent equivalent values;
 * false if not, or if the two objects compared are not both of type
 * Multiplication
 *
 * Calls equals() recursively on both lhs and rhs values of this object. All
 * calls to equals(), including on nested expressions, must return true each
 * time for an Multiplication object to be considered equal to another
 * Multiplication object.
 *****************************************************************************/
bool Mult :: equals( PTR( Expr ) e )
{
    PTR( Mult ) mult_cmp = CAST( Mult )( e );
    return mult_cmp != nullptr &&
           lhs_m->equals( mult_cmp->lhs_m ) &&
           rhs_m->equals( mult_cmp->rhs_m );
}

/******************************************************************************
 * \brief Simplifies a Multiplication object to its integer value
 *
 * \return A Val object representing the product of this Mult's lhs and rhs
 *
 * Calls interp() recursively on the lhs and rhs of an Expression, until it
 * reaches  either a Number or a Variable. Number values are multiplied
 * together, and this call ultimately returns all values of the Expression
 * (including nested Expressions) multiplied together. If Variables are
 * encountered, an exception is thrown (see: Var::interp()).
 *****************************************************************************/
PTR( Val ) Mult :: interp( PTR( Env ) env )
{
	if ( env == nullptr )
	{
		env = Env::empty;
	}

	return lhs_m->interp( env )->mult_with( rhs_m->interp( env ) );
}

/******************************************************************************
 * \brief Evaluates whether an Mult object includes a Variable as an operand
 *
 * \return True if a Multiplication object's lhs or rhs is a Variable object
 * (at any level), or false if there are none.
 *
 * Employed recursively, this method returns true if this Expression
 * (or any Expression nested within it) have a lhs or rhs of type Variable.
 *****************************************************************************/
bool Mult :: has_variable()
{
    return lhs_m->has_variable() || rhs_m->has_variable();
}

/******************************************************************************
 * \brief Replaces a Var within a Mult object with another Expr
 *
 * \param str The string value, or Var, to replace
 * \param e The Expr to replace the Var with
 * \return A new Mult object, with the requested Expr substitution
 *
 * If an Expression contains a user-inputted string value (e.g. Variable
 * value), the string will be re-assigned with another user-inputted
 * Expression value where it occurs. The Variable class is responsible for
 * checking whether the string that is searched for is actually contained by
 * the Expression calling it. If it is, its value is re-assigned. If not, it
 * simply returns a copy of itself. This method is called recursively on both
 * the lhs and rhs values of a Multiplication object. The Variable in question
 * is replaced at all levels of nesting.
 *****************************************************************************/
PTR( Expr ) Mult :: subst( std::string str, PTR( Expr ) e )
{
    return NEW( Mult )( lhs_m->subst( str, e ), rhs_m->subst( str, e ) );
}

/******************************************************************************
 * \brief Writes a Mult's basic string representation to an output stream
 *
 * \param stream A reference to an output stream to write to
 *
 * Called recursively on both the lhs and rhs operands of this object.
 * No spaces are added. One pair of parentheses surrounds the outermost
 * characters of each Multiplication expression.
 *****************************************************************************/
void Mult :: print( std::ostream & stream )
{
    stream << "(";
    lhs_m->print( stream );
    stream << "*";
    rhs_m->print( stream );
    stream << ")";
}

/******************************************************************************
 * \brief Driver method for pretty_print_at()
 *
 * \param stream A reference to an output stream to write to
 *****************************************************************************/
void Mult :: pretty_print( std::ostream & stream )
{
    prec_t         driver_prec = MULT;
    std::streampos driver_cursor_pos = 0;
    bool           driver_paren = false;

    pretty_print_at( stream, driver_prec, driver_cursor_pos, driver_paren );
}

/******************************************************************************
 * \brief Writes an Mult's stylized string representation to an output stream
 *
 * \param stream A reference to an output stream to write to
 * \param caller_prec The precedence level that this object should have,
 *                    which is determined by the caller
 * \param caller_pos The cursor position passed by the caller indicating
 *                   where the callee should begin printing
 * \param has_paren A boolean used to apply parentheses selectively
 *
 * Called recursively on both the lhs and rhs operands of this
 * Mult object. Spaces are added between operators and operands.
 * Pairs of parentheses are added on a precedence basis (operands associate
 * to the right; PEMDAS rules are followed).
 *****************************************************************************/
void Mult :: pretty_print_at( std::ostream & stream, prec_t caller_prec,
                              std::streampos & caller_pos, bool has_paren )
{
    bool close_paren = false;
    if ( caller_prec > MULT )
    {
        has_paren = true;
        stream << "(";
        close_paren = true;
    }

    lhs_m->pretty_print_at( stream, static_cast<prec_t>( MULT + 1 ),
                            caller_pos, has_paren );

    stream << " * ";

    rhs_m->pretty_print_at( stream, MULT, caller_pos, has_paren );

    if( close_paren )
        stream << ")";
}

/******************************************************************************
 * \brief Constructs a Var object representing a variable (i.e. a string)
 *
 * \param str A string to define this Variable object's string value.
 *****************************************************************************/
Var :: Var( std::string str )
{
    str_m = std::move( str );
}

/******************************************************************************
 * \brief Compares two Variable objects
 *
 * \param e The Expression to compare this object to
 * \return True if the Variable objects represent equivalent string values;
 * false if not, or if the two objects compared are not both of type Variable.
 *
 *****************************************************************************/
bool Var :: equals( PTR( Expr ) e )
{
    PTR( Var ) var_cmp = CAST( Var )( e );
    return var_cmp != nullptr && str_m == var_cmp->str_m;
}

/******************************************************************************
 * \brief This should not be called on a Variable object
 *
 * \throws std::runtime_error You cannot call interp() on a Variable object
 * \return This function will never return
 *****************************************************************************/
PTR( Val ) Var :: interp( PTR( Env ) env )
{
	if ( env == nullptr )
	{
		env = Env::empty;
	}

    return env->lookup( str_m );
}

/******************************************************************************
 * \brief Evaluates whether a Variable object includes a Variable as an operand
 *
 * \return Always true, for objects of this type.
 *****************************************************************************/
bool Var :: has_variable()
{
    return true;
}

/******************************************************************************
 * \brief Substitutes/replaces a Variable with another Expression
 *
 * \param str The string value, or Variable, to replace
 * \param e The Expression to replace the Variable with
 * \return A new Variable object, with the requested Expression substitution
 *
 * If an Expression contains a user-inputted string value
 * (e.g. Variable value), the string will be re-assigned with another
 * user-inputted Expression value where it occurs. The Variable class is also
 * responsible for checking whether the string that is searched for is
 * actually contained by the Expression calling it. If it is, its value is
 * re-assigned. If not, it simply returns a copy of itself.
 *****************************************************************************/
PTR( Expr ) Var :: subst( std::string str, PTR( Expr ) e )
{
    return str == str_m ? e : NEW( Var )( str_m );
}

/******************************************************************************
 * \brief Writes a Variable object's string representation to an output stream
 *
 * \param stream A reference to an output stream to write to
 *
 * For the Variable class, this simply means the value of the Variable
 * object's int_m member variable as a string. No parentheses or spaces are
 * added.
 *****************************************************************************/
void Var :: print( std::ostream & stream )
{
    stream << str_m;
}

/******************************************************************************
 * \brief Constructs a Let object representing a let binding
 *
 * \param lhs A string value to represent this Let object's lhs
 * \param rhs An Expression to define this Let object's lhs
 * \param body An Expression in which to exact the substitution
 *
 * The lhs must be a string. The rhs defines the lhs's value. Any Expression
 * class object can be used as a parameter for either the rhs or body. Numbers
 * and Variables act as terminal operands/Expressions, while
 * Addition/Multiplication objects act as nested Expressions.
 *****************************************************************************/
Let :: Let( std::string lhs, PTR( Expr ) rhs, PTR( Expr ) body )
{
    lhs_m = std::move( lhs );
    rhs_m = rhs;
    body_m = body;
}

/******************************************************************************
 * \brief Compares two Let objects
 *
 * \param e The Expression to compare this object to
 * \return True if the Let objects represent equivalent values; false
 * if not, or if the two objects compared are not both of type Let.
 *
 * Calls equals() recursively on both lhs and rhs values of this object. All
 * calls to equals(), including on nested expressions, must return true each
 * time for a Let object to be considered equal to another Let object.
 *****************************************************************************/
bool Let :: equals( PTR( Expr ) e )
{
    PTR( Let ) let_cmp = CAST( Let)( e );
    return let_cmp != nullptr &&
           lhs_m == ( let_cmp->lhs_m ) &&
           rhs_m->equals( let_cmp->rhs_m ) &&
           body_m->equals( let_cmp->body_m );
}

/******************************************************************************
 * \brief Simplifies a Let object to its integer value
 *
 * \return A Val object representing the sum/product of this Let object's body
 * after substitution
 *
 * This object's body calls subst(), using the lhs and rhs as parameters.
 * interp() is called recursively on the returned Expression, until it reaches
 * either a Number or a Variable. Number values are multiplied together, and
 * this call ultimately returns all values of the Expression (including nested
 * Expressions) multiplied together. If Variables are encountered, an
 * exception is thrown (see: Var::interp()).
 *****************************************************************************/
PTR( Val ) Let :: interp( PTR( Env ) env )
{
	if ( env == nullptr )
	{
		env = Env::empty;
	}

	PTR( Val ) rhs_val = rhs_m->interp( env );
	PTR( Env ) new_env = NEW( ExtendedEnv )( lhs_m, rhs_val, env );
	return body_m->interp( new_env );
}

/******************************************************************************
 * \brief Evaluates whether a Let object includes a Variable as an operand
 *
 * \return True if a Let object's rhs or body includes a Variable object
 * (at any level), or false if there are none.
 *
 * Employed recursively, this method returns true if this object (or any
 * Expression nested within it) have a lhs or rhs of type Variable.
 *****************************************************************************/
bool Let :: has_variable()
{
    return rhs_m->has_variable() || body_m->has_variable();
}

/******************************************************************************
 * \brief Replaces the lhs (variable) within a Let object with another Expr
 *
 * \param str The string value in the rhs or body to replace
 * \param e The Expression to replace the lhs (variable) with
 * \return A new Let object, with the requested Expression substitution
 *
 * Because Let is inherently substitution-oriented, this function is necessary
 * for Let::interp() as well. If a Let object contains a user-inputted string
 * value (e.g. Variable value), the string will be re-assigned with another
 * user-inputted Expression value where it occurs. The Variable class is
 * responsible for checking whether the string that is searched for is
 * actually contained by the Expression calling it. If it is, its value is
 * re-assigned. If not, it simply returns a copy of itself. This method is
 * called recursively on both the rhs and body of a Let object. The Variable
 * in question is replaced at all levels of nesting. The Let object's lhs is
 * not targeted/replaced by this function.
 *****************************************************************************/
PTR( Expr ) Let :: subst( std::string str, PTR( Expr ) e )
{
    return lhs_m == str ?
         NEW( Let )( lhs_m, rhs_m->subst( str, e ), body_m ) :
         NEW( Let )( lhs_m, rhs_m->subst( str, e ), body_m->subst( str, e ) );
}

/******************************************************************************
 * \brief Writes a Let's most basic string representation to an output stream
 *
 * \param stream A reference to an output stream to write to
 *
 * Called recursively on both the rhs and body Expressions of this Let object.
 * No spaces are added. One pair of parentheses surrounds the outermost
 * characters of each Let expression.
 *****************************************************************************/
void Let :: print( std::ostream& stream )
{
    stream << "(_let " << lhs_m << "=";
    rhs_m->print( stream );
    stream << " _in ";
    body_m->print( stream );
    stream << ")";
}

/******************************************************************************
 * \brief Driver method for pretty_print_at()
 *
 * \param stream A reference to an output stream to write to
 *****************************************************************************/
void Let :: pretty_print( std::ostream & stream )
{
    prec_t         driver_prec = NONE;
    std::streampos driver_cursor_pos = 0;
    bool           driver_paren = false;

    pretty_print_at( stream, driver_prec, driver_cursor_pos, driver_paren );
}

/******************************************************************************
 * \brief Writes an Let's stylized string representation to an output stream
 *
 * \param stream A reference to an output stream to write to
 * \param caller_prec The precedence level that this object should have,
 *                    which is determined by the caller
 * \param caller_pos The cursor position passed by the caller indicating
 *                   where the callee should begin printing
 * \param has_paren A boolean used to apply parentheses selectively
 *
 * Called recursively on all operands of this Let object. Spaces are added
 * between operators and operands. Pairs of parentheses are added on a
 * precedence basis (operands associate to the right; PEMDAS rules are
 * followed).
 *
 * Keywords (i.e. "_let", "_in") are always printed on newlines,
 * and line up vertically with the other keywords of the object they belong
 * to. Extra spacing after "_in" serves to correct its different length with
 * "_let", so that the operands that follow will be vertically aligned.
 *****************************************************************************/
void Let :: pretty_print_at( std::ostream & stream, prec_t caller_prec,
                             std::streampos & caller_pos, bool has_paren )
{
    bool close_paren = false;
    if ( caller_prec > NONE && !has_paren )
    {
        stream << "(";
        close_paren = true;
    }

    std::streampos start_pos = stream.tellp();
    std::string kw_offset( start_pos - caller_pos, ' ' );

    stream << "_let " << lhs_m << " = ";

    rhs_m->pretty_print_at( stream, NONE, caller_pos, has_paren );
    stream << "\n";

    caller_pos = stream.tellp();

    stream << kw_offset << "_in  ";
    body_m->pretty_print_at( stream, NONE, caller_pos, has_paren );

    if ( close_paren )
        stream << ")";
}

/******************************************************************************
 * \brief Constructs an If object representing a conditional operation
 *
 * \param condition An Expr object to define the condition/test
 * \param first_branch An Expr object to define the first branch/"then"
 * \param second_branch An Expr object to define the second branch/"else"
 *****************************************************************************/
If :: If( PTR( Expr ) condition, PTR( Expr ) first_branch, PTR( Expr ) second_branch )
{
    test_m = condition;
    then_m = first_branch;
    else_m = second_branch;
}

/******************************************************************************
 * \brief Compares two If objects
 *
 * \param e The object to compare this If object to
 * \return True if the two objects are both If objects and represent
 * equivalent operands
 *
 * Calls equals() recursively on all operands of this object. All
 * calls to equals(), including on nested expressions, must return true each
 * time for this If object to be considered equal to another object.
 *****************************************************************************/
bool If :: equals( PTR( Expr ) e )
{
    PTR( If ) if_cmp = CAST( If )( e );
    return if_cmp != nullptr &&
           test_m->equals( if_cmp->test_m ) &&
           then_m->equals( if_cmp->then_m ) &&
           else_m->equals( if_cmp->else_m );
}

/******************************************************************************
 * \brief Simplifies an If object to its equivalent Val value
 *
 * \return A Val object representing the value of this object after
 * conditional evaluation.
 *
 * The If object's condition operand is evaluated first. Based on the result of
 * this evaluation, either the then_m value is returned, or the else_m value.
 *****************************************************************************/
PTR( Val ) If :: interp( PTR( Env ) env )
{
    return test_m->interp()->is_true() ? then_m->interp() : else_m->interp();
}

/******************************************************************************
 * \brief Evaluates whether an If object includes a Var object as an operand
 *
 * \return True if any of an If object's operands include a Var object as an
 * operand.
 *
 * Employed recursively, this method returns true if this object (or any
 * Expression nested within it) have a lhs or rhs of type Variable.
 *****************************************************************************/
bool If :: has_variable()
{
    return test_m->has_variable() ||
           then_m->has_variable() ||
           else_m->has_variable();
}

/******************************************************************************
 * \brief Replaces a Var within an If object with another Expr object
 *
 * \param str The string value, or "variable", to replace
 * \param e The Expr object to replace the "variable" with
 * \return A new If object, with the necessary substitutions
 *
 * If an If contains a user-inputted string, the string will be replaced where
 * it occurs with another user-inputted parameter. The Var class is responsible
 * for checking whether the string that is searched for is actually contained
 * by the Expression calling it. (See: Var::subst() ). This method is called
 * recursively on both the lhs and rhs values of an If object. The "variable"
 * in question is replaced at all levels of nesting.
 *****************************************************************************/
PTR( Expr ) If :: subst( std::string str, PTR( Expr ) e )
{
    return NEW( If )( test_m->subst( str, e ),
                      then_m->subst( str, e ),
                      else_m->subst( str, e ) );
}

/******************************************************************************
 * \brief Writes a If object's most basic string representation to an output
 * stream
 *
 * \param stream A reference to an output stream to write to
 *
 * Called recursively on all operands of this If object. No spaces are added.
 * One pair of parentheses surrounds the outermost characters of each If
 * expression.
 *****************************************************************************/
void If :: print( std::ostream & stream )
{
    stream << "(_if ";
    test_m->print( stream );
    stream  << " _then ";
    then_m->print( stream );
    stream << " _else ";
    else_m->print( stream );
    stream << ")";
}

/******************************************************************************
 * \brief Driver method for pretty_print_at()
 *
 * \param stream A reference to an output stream to write to
 *****************************************************************************/
void If :: pretty_print( std::ostream & stream )
{
    prec_t         driver_prec = NONE;
    std::streampos driver_cursor_pos = 0;
    bool           driver_paren = false;

    pretty_print_at( stream, driver_prec, driver_cursor_pos, driver_paren );
}

/******************************************************************************
 * \brief Writes an If's stylized string representation to an output stream
 *
 * \param stream A reference to an output stream to write to
 * \param caller_prec The precedence level that this object should have,
 *                    which is determined by the caller
 * \param caller_pos The cursor position passed by the caller indicating
 *                   where the callee should begin printing
 * \param has_paren A boolean used to apply parentheses selectively
 *
 * Called recursively on all operands of this If object. Spaces are added
 * between operators and operands. Pairs of parentheses are added on a
 * precedence basis (operands associate to the right; PEMDAS rules are
 * followed).
 *
 * Keywords (i.e. "_if", "_then", "else") are always printed on newlines,
 * and line up vertically with the other keywords of the object they belong
 * to. Extra spacing after _if serves to correct its different length with
 * other keywords, so that the operands that follow will be vertically aligned.
 *****************************************************************************/
void If :: pretty_print_at( std::ostream & stream, prec_t caller_prec,
                            std::streampos & caller_pos, bool has_paren )
{
    bool close_paren = false;
    if ( caller_prec > NONE && !has_paren )
    {
        stream << "(";
        close_paren = true;
    }

    std::streampos start_pos = stream.tellp();
    const std::string kw_offset( start_pos - caller_pos, ' ' );

    stream << "_if   ";
    test_m->pretty_print_at( stream, NONE, caller_pos, has_paren );
    stream << "\n";

    caller_pos = stream.tellp();

    stream << kw_offset << "_then ";
    then_m->pretty_print_at( stream, NONE, caller_pos, has_paren );
    stream << "\n";

    /* Repeat for "_else" */
    caller_pos = stream.tellp();

    stream << kw_offset << "_else ";
    else_m->pretty_print_at( stream, NONE, caller_pos, has_paren );

    if ( close_paren )
        stream << ")";
}

Fun :: Fun( std::string formal_arg, PTR( Expr ) body )
{
    formal_arg_m = std::move( formal_arg );
    body_m = body;
}

bool Fun :: equals( PTR( Expr ) e )
{
    PTR( Fun ) fun_cmp = CAST( Fun )( e );
    return fun_cmp != nullptr &&
           formal_arg_m == fun_cmp->formal_arg_m &&
           body_m->equals( fun_cmp->body_m );
}

PTR( Val ) Fun :: interp( PTR( Env ) env )
{
    return NEW( FunVal )( formal_arg_m, body_m, env );
}

bool Fun :: has_variable()
{
    return body_m->has_variable();
}

PTR( Expr ) Fun :: subst( std::string str, PTR( Expr ) e )
{
    return formal_arg_m == str ?
           NEW( Fun )( formal_arg_m, body_m ) :
           NEW( Fun )( formal_arg_m, body_m->subst( str, e ) );
}

void Fun :: print( std::ostream & stream )
{
    stream << "(_fun (" << formal_arg_m << ") ";
    body_m->print( stream );
    stream << ")";
}

void Fun :: pretty_print( std::ostream & stream )
{
    prec_t         driver_prec = NONE;
    std::streampos driver_cursor_pos = 0;
    bool           driver_paren = false;

    pretty_print_at( stream, driver_prec, driver_cursor_pos, driver_paren );
}

void Fun :: pretty_print_at( std::ostream & stream, prec_t caller_prec,
                             std::streampos & caller_pos, bool has_paren )
{
    bool close_paren = false;
    if ( caller_prec > NONE && !has_paren )
    {
        stream << "(";
        close_paren = true;
    }

    std::streampos start_pos = stream.tellp();
    std::string kw_offset( start_pos - caller_pos, ' ' );

    stream << "_fun (" << formal_arg_m << ")";
    stream << "\n";

    caller_pos = stream.tellp();

    stream<< kw_offset << "  ";
    body_m->pretty_print_at( stream, NONE, caller_pos, has_paren );

    if ( close_paren )
        stream << ")";
}

Call :: Call( PTR( Expr ) to_be_called, PTR( Expr ) actual_arg )
{
    to_be_called_m = to_be_called;
    actual_arg_m = actual_arg;
}

bool Call :: equals( PTR( Expr ) e )
{
    PTR( Call ) call_cmp = CAST( Call )( e );
    return call_cmp != nullptr &&
           to_be_called_m->equals( call_cmp->to_be_called_m )&&
           actual_arg_m->equals( call_cmp->actual_arg_m );
}

PTR( Val ) Call :: interp( PTR( Env ) env )
{
    PTR( Val ) tbc_val = to_be_called_m->interp();
    PTR( Val ) arg_val = actual_arg_m->interp();
    return tbc_val->call( arg_val );
}

bool Call :: has_variable()
{
    return false;
}

PTR( Expr ) Call :: subst( std::string str, PTR( Expr ) e )
{
    return NEW( Call )( to_be_called_m->subst( str, e ), actual_arg_m->subst( str, e ) );
}

void Call :: print( std::ostream & stream )
{
    to_be_called_m->print( stream );
    stream << " ";
    actual_arg_m->print( stream );
}

void Call :: pretty_print( std::ostream & stream )
{
    prec_t         driver_prec = NONE;
    std::streampos driver_cursor_pos = 0;
    bool           driver_paren = false;

    pretty_print_at( stream, driver_prec, driver_cursor_pos, driver_paren );
}

void Call :: pretty_print_at( std::ostream & stream, prec_t caller_prec,
                            std::streampos & caller_pos, bool has_paren )
{
    to_be_called_m->pretty_print_at( stream, NONE, caller_pos, has_paren );
    stream << '(';
    actual_arg_m->pretty_print_at( stream, NONE, caller_pos, has_paren );
    stream << ')';
}