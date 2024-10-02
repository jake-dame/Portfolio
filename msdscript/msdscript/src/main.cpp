/******************************************************************************
 * \mainpage msdscript
 * \version 8.0
 * \author Jake Dame
 * \date 02/06/24
 *
 * \brief A mathematical expression interpreting program
 *
 * msdscript is a script interpretation program that supports various
 * functionality on user-inputted mathematical expressions. If the expression
 * entered in the console follows proper grammar, this program can simplify the
 * expression. It supports let binding, conditional evaluation, and comparison
 * operations. Running the program with the "--help" flag will list valid
 * arguments that encompass the programs useful functions.
 *****************************************************************************/

#include <iostream>
#include "Expr.h"
#include "pointers.h"
#include "Val.h"

#include "cmdline.h" /* Command line argument handling */

/******************************************************************************
 * \brief A main() function for the msdscript program
 *****************************************************************************/
int main( int argc, char ** argv )
{
	return use_arguments( argc, argv );
}