/******************************************************************************
 * \brief Parsing functions declaration
 *
 * \file parse.h
 * \author Jake Dame
 *****************************************************************************/

#pragma once

#include "Expr.h"
#include "pointers.h"

PTR( Expr ) parse_expr( const std::string & str );