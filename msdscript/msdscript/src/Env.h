/******************************************************************************
 * \brief Declarations for Env (Environment) class
 *
 * \file Env.h
 * \author Jake Dame
 *****************************************************************************/

#pragma once

#include <string>
#include <utility>

#include "pointers.h"

class Val;

/******************************************************************************
 * \class Env
 * \brief A "dictionary" for results of substituted (recursive, mostly)
 *        expressions
 *****************************************************************************/
class Env
{

public:

	static PTR( Env ) empty;

	virtual PTR( Val ) lookup( std::string find_name ) = 0;
};

class EmptyEnv : public Env
{

public:

	PTR( Val ) lookup( std::string find_name ) override
	{
		throw std::runtime_error( "Var cannot call interp()" );
	}
};

class ExtendedEnv : public Env
{

public:

	std::string name;
	PTR( Val ) val;
	PTR( Env ) rest;

	ExtendedEnv( std::string name, PTR( Val ) val, PTR( Env ) env )
	{
		this->name = std::move( name );
		this->val = val;
		this->rest = env;
	}

	PTR( Val ) lookup( std::string find_name ) override
	{
		if ( find_name == name )
		{
			return val;
		}
		else
		{
			return rest->lookup( find_name );
		}
	}
};