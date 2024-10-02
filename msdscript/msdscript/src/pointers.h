/******************************************************************************
 * \brief Macros for pointers (two different modes)
 *
 * \file pointers.h
 * \author Jake Dame
 *****************************************************************************/

#ifndef MSDSCRIPT_POINTERS_H
#define MSDSCRIPT_POINTERS_H

#include <memory> /* std::shared_ptr, std::make_shared */

	#define USE_PLAIN_POINTERS 0

	#if USE_PLAIN_POINTERS

	# define NEW(T)     new T
	# define PTR(T)     T*
	# define CAST(T)    dynamic_cast<T*>
	# define CLASS(T)   class T
	# define THIS       this

	#else

	# define NEW(T)     std::make_shared<T>
	# define PTR(T)     std::shared_ptr<T>
	# define CAST(T)    std::dynamic_pointer_cast<T>
	# define CLASS(T)   class T : public std::enable_shared_from_this<T>
	# define THIS       shared_from_this()

	#endif /* USE_PLAIN_POINTERS */

#endif /* MSDSCRIPT_POINTERS_H */