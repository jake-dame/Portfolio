/**
 * \file exec.h
 * \brief Exec and piping functions declarations for test_msdscript.
 * \author Nabil Makarem
 * */

#pragma once

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <cerrno>
#include <string>
#include <iostream>
#include <cassert>

class ExecResult
{

public:
    int exit_code;
    std::string out;
    std::string err;

    ExecResult()
    {
        exit_code = 0;
        out = "";
        err = "";
    }

};

extern ExecResult exec_program(int argc, const char * const * argv, std::string input);