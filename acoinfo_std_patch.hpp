#pragma once
#ifdef SYLIXOS
#include <SylixOS.h>
#include <stdlib.h>
#include <string>
#include <sstream>
 
//using namespace std;
namespace stdpatch{

    std::string to_string( int& n );
//    std::string to_string( size_t& n );
    std::string to_string( long int& n );
    std::string to_string(std::basic_string<char>::size_type n);

    int stoi( std::string s );
    unsigned long stoul(const std::string&  str, size_t* idx = 0, int base = 10);
    unsigned long stoll(const std::string&  str, size_t* idx = 0, int base = 10);
    unsigned long strtoull(const std::string&  str, size_t* idx = 0, int base = 10);
}
#endif
