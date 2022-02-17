#include <SylixOS.h>
#include <stdlib.h>
#include <string>
#include <sstream>
namespace stdpatch{

    std::string to_string( int& n )
    {
        std::ostringstream stm ;
        stm << n ;
        return stm.str() ;
    }
//    std::string to_string( size_t& n )
//        {
//            std::ostringstream stm ;
//            stm << n ;
//            return stm.str() ;
//        }
    std::string to_string( long int& n ){
        std::ostringstream stm ;
                    stm << n ;
                    return stm.str() ;
    }
    std::string to_string(std::basic_string<char>::size_type n){
        std::ostringstream stm ;
                    stm << n ;
                    return stm.str() ;
    }
    int stoi( std::string s )
    {
        return ::atoi(s.c_str()) ;
    }
    unsigned long stoul(const std::string&  str, size_t* idx = 0, int base = 10)
     {
        char *idxptr=NULL;
        unsigned long ans=::strtoul(str.c_str(),&idxptr,base);
        if(idx!=nullptr){
            *idx=idxptr-str.c_str();
        }
        return ans;
     }
    unsigned long stoll(const std::string&  str, size_t* idx = 0, int base = 10)
         {
            char *idxptr=NULL;

            unsigned long ans=::strtoll(str.c_str(),&idxptr,base);
            if(idx!=nullptr){
                *idx=idxptr-str.c_str();
            }
            return ans;
         }
    unsigned long strtoull(const std::string&  str, size_t* idx = 0, int base = 10)
         {
            char *idxptr=NULL;
            unsigned long ans=::strtoull(str.c_str(),&idxptr,base);
            if(idx!=nullptr){
                *idx=idxptr-str.c_str();
            }
            return ans;
         }
}
