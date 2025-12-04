//
// Created by kitbyte on 03.12.2025.
//

#ifndef TURBO_ASAR_INTERNAL_H
#define TURBO_ASAR_INTERNAL_H

#if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32))
#define __WINDOWS__
#endif

/* Export/Import macros for shared library */
#if defined(__WINDOWS__)
    #ifdef TURBO_ASAR_BUILD_DLL
        #define TURBO_ASAR_API __declspec(dllexport)
    #elif defined(TURBO_ASAR_BUILD_STATIC)
        #define TURBO_ASAR_API
    #else
        #define TURBO_ASAR_API __declspec(dllimport)
    #endif
#else
    #ifdef TURBO_ASAR_BUILD_DLL
        #define TURBO_ASAR_API __attribute__((visibility("default")))
    #else
        #define TURBO_ASAR_API
    #endif
#endif


#if __has_attribute(__fallthrough__)
# define fallthrough                    __attribute__((__fallthrough__))
#else
# define fallthrough                    do {} while (0)  /* fallthrough */
#endif

#if defined(__GNUC__) || defined(__clang__)
#ifndef __pure
#define __pure __attribute__((__pure__))
#endif
#else
# define __pure
#endif

#ifdef __WINDOWS__
#define PATH_SEPARATOR '\\'
#define PATH_SEPARATOR_STR "\\"
#else
#define PATH_SEPARATOR '/'
#define PATH_SEPARATOR_STR "/"
#endif

#define TURBO_ASAR_VERSION "1.0.0"

#endif //TURBO_ASAR_INTERNAL_H
