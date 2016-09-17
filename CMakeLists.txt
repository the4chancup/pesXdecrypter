project(pesXdecrypter)
cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

if (CMAKE_COMPILER_IS_GNUCXX)
    # Improve inlining and force explicit exporting of symbols with GCC.
    # This also works with MinGW.
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fvisibility-inlines-hidden")
endif()

# Store common source files in variables.
set(LIBRARY_SOURCES src/crypt.c src/mt19937ar.c src/masterkey.c)
set(DECRYPTER_SOURCES src/decrypter.c src/mt19937ar.c src/masterkey.c)
set(ENCRYPTER_SOURCES src/encrypter.c src/mt19937ar.c src/masterkey.c)

# Macro to add a library, decrypter, and encrypter for the given PES version.
macro(add_pes_version PES_VERSION)
    # Determine target names.
    set(LIBRARY "pes${PES_VERSION}decrypter")
    set(DECRYPTER "decrypter${PES_VERSION}")
    set(ENCRYPTER "encrypter${PES_VERSION}")
    
    # Add library and executables.
    add_library(${LIBRARY} SHARED ${LIBRARY_SOURCES})
    add_executable(${DECRYPTER} ${DECRYPTER_SOURCES})
    add_executable(${ENCRYPTER} ${ENCRYPTER_SOURCES})
    
    # Enable C99 support.
    set_property(TARGET ${LIBRARY} PROPERTY C_STANDARD 99)
    set_property(TARGET ${DECRYPTER} PROPERTY C_STANDARD 99)
    set_property(TARGET ${ENCRYPTER} PROPERTY C_STANDARD 99)
 
    # Set the preprocessor define BUILDING_LIBRARY for building the libraries.
    # This causes symbols to be exported instead of imported.
    target_compile_definitions(${LIBRARY} PRIVATE -DBUILDING_LIBRARY)
    
    # Set a preprocessor define to decide which master key to use.
    string(TOUPPER "USE_PES${PES_VERSION}_MASTER_KEY" MASTER_KEY)
    target_compile_definitions(${LIBRARY} PRIVATE -D"${MASTER_KEY}")
    target_compile_definitions(${DECRYPTER} PRIVATE "-D${MASTER_KEY}")
    target_compile_definitions(${ENCRYPTER} PRIVATE "-D${MASTER_KEY}")

    # Link the executables against the library.
    target_link_libraries(${DECRYPTER} ${LIBRARY})
    target_link_libraries(${ENCRYPTER} ${LIBRARY})
endmacro()

# Add a library, decrypter, and encrypter for all PES versions below.
# When adding a new version, make sure to also add a new key to masterkey.c.
add_pes_version("16")
add_pes_version("16myClub")
add_pes_version("17")