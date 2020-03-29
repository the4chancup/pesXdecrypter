/*
    This is free and unencumbered software released into the public domain.

    Anyone is free to copy, modify, publish, use, compile, sell, or
    distribute this software, either in source code form or as a compiled
    binary, for any purpose, commercial or non-commercial, and by any
    means.

    In jurisdictions that recognize copyright laws, the author or authors
    of this software dedicate any and all copyright interest in the
    software to the public domain. We make this dedication for the benefit
    of the public at large and to the detriment of our heirs and
    successors. We intend this dedication to be an overt act of
    relinquishment in perpetuity of all present and future rights to this
    software under copyright law.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
    OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
    ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
    OTHER DEALINGS IN THE SOFTWARE.

    For more information, please refer to <http://unlicense.org>
 */
 
//To compile in MinGW:
// gcc -c crypt.c mt19937ar.c masterkey.c -DBUILDING_LIBRARY -D_WIN32
// gcc -std=c99 -shared -o libpesXcrypter.dll crypt.o mt19937ar.o masterkey.o

#ifndef _CRYPT_H
#define _CRYPT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BUILDING_LIBRARY

#ifdef _WIN32
#define CRYPTER_EXPORT __declspec(dllexport)
#else
#define CRYPTER_EXPORT __attribute__ ((visibility ("protected")))
#endif

#else

#define CRYPTER_EXPORT

#endif /* BUILDING_LIBRARY */

struct FileHeaderNew
{
    uint8_t mysteryData[64];
    uint32_t dataSize;
    uint32_t logoSize;
    uint32_t descSize;
    uint32_t serialLength;
    uint8_t hash[64];
    uint8_t fileTypeString[32];
    uint8_t gameVersionString[32];
};

struct FileHeaderOld
{
    uint8_t mysteryData[64];
    uint32_t dataSize;
    uint32_t logoSize;
    uint32_t descSize;
    uint32_t serialLength;
    uint8_t hash[64];
    uint8_t fileTypeString[32];
};

struct FileDescriptorNew
{
    uint8_t *encryptionHeader;
    struct FileHeaderNew *fileHeader;

    uint8_t *description;
    uint8_t *logo;
    uint8_t *data;
    uint8_t *serial;
};

struct FileDescriptorOld
{
    uint8_t *encryptionHeader;
    struct FileHeaderOld *fileHeader;

    uint8_t *description;
    uint8_t *logo;
    uint8_t *data;
    uint8_t *serial;
};

struct FileDescriptorNew CRYPTER_EXPORT *createFileDescriptorNew();
void CRYPTER_EXPORT destroyFileDescriptorNew(struct FileDescriptorNew *desc);
struct FileDescriptorOld CRYPTER_EXPORT *createFileDescriptor();
void CRYPTER_EXPORT destroyFileDescriptorOld(struct FileDescriptorOld *desc);

void CRYPTER_EXPORT decryptWithKeyNew(struct FileDescriptorNew *descriptor, const uint8_t *input, const char *masterKey);
uint8_t CRYPTER_EXPORT *encryptWithKeyNew(const struct FileDescriptorNew *descriptor, int *size, const char *masterKey);
void CRYPTER_EXPORT decryptWithKeyOld(struct FileDescriptorOld *descriptor, const uint8_t *input, const char *masterKey);
uint8_t CRYPTER_EXPORT *encryptWithKeyOld(const struct FileDescriptorOld *descriptor, int *size, const char *masterKey);

uint8_t *readFile(const char *path, uint32_t *sizePtr);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPT_H */
