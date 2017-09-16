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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#include "mt19937ar.h"
#include "crypt.h"
#include "masterkey.h"

#define ENCRYPTION_HEADER_SIZE 320


uint32_t rol(uint32_t a, uint32_t shift)
{
    return (a << shift) | (a >> (32 - shift));
}

uint32_t ror(uint32_t a, uint32_t shift)
{
    return (a >> shift) | (a << (32 - shift));
}

void xorRepeatingBlocks(uint8_t *output, const uint8_t *input, int length)
{
    for (int i = 0; i < length; ++i)
        output[i & 63] ^= input[i];
}

void xorWithLongParam(const uint8_t *input, uint8_t *output, uint64_t param)
{
    const uint64_t * input64 = (uint64_t *)input;
          uint64_t *output64 = (uint64_t *)output;

    for (int i = 0; i < 8; ++i)
        output64[i] = input64[i] ^ param;
}

void reverseLongs(uint8_t *output, const uint8_t *input)
{
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j)
            output[i*8 + j] = input[i*8 + 7 - j];
}

void cryptStream(uint8_t *output, const uint8_t *key, const uint8_t *input, int length)
{
    uint32_t *input32 = (uint32_t *)input;
    uint32_t *output32 = (uint32_t *)output;

    init_by_array((uint32_t *)key, 16);
    uint32_t c0 = genrand_int32();
    uint32_t c1 = genrand_int32();
    uint32_t c2 = genrand_int32();
    uint32_t c3 = genrand_int32();

    for (int i = 0; i < length/4; ++i) {
        uint32_t c4 = genrand_int32();

        output32[i] = c4 ^ c3 ^ c2 ^ c1 ^ c0 ^ input32[i];

        c0 = ror(c1, 15);
        c1 = rol(c2, 11);
        c2 = rol(c3, 7);
        c3 = ror(c4, 13);
    }
    if (length & 3) {
        uint32_t rest;
        memcpy(&rest, &input[length & (~3)], length & 3);

        rest ^= genrand_int32() ^ c3 ^ c2 ^ c1 ^ c0;

        memcpy(&output[length & (~3)], &rest, length & 3);
    }
}

void cryptHeader(uint8_t *output, const uint8_t *input, const uint8_t *key)
{
    uint8_t headerKey[64], shuffledMasterKey[64];

    memcpy(headerKey, &input[256], 64);
    reverseLongs(shuffledMasterKey, key);
    xorRepeatingBlocks(headerKey, shuffledMasterKey, 64);
    cryptStream(output, headerKey, input, ENCRYPTION_HEADER_SIZE);
    memcpy(&output[256], &input[256], 64);
}

void decryptWithKey(struct FileDescriptor *descriptor, const uint8_t *input, const char *masterKey)
{
    descriptor->encryptionHeader = (uint8_t *)malloc(ENCRYPTION_HEADER_SIZE);
    descriptor->fileHeader       = (struct FileHeader *)malloc(sizeof(struct FileHeader));

    cryptHeader(descriptor->encryptionHeader, input, masterKey);
    input += ENCRYPTION_HEADER_SIZE;

    uint8_t rollingKey[64], intermediateKey[64];
    memcpy(rollingKey, descriptor->encryptionHeader, 64);
    xorRepeatingBlocks(rollingKey, &descriptor->encryptionHeader[64], 256);

    xorWithLongParam(rollingKey, intermediateKey, sizeof(struct FileHeader));
    cryptStream((uint8_t *)descriptor->fileHeader, intermediateKey, input, sizeof(struct FileHeader));
    input += sizeof(struct FileHeader);

    descriptor->data        = (uint8_t *)malloc(descriptor->fileHeader->dataSize);
    descriptor->logo        = (uint8_t *)malloc(descriptor->fileHeader->logoSize);
    descriptor->description = (uint8_t *)malloc(descriptor->fileHeader->descSize);
    descriptor->serial      = (uint8_t *)malloc(descriptor->fileHeader->serialLength*2);

    xorWithLongParam(rollingKey, intermediateKey, 0);
    cryptStream(descriptor->description, intermediateKey, input, descriptor->fileHeader->descSize);
    input += descriptor->fileHeader->descSize;


    xorWithLongParam(rollingKey, intermediateKey, 1);
    cryptStream(descriptor->logo, intermediateKey, input, descriptor->fileHeader->logoSize);
    input += descriptor->fileHeader->logoSize;

    xorWithLongParam(rollingKey, intermediateKey, 2);
    cryptStream(descriptor->data, intermediateKey, input, descriptor->fileHeader->dataSize);
    input += descriptor->fileHeader->dataSize;

    xorWithLongParam(rollingKey, intermediateKey, 3);
    cryptStream(descriptor->serial, intermediateKey, input, descriptor->fileHeader->serialLength*2);
}

uint8_t *encryptWithKey(const struct FileDescriptor *descriptor, int *size, const char *masterKey)
{
    *size = ENCRYPTION_HEADER_SIZE
          + sizeof(struct FileHeader)
          + descriptor->fileHeader->dataSize
          + descriptor->fileHeader->logoSize
          + descriptor->fileHeader->descSize
          + descriptor->fileHeader->serialLength*2;

    uint8_t *result = (uint8_t *)malloc(*size);
    if (!result)
        return NULL;

    uint8_t *output = result;

    cryptHeader(output, descriptor->encryptionHeader, masterKey);
    output += ENCRYPTION_HEADER_SIZE;

    uint8_t rollingKey[64], intermediateKey[64];
    memcpy(rollingKey, descriptor->encryptionHeader, 64);
    xorRepeatingBlocks(rollingKey, &descriptor->encryptionHeader[64], 256);

    xorWithLongParam(rollingKey, intermediateKey, sizeof(struct FileHeader));
    cryptStream(output, intermediateKey, (uint8_t *)descriptor->fileHeader, sizeof(struct FileHeader));
    output += sizeof(struct FileHeader);

    xorWithLongParam(rollingKey, intermediateKey, 0);
    cryptStream(output, intermediateKey, descriptor->description, descriptor->fileHeader->descSize);
    output += descriptor->fileHeader->descSize;

    xorWithLongParam(rollingKey, intermediateKey, 1);
    cryptStream(output, intermediateKey, descriptor->logo, descriptor->fileHeader->logoSize);
    output += descriptor->fileHeader->logoSize;

    xorWithLongParam(rollingKey, intermediateKey, 2);
    cryptStream(output, intermediateKey, descriptor->data, descriptor->fileHeader->dataSize);
    output += descriptor->fileHeader->dataSize;

    xorWithLongParam(rollingKey, intermediateKey, 3);
    cryptStream(output, intermediateKey, descriptor->serial, descriptor->fileHeader->serialLength*2);

    return result;
}

struct FileDescriptor CRYPTER_EXPORT *createFileDescriptor()
{
    struct FileDescriptor *result = malloc(sizeof(struct FileDescriptor));
    if (result)
        memset(result, 0, sizeof(struct FileDescriptor));
    return result;
}

void CRYPTER_EXPORT destroyFileDescriptor(struct FileDescriptor *desc)
{
    if (desc->encryptionHeader) free(desc->encryptionHeader);
    if (desc->fileHeader)       free(desc->fileHeader);
    if (desc->description)      free(desc->description);
    if (desc->logo)             free(desc->logo);
    if (desc->data)             free(desc->data);
    if (desc->serial)           free(desc->serial);
    free(desc);
}

//encrypter & decrypter helpers ...
uint8_t *readFile(const char *path, uint32_t *sizePtr)
{
    FILE *inStream = fopen(path, "rb");
    if (!inStream)
        return NULL;

    struct stat file;
    if (stat(path, &file))
        return NULL;
    int size = file.st_size;

    uint8_t *input = (uint8_t *)malloc(size);
    fread(input, 1, size, inStream);
    fclose(inStream);

    if (sizePtr)
        *sizePtr = size;

    return input;
}

uint8_t *readFileDir(const char *dirName, const char *fileName, uint32_t *sizePtr)
{
    char *path = (char *)malloc(strlen(dirName) + strlen(fileName) + 2);
    sprintf(path, "%s/%s", dirName, fileName);

    uint8_t *result = readFile(path, sizePtr);

    free(path);

    return result;
}

void writeFile(const char *path, const uint8_t *data, int size)
{
    FILE *outStream = fopen(path, "wb");
    if (!outStream)
        return;
    fwrite(data, 1, size, outStream);
    fclose(outStream);
}

void writeFileDir(const char *dirName, const char *fileName, const uint8_t *data, int size)
{
    struct stat dir;
    if (stat(dirName, &dir))
#ifdef __unix__
        mkdir(dirName, 0777);
#else
        mkdir(dirName);
#endif

    char *path = (char *)malloc(strlen(dirName) + strlen(fileName) + 2);
    sprintf(path, "%s/%s", dirName, fileName);

    writeFile(path, data, size);

    free(path);
}


void CRYPTER_EXPORT decryptWithKey_ex(const char *pathIn, const char *pathOut, const char *masterKey)
{
    uint8_t *input = readFile(pathIn, NULL);
    if (!input) {
        #ifndef BUILDING_LIBRARY
            printf("Unable to open input file");
        #endif
        return;
    }

    struct FileDescriptor *descriptor = createFileDescriptor();
    decryptWithKey(descriptor, input, masterKey);

    writeFileDir(pathOut, "encryptHeader.dat",     descriptor->encryptionHeader, ENCRYPTION_HEADER_SIZE);
    writeFileDir(pathOut, "header.dat", (uint8_t *)descriptor->fileHeader,       sizeof(struct FileHeader));
    writeFileDir(pathOut, "description.dat",       descriptor->description,      descriptor->fileHeader->descSize);
    writeFileDir(pathOut, "logo.png",              descriptor->logo,             descriptor->fileHeader->logoSize);
    writeFileDir(pathOut, "data.dat",              descriptor->data,             descriptor->fileHeader->dataSize);
    writeFileDir(pathOut, "version.txt",           descriptor->serial,           descriptor->fileHeader->serialLength*2);

    destroyFileDescriptor(descriptor);
}


void CRYPTER_EXPORT encryptWithKey_ex(const char *pathIn, const char *pathOut, const char *masterKey)
{
    struct FileDescriptor *descriptor = createFileDescriptor();
    descriptor->encryptionHeader                = readFileDir(pathIn, "encryptHeader.dat", NULL);
    descriptor->fileHeader = (struct FileHeader *)readFileDir(pathIn, "header.dat", NULL);
    descriptor->description                     = readFileDir(pathIn, "description.dat", &descriptor->fileHeader->descSize);
    descriptor->logo                            = readFileDir(pathIn, "logo.png",        &descriptor->fileHeader->logoSize);
    descriptor->data                            = readFileDir(pathIn, "data.dat",        &descriptor->fileHeader->dataSize);
    descriptor->serial                          = readFileDir(pathIn, "version.txt",     &descriptor->fileHeader->serialLength);
    descriptor->fileHeader->serialLength /= 2;

    int outputSize;
    uint8_t *output = encryptWithKey(descriptor, &outputSize, masterKey);

    writeFile(pathOut, output, outputSize);

    destroyFileDescriptor(descriptor);
}


// *** Old functions, maintained for backwards compability ***

// Decrypt the data at input and store it in descriptor.
// Uses the globally set MasterKey.
void CRYPTER_EXPORT decrypt(struct FileDescriptor *descriptor, const uint8_t *input)
{
    decryptWithKey(descriptor, input, MasterKey);
}

// Encrypt and return the data stored in descriptor; size of output is stored at size.
// Uses the globally set MasterKey.
uint8_t CRYPTER_EXPORT *encrypt(const struct FileDescriptor *descriptor, int *size)
{
    return encryptWithKey(descriptor, size, MasterKey);
}

// Decrypt the file at PathIn and put it out into folder pathOut.
// Uses the globally set MasterKey.
void CRYPTER_EXPORT decrypt_ex(const char *pathIn, const char *pathOut)
{
    decryptWithKey_ex(pathIn, pathOut, MasterKey);
}

// Encrypts the folder PathIn and puts it out into file pathOut
// Uses the globally set MasterKey.
void CRYPTER_EXPORT encrypt_ex(const char *pathIn, const char *pathOut)
{
    encryptWithKey_ex(pathIn, pathOut, MasterKey);
}
