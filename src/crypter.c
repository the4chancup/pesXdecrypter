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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/stat.h>

#include "mt19937ar.h"

struct FileHeader
{
    uint8_t mysteryData[64];
    uint32_t dataSize;
    uint32_t logoSize;
    uint32_t descSize;
    uint32_t serialLength;
    uint8_t hash[64];
    uint8_t fileTypeString[32];
};

struct FileDescriptor
{
    uint8_t *encryptionHeader;
    struct FileHeader *fileHeader;
    
    uint8_t *description;
    uint8_t *logo;
    uint8_t *data;
    uint8_t *serial;
};

static const uint8_t MasterKey[] = {
    0x4D, 0x55, 0x94, 0x66, 0xD9, 0x62, 0x5C, 0xEC,
    0xC1, 0x7C, 0x48, 0x36, 0x77, 0x31, 0x50, 0xE1,
    0x87, 0x1C, 0xB5, 0x6B, 0x41, 0xD4, 0x92, 0x4F,
    0x4A, 0x8C, 0x71, 0x27, 0x0A, 0x0D, 0x50, 0x63,
    0x94, 0x2B, 0x58, 0x5E, 0x99, 0x0B, 0x8B, 0x97,
    0x96, 0x66, 0xC0, 0x00, 0xB7, 0x1D, 0x72, 0x75,
    0xD6, 0xE8, 0x5B, 0x0E, 0xAF, 0xF1, 0x72, 0xD1,
    0xB1, 0xE3, 0x3C, 0x75, 0xDE, 0x9C, 0x13, 0x09,
};

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
    uint32_t * input32 = (uint32_t *)input;
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
    cryptStream(output, headerKey, input, 320);
    memcpy(&output[256], &input[256], 64);
}

void decrypt(struct FileDescriptor *descriptor, const uint8_t *input)
{
    descriptor->encryptionHeader = (uint8_t *)malloc(320);
    descriptor->fileHeader       = (struct FileHeader *)malloc(sizeof(struct FileHeader));

    cryptHeader(descriptor->encryptionHeader, input, MasterKey);
    input += 320;

    uint8_t rollingKey[64], intermediateKey[64];
    memcpy(rollingKey, descriptor->encryptionHeader, 64);
    xorRepeatingBlocks(rollingKey, &descriptor->encryptionHeader[64], 256);
    
    xorWithLongParam(rollingKey, intermediateKey, sizeof(struct FileHeader));
    cryptStream((uint8_t *)descriptor->fileHeader, intermediateKey, input, sizeof(struct FileHeader));
    input += sizeof(struct FileHeader);

    descriptor->data        = (uint8_t *)malloc(descriptor->fileHeader->dataSize);
    descriptor->logo            = (uint8_t *)malloc(descriptor->fileHeader->logoSize);
    descriptor->description = (uint8_t *)malloc(descriptor->fileHeader->descSize);
    descriptor->serial   = (uint8_t *)malloc(descriptor->fileHeader->serialLength*2);

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

uint8_t *encrypt(const struct FileDescriptor *descriptor, int *size)
{
    *size = 320
          + sizeof(struct FileHeader)
          + descriptor->fileHeader->dataSize
          + descriptor->fileHeader->logoSize
          + descriptor->fileHeader->descSize
          + descriptor->fileHeader->serialLength*2;

    uint8_t *result = (uint8_t *)malloc(*size);
    if (!result)
        return NULL;

    uint8_t *output = result;

    cryptHeader(output, descriptor->encryptionHeader, MasterKey);
    output += 320;

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

void writeFile(const char *path, const uint8_t *data, int size)
{
    FILE *outStream = fopen(path, "wb");
    if (!outStream)
        return;
    fwrite(data, 1, size, outStream);
    fclose(outStream);
}

uint8_t *readFileDir(const char *dirName, const char *fileName, uint32_t *sizePtr)
{
    char *path = (char *)malloc(strlen(dirName) + strlen(fileName) + 2);
    sprintf(path, "%s/%s", dirName, fileName);

    uint8_t *result = readFile(path, sizePtr);

    free(path);

    return result;
}

void writeFileDir(const char *dirName, const char *fileName, const uint8_t *data, int size)
{
    struct stat dir;
    if (stat(dirName, &dir))
#ifdef __MINGW32__
        mkdir(dirName);
#else
        mkdir(dirName, 0777);
#endif

    char *path = (char *)malloc(strlen(dirName) + strlen(fileName) + 2);
    sprintf(path, "%s/%s", dirName, fileName);

    writeFile(path, data, size);

    free(path);
}

int main(int argc, const char *argv[])
{
#if DECRYPTER
    if (argc != 3) {
        printf("Usage: decrypter [input_file] [output_dir]\n");
        return -1;
    }

    uint8_t *input = readFile(argv[1], NULL);
    if (!input) {
        printf("Unable to open input file");
        return -1;
    }

    struct FileDescriptor descriptor;
    decrypt(&descriptor, input);

    writeFileDir(argv[2], "encryptHeader.dat",     descriptor.encryptionHeader, 320);
    writeFileDir(argv[2], "header.dat", (uint8_t *)descriptor.fileHeader,       sizeof(struct FileHeader));
    writeFileDir(argv[2], "description.dat",       descriptor.description,  descriptor.fileHeader->descSize);
    writeFileDir(argv[2], "logo.png",              descriptor.logo,             descriptor.fileHeader->logoSize);
    writeFileDir(argv[2], "data.dat",              descriptor.data,         descriptor.fileHeader->dataSize);
    writeFileDir(argv[2], "version.txt",           descriptor.serial,    descriptor.fileHeader->serialLength*2);
#else
    if (argc != 3) {
        printf("Usage: encrypter [input_dir] [output_file]\n");
        return -1;
    }

    struct FileDescriptor descriptor;
    descriptor.encryptionHeader                = readFileDir(argv[1], "encryptHeader.dat", NULL);
    descriptor.fileHeader = (struct FileHeader *)readFileDir(argv[1], "header.dat", NULL);
    descriptor.description                 = readFileDir(argv[1], "description.dat", &descriptor.fileHeader->descSize);
    descriptor.logo                            = readFileDir(argv[1], "logo.png",        &descriptor.fileHeader->logoSize);
    descriptor.data                        = readFileDir(argv[1], "data.dat",        &descriptor.fileHeader->dataSize);
    descriptor.serial                   = readFileDir(argv[1], "version.txt",     &descriptor.fileHeader->serialLength);
    descriptor.fileHeader->serialLength /= 2;

    int outputSize;
    uint8_t *output = encrypt(&descriptor, &outputSize);

    writeFile(argv[2], output, outputSize);
#endif

    return 0;
}
