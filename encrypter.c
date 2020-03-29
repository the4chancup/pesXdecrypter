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

#include <stdio.h>
#include <stdint.h>

#include "masterkey.h"
#include "crypt.h"


int main(int argc, const char *argv[])
{
    if (argc == 3) {
        encrypt_ex(argv[1], argv[2]);
    }
    else if (argc == 4) {
        uint32_t size;
        uint8_t *key = readFile(argv[3], &size);
        if (size != MASTER_KEY_LENGTH) {
            printf("Invalid key size!\n");
            return -1;
        }
        encryptWithKey_ex(argv[1], argv[2], key);
    }
    else {
        printf("Usage: encrypter [input_dir] [output_file] [[master_key_file]]\n");
        return -1;
    }
    
    return 0;
}
