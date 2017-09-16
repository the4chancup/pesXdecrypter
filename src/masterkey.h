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

#ifndef _MASTERKEY_H
#define _MASTERKEY_H

#include <stdint.h>

#include "crypt.h"

#define MASTER_KEY_LENGTH 64


// Empty master key for default usage.
const uint8_t MasterKeyZero[MASTER_KEY_LENGTH];

// Expose master keys for library usage.
CRYPTER_EXPORT extern const uint8_t MasterKeyPes16[MASTER_KEY_LENGTH];
CRYPTER_EXPORT extern const uint8_t MasterKeyPes16MyClub[MASTER_KEY_LENGTH];
CRYPTER_EXPORT extern const uint8_t MasterKeyPes17[MASTER_KEY_LENGTH];
CRYPTER_EXPORT extern const uint8_t MasterKeyPes18[MASTER_KEY_LENGTH];

// Old global master key, maintained for backwards compability.
extern uint8_t const *MasterKey;

#endif /* _MASTERKEY_H */
