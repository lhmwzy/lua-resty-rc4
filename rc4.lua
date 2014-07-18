local ffi = require "ffi"
local ffi_new=ffi.new
local C =ffi.C
local ffi_str = ffi.string
local setmetatable=setmetatable
local error = error

module(...)
_VERSION='0.01'

local mt={__index = _M}

ffi.cdef[[
        typedef struct rc4_key_st
        {
            unsigned int x,y;
            unsigned int data[256];
        } RC4_KEY;
void RC4_set_key(RC4_KEY *key,int len,const unsigned char *data);
void RC4(RC4_KEY *key,size_t len,const unsigned char *indata,unsigned char *outdata);

]]

function crypt(plaintext,key)
        local ciphertext = ffi_new("unsigned char[?]",#plaintext)
        local rc4_key = ffi_new(ffi.typeof("RC4_KEY[1]"))
        C.RC4_set_key(rc4_key,#key,key)
        C.RC4(rc4_key,#plaintext,plaintext,ciphertext)
        return ffi_str(ciphertext,#plaintext)
end

local class_mt = {
    -- to prevent use of casual module global variables
    __newindex = function (table, key, val)
        error('attempt to write to undeclared variable "' .. key .. '"')
    end
}

setmetatable(_M, class_mt)
