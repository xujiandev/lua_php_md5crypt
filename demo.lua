--local crypt = require "crypt"
--local phpcrypt = crypt:new()
--local password = 'testtoken'
--local salt = '$1$0r2hkb9S$'
--local cryptpw = phpcrypt:cryptmd5(password, salt)
--ngx.say(cryptpw)

local ffi = require "ffi"

ffi.cdef[[
char *crypt(const char *key, const char *salt);
]]

local ccrypt = ffi.load("crypt")
local temp = ccrypt.crypt('!#kpqdq7219129#mls', '$1$r/6wWgJJ$')
local result = ffi.string(temp)

print(result)
