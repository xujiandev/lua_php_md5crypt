local crypt = require "crypt"
local phpcrypt = crypt:new()
local password = 'testtoken'
local salt = '$1$0r2hkb9S$'
local cryptpw = phpcrypt:cryptmd5(password, salt)
ngx.say(cryptpw)
