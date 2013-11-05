local bit = require "bit"
local ssub = string.sub
local sbyte = string.byte
local schar = string.char
local sfind = string.find
local sformat = string.format
local insert = table.insert
local concat = table.concat
local setmetatable = setmetatable
local tonumber = tonumber
local error = error
local md5 = ngx.md5

module(...)

_VERSION = '0.01'

local mt = { __index = _M }

function new(self)
    return setmetatable({}, mt)
end

local function getchar(s, n)
	return schar(sbyte(s, n))
end

local function to64(v, n)
	local itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
	local ret = ''
	for n = n - 1, 0, -1 do
		ret = ret .. getchar(itoa64, bit.band(v, 0x3f) + 1)
		v = bit.rshift(v, 6)
	end
	return ret
end

local function packH(str)
	local packstr = ''
	for k = 1, #str, 2 do
		local chars = getchar(str, k) .. getchar(str, k + 1)
		packstr = packstr .. schar(tonumber(chars, 16))
	end
	return packstr
end

local function judgment(param)
	if 0 == tonumber(param) or '0' == param then
		return nil
	else
		return param
	end
end

function cryptmd5(self, pw, salt)
	local magic = '$1$'
	if ssub(salt, 1, #magic) == magic then
		salt = ssub(salt, #magic + 1, #salt)
	end
    local delim_from, _ = sfind(salt, '$', 1)
	salt = ssub(salt, 1, delim_from - 1)
	salt = ssub(salt, 1, 8)

	local ctx = pw .. magic .. salt
	local packctx = packH(md5(pw .. salt .. pw))

	for k = #pw, 1, -16 do
		ctx = ctx .. ssub(packctx, 1, (#pw > 16) and 16 or #pw)
	end

	local lenpw = #pw
	while lenpw > 0 do
		if judgment(bit.band(lenpw, 1)) then
			ctx = ctx .. schar(0)
		else
			ctx = ctx .. getchar(pw, 1)
		end
		lenpw = bit.rshift(lenpw, 1)
	end
	local final = packH(md5(ctx))

	for k = 0, 999 do
		local tmpctx = ''
		if judgment(bit.band(k, 1)) then
			tmpctx = tmpctx .. pw
		else
			tmpctx = tmpctx .. ssub(final, 1, 16)
		end
		if judgment(k % 3) then
			tmpctx = tmpctx .. salt
		end
		if judgment(k % 7) then
			tmpctx = tmpctx .. pw
		end
		if judgment(bit.band(k, 1)) then
			tmpctx = tmpctx .. ssub(final, 1, 16)
		else
			tmpctx = tmpctx .. pw
		end
		final = packH(md5(tmpctx))
	end

	local passwd = {}
	insert(passwd, to64(bit.bor(bit.lshift(sbyte(final, 1), 16), bit.lshift(sbyte(final, 7), 8), sbyte(final, 13)), 4))
	insert(passwd, to64(bit.bor(bit.lshift(sbyte(final, 2), 16), bit.lshift(sbyte(final, 8), 8), sbyte(final, 14)), 4))
	insert(passwd, to64(bit.bor(bit.lshift(sbyte(final, 3), 16), bit.lshift(sbyte(final, 9), 8), sbyte(final, 15)), 4))
	insert(passwd, to64(bit.bor(bit.lshift(sbyte(final, 4), 16), bit.lshift(sbyte(final, 10), 8), sbyte(final, 16)), 4))
	insert(passwd, to64(bit.bor(bit.lshift(sbyte(final, 5), 16), bit.lshift(sbyte(final, 11), 8), sbyte(final, 6)), 4))
	insert(passwd, to64(sbyte(final, 12), 2))

	return magic .. salt .. '$' .. concat(passwd, '')

end

local class_mt = {
    -- to prevent use of casual module global variables
    __newindex = function (table, key, val)
        error('attempt to write to undeclared variable "' .. key .. '"')
    end
}

setmetatable(_M, class_mt)
