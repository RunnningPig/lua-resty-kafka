-- Copyright (C) Dejiang Zhu(doujiang24)
local ffi = require "ffi"


local bit = require "bit"


local protocol = require "resty.kafka.protocol.common"


local setmetatable = setmetatable
local concat = table.concat
local lshift = bit.lshift
local rshift = bit.rshift
local arshift = bit.arshift
local band = bit.band
local bor = bit.bor
local bxor = bit.bxor
local char = string.char
local crc32 = ngx.crc32_long
local crc32c = protocol.crc32c
local ngx_now = ngx.now
local floor = math.floor
local tonumber = tonumber


local _M = {}
local mt = { __index = _M }

local MESSAGE_VERSION_0 = 0
local MESSAGE_VERSION_1 = 1
local MESSAGE_VERSION_2 = 2


local API_VERSION_V0 = 0
local API_VERSION_V1 = 1
local API_VERSION_V2 = 2
local API_VERSION_V3 = 3


_M.API_VERSION_V0 = 0
_M.API_VERSION_V1 = 1
_M.API_VERSION_V2 = 2
_M.API_VERSION_V3 = 3

_M.ProduceRequest = 0
_M.FetchRequest = 1
_M.OffsetRequest = 2
_M.MetadataRequest = 3
_M.OffsetCommitRequest = 8
_M.OffsetFetchRequest = 9
_M.ConsumerMetadataRequest = 10

_M.SaslHandshakeRequest = 17
_M.ApiVersionsRequest = 18
_M.SaslAuthenticateRequest = 36


local function str_int8(int)
    return char(band(int, 0xff))
end


local function str_int16(int)
    return char(band(rshift(int, 8), 0xff),
                band(int, 0xff))
end


local function str_int32(int)
    -- ngx.say(debug.traceback())
    return char(band(rshift(int, 24), 0xff),
                band(rshift(int, 16), 0xff),
                band(rshift(int, 8), 0xff),
                band(int, 0xff))
end


-- XX int can be cdata: LL or lua number
local function str_int64(int)
    int = int * 1LL

    return char(tonumber(band(rshift(int, 56), 0xff)),
                tonumber(band(rshift(int, 48), 0xff)),
                tonumber(band(rshift(int, 40), 0xff)),
                tonumber(band(rshift(int, 32), 0xff)),
                tonumber(band(rshift(int, 24), 0xff)),
                tonumber(band(rshift(int, 16), 0xff)),
                tonumber(band(rshift(int, 8), 0xff)),
                tonumber(band(int, 0xff)))
end


function _M.new(self, apikey, correlation_id, client_id, api_version)
    api_version = api_version or API_VERSION_V0
    local len = 8
    local offset = 5
    local req = {
        0,   -- request size: int32
        str_int16(apikey),
        str_int16(api_version),
        str_int32(correlation_id),
    }

    if api_version > API_VERSION_V0  then
        local cid, clen
        if not client_id or #client_id == 0 then
            cid, clen = str_int16(-1), 2
        else
            cid, clen = client_id, #client_id
        end

        req[5] = str_int16(clen)
        req[6] = cid
        len = len + 2 + clen
        offset = offset + 2
    end

    return setmetatable({
        _req = req,
        api_key = apikey,
        api_version = api_version,
        offset = offset,
        len = len,
    }, mt)
end


function _M.int8(self, int)
    local req = self._req
    local offset = self.offset

    req[offset] = str_int8(int)

    self.offset = offset + 1
    self.len = self.len + 1
end


function _M.int16(self, int)
    local req = self._req
    local offset = self.offset

    req[offset] = str_int16(int)

    self.offset = offset + 1
    self.len = self.len + 2
end


function _M.int32(self, int)
    local req = self._req
    local offset = self.offset

    req[offset] = str_int32(int)

    self.offset = offset + 1
    self.len = self.len + 4
end


function _M.int64(self, int)
    local req = self._req
    local offset = self.offset

    req[offset] = str_int64(int)

    self.offset = offset + 1
    self.len = self.len + 8
end


function _M.string(self, str)
    if not str then
        -- -1 mean null
        return self:int16(-1)
    end

    local req = self._req
    local offset = self.offset
    local str_len = #str

    req[offset] = str_int16(str_len)
    req[offset + 1] = str

    self.offset = offset + 2
    self.len = self.len + 2 + str_len
end


function _M.bytes(self, str)
    local req = self._req
    local offset = self.offset
    local str_len = #str

    req[offset] = str_int32(str_len)
    req[offset + 1] = str

    self.offset = offset + 2
    self.len = self.len + 4 + str_len
end

-- The following code is referenced in this section.
-- https://github.com/Neopallium/lua-pb/blob/1253c85d7c67dc355ec8d827df74d72c4eee3e3f/pb/standard/pack.lua
local function varint_next_byte(num)
	if num >= 0 and num < 128 then return num end
	local b = bor(band(num, 0x7F), 0x80)
	return (b), varint_next_byte(rshift(num, 7))
end


local function varint64_next_byte_h_l(h, l)
	if h ~= 0 then
		-- encode lower 28 bits.
		local b1 = bor(band(l, 0x7F), 0x80)
		local b2 = bor(band(rshift(l, 7), 0x7F), 0x80)
		local b3 = bor(band(rshift(l, 14), 0x7F), 0x80)
		local b4 = bor(band(rshift(l, 21), 0x7F), 0x80)
		-- encode 4 bits from low 32-bits and 3 bits from high 32-bits
		local b5 = bor(band(rshift(l, 28), 0xF) + (band(h, 0x7) * 16), 0x80)
		h = rshift(h, 3)
		-- Use variable length encoding of
		return b1, b2, b3, b4, b5, varint_next_byte(h)
	end
	-- No high bits.  Use variable length encoding of low bits.
	return varint_next_byte(l)
end


local function str_varint64_cdata(num)
	return char(varint64_next_byte_h_l(tonumber(num / 0x100000000), tonumber(num % 0x100000000)))
end


-- convert number to unsigned int32
local function uint32(num)
	return num % 0x100000000
end


local function str_varint64_num(num)
	if num >= 0 and num <= 0xFFFFFFFF then
		return char(varint_next_byte(num))
	end
	local h, l = uint32(floor(num / 0x100000000)), uint32(num)
	return char(varint64_next_byte_h_l(h, l))
end


local function str_varint64(num)
	if type(num) == 'number' then
		return str_varint64_num(num)
	end
	return str_varint64_cdata(num)
end


local function str_varint32(num)
	-- only use the lowest 32-bits
	if num >= 0x100000000 then
		num = num % 0x100000000
	end
	if type(num) == 'number' then
		return str_varint64_num(num)
	end
	return str_varint64_cdata(num)
end


local function zigzag64(num)
	num = num * 2
	if num < 0 then
		num = (-num) - 1
	end
	return num
end


local function zigzag32(num)
	return bxor(lshift(num, 1), arshift(num, 31))
end


local function str_varint(num)
    return str_varint32(zigzag32(num))
end


local function str_varlong(num)
    return str_varint64(zigzag64(num))
end


function _M.varlong(self, num)
    local req = self._req
    local offset = self.offset

    local str = str_varlong(num)
    req[offset] = str

    self.offset = offset + 1
    self.len = self.len + #str
end


function _M.varint(self, num)
    local req = self._req
    local offset = self.offset

    local str = str_varint(num)
    req[offset] = str

    self.offset = offset + 1
    self.len = self.len + #str
end


local function message_package(key, msg, message_version)
    local key = key or ""
    local key_len = #key
    local len = #msg

    local req
    local head_len
    if message_version == MESSAGE_VERSION_1 then
        req = {
            -- MagicByte
            str_int8(1),
            -- XX hard code no Compression
            str_int8(0),
            str_int64(ffi.new("int64_t", (ngx_now() * 1000))), -- timestamp
            str_int32(key_len),
            key,
            str_int32(len),
            msg,
        }
        head_len = 22

    else
        req = {
            -- MagicByte
            str_int8(0),
            -- XX hard code no Compression
            str_int8(0),
            str_int32(key_len),
            key,
            str_int32(len),
            msg,
        }
        head_len = 14
    end

    local str = concat(req)
    return crc32(str), str, key_len + len + head_len
end


local function message_set_v0_1(self, messages, index, message_version)
    local req = self._req
    local off = self.offset
    local msg_set_size = 0

    for i = 1, index, 2 do
        local crc32, str, msg_len = message_package(messages[i], messages[i + 1], message_version)

        req[off + 1] = str_int64(0) -- offset
        req[off + 2] = str_int32(msg_len) -- include the crc32 length

        req[off + 3] = str_int32(crc32)
        req[off + 4] = str

        off = off + 4
        msg_set_size = msg_set_size + msg_len + 12
    end

    req[self.offset] = str_int32(msg_set_size) -- MessageSetSize

    self.offset = off + 1
    self.len = self.len + 4 + msg_set_size
end


local function str_record(key, msg, msgcnt)
    key = key or ""
    local str = concat {
        str_int8(0),        -- attributes
        str_varlong(0),     -- timestampDelta
        str_varint(msgcnt), -- offsetDelta
        str_varint(#key),   -- keyLength
        key,                -- key
        str_varint(#msg),   -- valueLength
        msg,                -- value
        str_varint(0),      -- headersCount
    }
    return str
end


local function str_record_batch(messages, index)
    local req = {}

    local off = 9
    local record_count = 0
    for i = 1, index, 2 do
        local record = str_record(messages[i], messages[i + 1], record_count)
        req[off] = str_varint(#record)  -- recordLength
        req[off + 1] = record

        record_count = record_count + 1
        off = off + 2
    end

    req[1] = str_int16(0)                   -- attributes
    req[2] = str_int32(record_count-1)      -- lastOffsetDelta
    req[3] = str_int64(ngx_now() * 1000)    -- baseTimestamp
    req[4] = str_int64(ngx_now() * 1000)    -- maxTimestamp
    req[5] = str_int64(-1)              -- producerId
    req[6] = str_int16(0)               -- producerEpoch
    req[7] = str_int32(0)               -- baseSequence
    req[8] = str_int32(record_count)    -- recordCount

    local str = concat(req)
    return str
end


local function message_set_v2(self, messages, index)
    local req = self._req
    local off = self.offset

    local record_batch = str_record_batch(messages, index)
    local message_size = 8 + 4 + 4 + 1 + 4 + #record_batch

    -- https://kafka.apache.org/documentation.html#recordbatch
    req[off + 0] = str_int32(message_size)          -- messageSize
    req[off + 1] = str_int64(0)                     -- baseOffset
    req[off + 2] = str_int32(message_size-(8+4))    -- batchLength
    req[off + 3] = str_int32(0)                     -- partitionLeaderEpoch
    req[off + 4] = str_int8(2)                      -- magic
    req[off + 5] = str_int32(crc32c(record_batch))  -- crc
    req[off + 6] = record_batch

    self.offset = off + 7
    self.len = self.len + 4 + message_size
end


function _M.message_set(self, messages, index)
    local index = index or #messages

    local message_version = MESSAGE_VERSION_0
    if self.api_key == _M.ProduceRequest and self.api_version == API_VERSION_V2 then
        message_version = MESSAGE_VERSION_1

    elseif self.api_key == _M.ProduceRequest and self.api_version == API_VERSION_V3 then
        message_version = MESSAGE_VERSION_2
    end

    if message_version == MESSAGE_VERSION_2 then
        message_set_v2(self, messages, index)

    else
        message_set_v0_1(self, messages, index, message_version)
    end

end


function _M.package(self)
    local req = self._req
    req[1] = str_int32(self.len)

    return req
end


return _M
