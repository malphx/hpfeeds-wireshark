-- hpfeeds.lua
--
-- a basic Wireshark's LUA dissector for the HPfeeds protocol
-- see README for installation and usage
--
-- hpfeeds-wireshark
-- Copyright (C) 2012  Franck GUENICHOT
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
-- 
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
-- 
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

packetnum = -1
hpfeeds = Proto("hpfeeds","HPfeeds", "HPfeeds Protocol")

-- Protocol Fields

local f = hpfeeds.fields
local opcodes = { [0] = "Error",[1] = "Info",[2] = "Auth",[3] = "Publish",[4] = "Subscribe"}
f.msglength = ProtoField.uint32("hpfeeds.msglen", "Message Length")
f.opcode = ProtoField.uint8("hpfeeds.opcode", "Opcode", nil, opcodes)
f.server = ProtoField.string("hpfeeds.server", "Server Name")
f.nonce = ProtoField.bytes("hpfeeds.nonce", "Nonce")
f.hash = ProtoField.bytes("hpfeeds.hash", "Hash")
f.ident = ProtoField.string("hpfeeds.ident", "Identifier")
f.channel = ProtoField.string("hpfeeds.channel", "Channel")
f.payload = ProtoField.bytes("hpfeeds.payload","Payload")

-- dissector function
function hpfeeds.dissector(buffer,pinfo,tree)
		
	local subtree = tree:add (hpfeeds, buffer(), "HPfeeds Protocol ("..buffer:len()..")")
	pinfo.cols.protocol = "HPfeeds"
	
	-- Packet header
	local offset = 0
	local msglen = buffer(offset,4)
	subtree:add(f.msglength,msglen)
	offset = offset + 4
	local opcode = buffer(offset, 1)
	subtree:add(f.opcode,opcode)
	offset = offset + 1
	
	if (opcode:uint() == 0) then
		-- Error packet
		local payload = buffer(offset)
		subtree:add(f.payload,payload)
		
	elseif (opcode:uint() == 1) then
		-- Info packet
		local len = buffer(offset, 1)
		offset = offset + 1
		local server = buffer(offset, len:uint())
		subtree:add(f.server,server)
		offset = offset + len:uint()
		local nonce = buffer(offset,4)
		subtree:add(f.nonce,nonce)
		offset = offset + 4
	
	elseif (opcode:uint() == 2) then
		-- Auth packet
		local len = buffer(offset, 1)
		offset = offset + 1
		local ident = buffer(offset, len:uint())
		subtree:add(f.ident,ident)
		offset = offset + len:uint()
		local hash = buffer(offset)
		subtree:add(f.hash,hash)		
		
	elseif (opcode:uint() == 3) then
		-- Publish packet
		local len = buffer(offset, 1)
		offset = offset + 1
		local ident = buffer(offset, len:uint())
		subtree:add(f.ident,ident)
		offset = offset + len:uint()
		len = buffer(offset, 1)
		offset = offset + 1
		local channel = buffer(offset, len:uint())
		subtree:add(f.channel,channel)
		offset = offset + len:uint()
		local payload = buffer(offset)
		subtree:add(f.payload,payload)

	elseif (opcode:uint() == 4) then
		-- Subscribe packet
		local len = buffer(offset, 1)
		offset = offset + 1
		local ident = buffer(offset, len:uint())
		subtree:add(f.ident,ident)
		offset = offset + len:uint()
		len = buffer(offset, 1)
		offset = offset + 1
		local channel = buffer(offset, len:uint())
		subtree:add(f.channel,channel)
		offset = offset + len:uint()		
 	end
	-- Info column display
	pinfo.cols.info = ("HPfeeds ")
	pinfo.cols.info:append (opcodes[opcode:uint()] .. " message")
	
end
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add (10000, hpfeeds)
