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
f.msglength = ProtoField.uint32("hpfeeds.msglen", "Message length")
f.opcode = ProtoField.uint8("hpfeeds.opcode", "Opcode", nil, opcodes)
f.server = ProtoField.string("hpfeeds.server", "Broker name")
f.nonce = ProtoField.bytes("hpfeeds.nonce", "Nonce")
f.hash = ProtoField.bytes("hpfeeds.hash", "Hash")
f.ident = ProtoField.string("hpfeeds.ident", "Identifier")
f.channel = ProtoField.string("hpfeeds.channel", "Channel")
f.errmsg = ProtoField.string("hpfeeds.errmsg", "Error")
f.payload = ProtoField.bytes("hpfeeds.payload","Payload")

-- dissector function
function hpfeeds.dissector(buffer,pinfo,tree)
		
	-- Add an HPfeeds Protocol subtree in the decoded pane
	local subtree = tree:add (hpfeeds, buffer(), "HPfeeds Protocol ("..buffer:len()..")")
	local info_msg_type
	local info_error
	local info_ident
	local info_chan
	local info_broker
	
	-- pktlen stores the actual buffer size
	local pktlen = buffer:len()
	local offset = 0
	-- used for TCP reassembly stuff
	pinfo.desegment_len = 0
	
	-- whole HPfeeds message size
	-- some message cannot fit in a single packet
	-- we need to know the message size to as wireshark to do reassembly
	local msg_len
	
	-- Stores the offset of the starting point of a message
	-- it's used when messages are stacked in the same packet
	-- for example, multiple channels subscription in a single subscribe packet
	local msg_start
	
	-- main dissection loop
	while offset < pktlen do
		-- if offset is less than pktlen, then we have stacked messages
		msg_start = offset	
		-- Packet header
		msg_len = buffer(offset,4)
		offset = offset + 4
		local opcode = buffer(offset, 1)
		offset = offset + 1
		
		-- Displays message general info in the decoded pane
		subtree:add(f.msglength,msg_len)
		subtree:add(f.opcode,opcode)
		
		-- Stores the message's type in a string 
		-- used in the information column
		info_msg_type = opcodes[opcode:uint()]
		
		if (opcode:uint() == 0) then
				-- Error packet
				local errmsg = buffer(offset)
				offset = pktlen
				
				-- displays decoded info
				msg_tree = subtree:add(hpfeeds, buffer(offset), "Error message")
				msg_tree:add(f.errmsg,errmsg)
				
				
		elseif (opcode:uint() == 1) then
				-- Info packet
				local len = buffer(offset, 1)
				offset = offset + 1
				local server = buffer(offset, len:uint())
				offset = offset + len:uint()
				local nonce = buffer(offset,4)
				offset = offset + 4
				-- displays decoded message info
				msg_tree = subtree:add(hpfeeds, buffer(offset), "Info message, " .. "Broker: " .. server:string())
				msg_tree:add(f.server,server)
				msg_tree:add(f.nonce,nonce)
				-- populates information vars
				info_broker = server:string()
						
		elseif (opcode:uint() == 2) then
				-- Auth packet
				local len = buffer(offset, 1)
				offset = offset + 1
				local ident = buffer(offset, len:uint())
				offset = offset + len:uint()
				local hash = buffer(offset)
				offset = pktlen
				
				-- displays decoded message info
				msg_tree = subtree:add(hpfeeds, buffer(offset), "Auth message, " .. "Ident: " .. ident:string())
				msg_tree:add(f.ident,ident)
				msg_tree:add(f.hash,hash)
				-- populates information vars
				info_ident = ident:string()
								
		elseif (opcode:uint() == 3) then
 				-- Publish packet
				local len = buffer(offset, 1)
				offset = offset + 1
				local ident = buffer(offset, len:uint())
				offset = offset + len:uint()
				len = buffer(offset, 1)
				offset = offset + 1
				local channel = buffer(offset, len:uint())
				offset = offset + len:uint()
				local payload = buffer(offset)
				offset = pktlen
				
				-- displays decoded message info
				msg_tree = subtree:add(hpfeeds, buffer(offset), "Publish message, " .. "Ident: " .. ident:string() .. ", Channel: " .. channel:string() )
				msg_tree:add(f.ident,ident)
				msg_tree:add(f.channel,channel)
				msg_tree:add(f.payload,payload)
				-- populates information vars
				info_ident = ident:string()
				info_chan = channel:string()
							
		elseif (opcode:uint() == 4) then
				-- Subscribe packet				 
				local len = buffer(offset, 1)
				offset = offset + 1
				local ident = buffer(offset, len:uint())
				offset = offset + len:uint()
				local channel = buffer(offset, ((msg_start + msg_len:uint()) - offset))
				offset = offset + ((msg_start + msg_len:uint()) - offset)
				
				-- displays decoded message info
				msg_tree = subtree:add(hpfeeds, buffer(offset), "Subscribe message, " .. "Ident: " .. ident:string() .. ", Channel: " .. channel:string() )
				msg_tree:add(f.ident,ident)
				msg_tree:add(f.channel,channel)
				-- populates information vars
				info_ident = ident:string()
				info_chan = channel:string()
							
		end
	end
	
	-- Do we have enough data to decode the message ?
	-- if offset is less than msg_len then we don't have enough data
	-- and we must ask wireshark for more segments
	if offset < msg_len:uint() then
			pinfo.desegment_len = msg_len:uint() - offset
			pinfo.desegment_offset = msg_start
	end
	
	-- Info column display
	pinfo.cols.info = ("HPfeeds ")
	pinfo.cols.info:append (info_msg_type .. " message")
	if 		 info_msg_type == "Error" 	  then pinfo.cols.info:append (", Error: " .. info_error)
	elseif info_msg_type == "Info" 			then pinfo.cols.info:append (", Broker: " .. info_broker)
	elseif info_msg_type == "Auth" 			then pinfo.cols.info:append (", Ident: " .. info_ident)
	elseif info_msg_type == "Publish" 	then pinfo.cols.info:append (", Ident: " .. info_ident .. ", Channel: " .. info_chan)
	elseif info_msg_type == "Subscribe" then pinfo.cols.info:append (", Ident: " .. info_ident .. ", Channel: " .. info_chan)
	end
	
	
	
end
-- register the dissector
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add (10000, hpfeeds)
