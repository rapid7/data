codesys_protocol = Proto("codesysv3", "CoDeSys V3 Protocol")

-- Basic header fields
fld_codesysv3_magic_byte                =  ProtoField.uint8("codesysv3.magic_byte",                "Magic byte",       base.HEX)

fld_codesysv3_hop_info                  =  ProtoField.uint8("codesysv3.hop_info",                  "Hop info",         base.HEX)
fld_codesysv3_hop_info_hop_count        =  ProtoField.uint8("codesysv3.hop_info.hop_count",        "Hop count",        base.HEX, nil, 0xF8)
fld_codesysv3_hop_info_header_length    =  ProtoField.uint8("codesysv3.hop_info.header_length",    "Header length",    base.HEX, nil, 0x07)

fld_codesysv3_packet_info               =  ProtoField.uint8("codesysv3.packet_info",               "Packet info",      base.HEX)
fld_codesysv3_packet_info_priority      =  ProtoField.uint8("codesysv3.packet_info.priority",      "Priority",         base.HEX, { [0] = "Low", [1] = "Normal", [2] = "High", [3] = "Emergency" }, 0xC0)
fld_codesysv3_packet_info_signal        =  ProtoField.uint8("codesysv3.packet_info.signal",        "Signal",           base.HEX, { [1] = "Signal", [0] = "No Signal"}, 0x20)
fld_codesysv3_packet_info_address_type  =  ProtoField.uint8("codesysv3.packet_info.address_type",  "Address type",     base.HEX, { [1] = "Relative address", [0] = "Absolute address" }, 0x10)
fld_codesysv3_packet_info_max_block_length =  ProtoField.uint8("codesysv3.packet_info.max_block_length", "Maximum block length", base.HEX, nil, 0x0F)

fld_codesysv3_service_id                = ProtoField.uint8("codesysv3.service_id",                 "Service ID",       base.HEX, { [1] = "Address Service Request", [2] = "Address Service Response", [3] = "Name Service Request", [4] = "Name Service Response", [0x40] = "Channel Service" })

fld_codesysv3_message_id                = ProtoField.uint8("codesysv3.message_id",                 "Message ID",       base.HEX)

fld_codesysv3_address_lengths           = ProtoField.uint8("codesysv3.address_lengths",            "Address Lengths",  base.HEX)
fld_codesysv3_address_lengths_receiver  = ProtoField.uint8("codesysv3.address_lengths.receiver",   "Receiver address length", base.HEX, nil, 0x0F)
fld_codesysv3_address_lengths_sender    = ProtoField.uint8("codesysv3.address_lengths.sender",     "Sender address length", base.HEX, nil, 0xF0)

fld_codesysv3_broadcast_id              = ProtoField.uint16("codesysv3.broadcast_id",              "Broadcast ID",     base.HEX)

fld_codesysv3_addresses                 = ProtoField.uint8("codesysv3.addresses",                  "Addresses",        base.HEX)
fld_codesysv3_addresses_receiver        = ProtoField.uint8("codesysv3.addresses.receiver",         "Receiver Address", base.HEX)
fld_codesysv3_addresses_sender          = ProtoField.uint8("codesysv3.addresses.sender",           "Sender Address",   base.HEX)

fld_codesysv3_padding                   = ProtoField.bytes("codesysv3.padding",                    "Padding")

fld_codesysv3_payload                   = ProtoField.bytes("codesysv3.payload",                    "Payload")

-- Name service
-- General header fields for Name Service packets
fld_codesysv3_name_service_header       = ProtoField.none("codesysv3.name_service",                "Name Service Header")
fld_codesysv3_name_service_pkg_type     = ProtoField.uint16("codesysv3.name_service.pkg_type",     "Package type",     base.HEX, { [0xC201] = "Resolve Name", [0xC202] = "Resolve Address", [0xC203] = "Resolve Gateway", [0xC280] = "Identification" })
fld_codesysv3_name_service_version      = ProtoField.uint16("codesysv3.name_service.version",      "Version",          base.HEX)
fld_codesysv3_name_service_request_id   = ProtoField.uint32("codesysv3.name_service.request_id",   "Request ID",       base.HEX)

-- Name Service Request
fld_codesysv3_name_service_request      = ProtoField.none("codesysv3.name_service_request",        "Name Service Request")
fld_codesysv3_name_service_request_name = ProtoField.string("codesysv3.name_service_request.name", "Name Service Request Name", base.UNICODE)

-- Name Service Response - Nodeinfo
fld_codesysv3_name_service_response     = ProtoField.none("codesysv3.name_service_response",       "Name Service Response")
-- TODO: Name Service Response Name, Address, Resolved Gateway
fld_codesysv3_name_service_response_nodeinfo = ProtoField.none("codesysv3.name_service_response.nodeinfo", "Nodeinfo")

-- Nodeinfo Version 4.00
fld_codesysv3_name_service_response_nodeinfo400_max_channels = ProtoField.uint16("codesysv3.name_service.nodeinfo.max_channels", "Max channels", base.DEC)
-- TODO: Add field values for byte order
fld_codesysv3_name_service_response_nodeinfo400_byte_order = ProtoField.uint8("codesysv3.name_service.nodeinfo.byte_order", "Byte order", base.HEX)
fld_codesysv3_name_service_response_nodeinfo400_addr_difference = ProtoField.uint16("codesysv3.name_service.nodeinfo.addr_difference", "Address difference", base.DEC)
fld_codesysv3_name_service_response_nodeinfo400_parent_addr_size = ProtoField.uint16("codesysv3.name_service.nodeinfo.parent_addr_size", "Parent address size", base.DEC)
fld_codesysv3_name_service_response_nodeinfo400_node_name_length = ProtoField.uint16("codesysv3.name_service.nodeinfo.node_name_length", "Node name length", base.DEC)
fld_codesysv3_name_service_response_nodeinfo400_device_name_length = ProtoField.uint16("codesysv3.name_service.nodeinfo.device_name_length", "Device name length", base.DEC)
fld_codesysv3_name_service_response_nodeinfo400_vendor_name_length = ProtoField.uint16("codesysv3.name_service.nodeinfo.vendor_name_length", "Vendor name length", base.DEC)
fld_codesysv3_name_service_response_nodeinfo400_target_type = ProtoField.uint32("codesysv3.name_service.nodeinfo.target_type", "Target type", base.HEX)
fld_codesysv3_name_service_response_nodeinfo400_target_id = ProtoField.uint32("codesysv3.name_service.nodeinfo.target_id", "Target ID", base.HEX)
fld_codesysv3_name_service_response_nodeinfo400_target_version = ProtoField.uint32("codesysv3.name_service.nodeinfo.target_version", "Target Version", base.HEX)
fld_codesysv3_name_service_response_nodeinfo400_flags = ProtoField.uint32("codesysv3.name_service.nodeinfo.flags", "Flags", base.HEX)
fld_codesysv3_name_service_response_nodeinfo400_flags_encrypted_comm_supported = ProtoField.uint32("codesysv3.name_service.nodeinfo.flags.encrypted_comm_supported", "Encrypted communication supported", base.HEX, { [0] = "No", [1] = "Yes" }, 0x00000001)
fld_codesysv3_name_service_response_nodeinfo400_flags_encrypted_comm_required = ProtoField.uint32("codesysv3.name_service.nodeinfo.flags.encrypted_comm_required", "Encrypted communication required", base.HEX, { [0] = "No", [1] = "Yes" }, 0x00000002)
fld_codesysv3_name_service_response_nodeinfo400_serial_number_length = ProtoField.uint16("codesysv3.name_service.nodeinfo.serial_number_length", "Serial number length", base.DEC)
fld_codesysv3_name_service_response_nodeinfo400_oem_data_length = ProtoField.uint16("codesysv3.name_service.nodeinfo.oem_data_length", "OEM data length", base.DEC)
fld_codesysv3_name_service_response_nodeinfo400_block_drv_type = ProtoField.uint8("codesysv3.name_service.nodeinfo.blk_drv_type", "Block driver type", base.HEX, { [0x00] = "None", [0x01] = "TCP", [0x02] = "COM", [0x03] = "USB", [0x04] = "SHM", [0x05] = "UDP", [0x06] = "CAN Client", [0x07] = "CAN Server", [0x08] = "Direct call" })
fld_codesysv3_name_service_response_nodeinfo400_reserved_byte = ProtoField.uint8("codesysv3.name_service.nodeinfo.reserved_byte", "Reserved", base.HEX)
fld_codesysv3_name_service_response_nodeinfo400_reserved_dword = ProtoField.uint32("codesysv3.name_service.nodeinfo.reserved_dword", "Reserved", base.HEX)
fld_codesysv3_name_service_response_nodeinfo400_parent_address = ProtoField.bytes("codesysv3.name_service.nodeinfo.parent_address", "Parent address")
fld_codesysv3_name_service_response_nodeinfo400_node_name = ProtoField.string("codesysv3.name_service.nodeinfo.node_name", "Node name", base.UNICODE)
fld_codesysv3_name_service_response_nodeinfo400_device_name = ProtoField.string("codesysv3.name_service.nodeinfo.device_name", "Device name", base.UNICODE)
fld_codesysv3_name_service_response_nodeinfo400_vendor_name = ProtoField.string("codesysv3.name_service.nodeinfo.vendor_name", "Vendor name", base.UNICODE)
fld_codesysv3_name_service_response_nodeinfo400_serial_number = ProtoField.string("codesysv3.name_service.nodeinfo.serial_number", "Serial number", base.ASCII)
fld_codesysv3_name_service_response_nodeinfo400_oem_data = ProtoField.bytes("codesysv3.name_service.nodeinfo.oem_data", "OEM data")

codesys_protocol.fields = {
    fld_codesysv3_magic_byte,
    fld_codesysv3_hop_info,
    fld_codesysv3_hop_info_hop_count,
    fld_codesysv3_hop_info_header_length,
    fld_codesysv3_packet_info,
    fld_codesysv3_packet_info_priority,
    fld_codesysv3_packet_info_signal,
    fld_codesysv3_packet_info_address_type,
    fld_codesysv3_packet_info_max_block_length,
    fld_codesysv3_service_id,
    fld_codesysv3_message_id,
    fld_codesysv3_address_lengths,
    fld_codesysv3_address_lengths_receiver,
    fld_codesysv3_address_lengths_sender,
    fld_codesysv3_broadcast_id,
    fld_codesysv3_addresses,
    fld_codesysv3_addresses_receiver,
    fld_codesysv3_addresses_sender,
    fld_codesysv3_padding,
    fld_codesysv3_payload,
    fld_codesysv3_name_service_header,
    fld_codesysv3_name_service_pkg_type,
    fld_codesysv3_name_service_version,
    fld_codesysv3_name_service_request_id,
    fld_codesysv3_name_service_request,
    fld_codesysv3_name_service_request_name,
    fld_codesysv3_name_service_response,
    fld_codesysv3_name_service_response_nodeinfo,
    fld_codesysv3_name_service_response_nodeinfo400_max_channels,
    fld_codesysv3_name_service_response_nodeinfo400_byte_order,
    fld_codesysv3_name_service_response_nodeinfo400_addr_difference,
    fld_codesysv3_name_service_response_nodeinfo400_parent_addr_size,
    fld_codesysv3_name_service_response_nodeinfo400_node_name_length,
    fld_codesysv3_name_service_response_nodeinfo400_device_name_length,
    fld_codesysv3_name_service_response_nodeinfo400_vendor_name_length,
    fld_codesysv3_name_service_response_nodeinfo400_target_type,
    fld_codesysv3_name_service_response_nodeinfo400_target_id,
    fld_codesysv3_name_service_response_nodeinfo400_target_version,
    fld_codesysv3_name_service_response_nodeinfo400_flags,
    fld_codesysv3_name_service_response_nodeinfo400_flags_encrypted_comm_required,
    fld_codesysv3_name_service_response_nodeinfo400_flags_encrypted_comm_supported,
    fld_codesysv3_name_service_response_nodeinfo400_serial_number_length,
    fld_codesysv3_name_service_response_nodeinfo400_oem_data_length,
    fld_codesysv3_name_service_response_nodeinfo400_block_drv_type,
    fld_codesysv3_name_service_response_nodeinfo400_reserved_byte,
    fld_codesysv3_name_service_response_nodeinfo400_reserved_dword,
    fld_codesysv3_name_service_response_nodeinfo400_parent_address,
    fld_codesysv3_name_service_response_nodeinfo400_node_name,
    fld_codesysv3_name_service_response_nodeinfo400_device_name,
    fld_codesysv3_name_service_response_nodeinfo400_vendor_name,
    fld_codesysv3_name_service_response_nodeinfo400_serial_number,
    fld_codesysv3_name_service_response_nodeinfo400_oem_data,
}

function codesys_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = codesys_protocol.name

  local subtree = tree:add(codesys_protocol, buffer(), "CoDeSys V3 Protocol Data")

  -- Magic value
  subtree:add_le(fld_codesysv3_magic_byte, buffer(0,1))
 
  -- Hop info
  local header_len_bytes = bit.band(buffer(1,1):uint(), 0x07) * 2
  local subtree_hop_info = subtree:add(fld_codesysv3_hop_info, buffer(1,1))
  subtree_hop_info:add(fld_codesysv3_hop_info_hop_count, buffer(1,1))
  subtree_hop_info:add(fld_codesysv3_hop_info_header_length, buffer(1,1)):append_text(" (Actual length: " .. header_len_bytes .. " bytes)")

  -- Packet info
  local max_block_len_bytes = (bit.band(buffer(2,1):uint(), 0x0F) + 1) * 32
  local subtree_packet_info = subtree:add(fld_codesysv3_packet_info, buffer(2,1))
  subtree_packet_info:add(fld_codesysv3_packet_info_priority, buffer(2,1))
  subtree_packet_info:add(fld_codesysv3_packet_info_signal, buffer(2,1))
  subtree_packet_info:add(fld_codesysv3_packet_info_address_type, buffer(2,1))
  subtree_packet_info:add(fld_codesysv3_packet_info_max_block_length, buffer(2,1)):append_text(" (Actual length: " .. max_block_len_bytes .. " bytes)" )

  -- Service ID
  local service_id = buffer(3,1):uint()
  subtree:add(fld_codesysv3_service_id, buffer(3,1))

  -- Message ID
  subtree:add(fld_codesysv3_message_id, buffer(4,1))

  -- Address lengths
  local addr_lengths = buffer(5,1):uint()
  local addr_length_receiver_bytes = bit.band(addr_lengths, 0x0F) * 2
  local addr_length_sender_bytes = bit.rshift(addr_lengths, 4) * 2
  local subtree_address_lengths = subtree:add(fld_codesysv3_address_lengths, buffer(5,1))
  subtree_address_lengths:add(fld_codesysv3_address_lengths_sender, buffer(5,1)):append_text(" (Actual length: " .. addr_length_sender_bytes .. " bytes)")
  subtree_address_lengths:add(fld_codesysv3_address_lengths_receiver, buffer(5,1)):append_text(" (Actual length: " .. addr_length_receiver_bytes .. " bytes)")
  
  -- FIXME: sanity check: addr_length_receiver_bytes + addr_length_sender_bytes + header_len_val == current offset which is usually 6
  local offset = 6

  -- FIXME: not always? needs investigation
  -- -- Broadcast ID
  -- -- In case the length of the receiver address is 0, this packet is a broadcast.
  -- -- This adds another 2-byte field called the broadcast ID
  -- -- FIXME: address type needs to be absolute for broadcasts - check this?
  -- if addr_length_receiver_bytes == 0 then
  --   subtree:add(fld_codesysv3_broadcast_id, buffer(offset, 2))
  --   offset = offset + 2
  -- end

  offset = header_len_bytes

  local offset_receiver_addr = header_len_bytes
  local offset_sender_addr = header_len_bytes + addr_length_receiver_bytes

  -- Address information
  -- FIXME: we could parse a lot more here. Absolute vs relative addresses etc.
  local subtree_addresses = subtree:add(fld_codesysv3_addresses, buffer(offset, addr_length_receiver_bytes + addr_length_sender_bytes))
  if addr_length_receiver_bytes > 0 then
    subtree_addresses:add(fld_codesysv3_addresses_receiver, buffer(offset_receiver_addr, addr_length_receiver_bytes))
  end
  if addr_length_sender_bytes > 0 then
    subtree_addresses:add(fld_codesysv3_addresses_sender, buffer(offset_sender_addr, addr_length_sender_bytes))
  end

  -- Payload
  -- skip ahead to the data
  offset = header_len_bytes + addr_length_receiver_bytes + addr_length_sender_bytes

  -- Add padding if necessary
  local padding_len = 0
  if bit.band(offset, 0x03) ~= 0 then
    padding_len = 2
  end

  if padding_len > 0 then
    subtree:add(fld_codesysv3_padding, buffer(offset, padding_len))
    offset = offset + padding_len
  end

  local remaining_bytes = length - offset
  if remaining_bytes > 0 then
    --local subtree_payload = subtree:add(fld_codesysv3_payload, buffer(offset, remaining_bytes))

    if service_id == 1 then
      -- dissect_address_service_request(buffer(offset, remaining_bytes), subtree)
    elseif service_id == 2 then
      -- dissect_address_service_response(buffer(offset, remaining_bytes), subtree)
    elseif service_id == 3 then
      dissect_name_service_request(buffer(offset, remaining_bytes), subtree)
    elseif service_id == 4 then
      dissect_name_service_response(buffer(offset, remaining_bytes), subtree)
    elseif service_id == 0x40 then
      -- dissect_channel_service(buffer(offset, remaining_bytes), subtree)
    end
  end


end

-- TODO
-- function dissect_address_service_request(buffer, tree)
-- end

-- TODO
-- function dissect_address_service_response(buffer, tree)
-- end

function dissect_name_service_header(buffer, tree)
  local subtree = tree:add(fld_codesysv3_name_service_header, buffer(0,8))

  local pkg_type = buffer(0,2):le_uint()
  local version = buffer(2,2):le_uint()
  local request_id = buffer(4,4):le_uint()

  subtree:add_le(fld_codesysv3_name_service_pkg_type, buffer(0,2))
  subtree:add_le(fld_codesysv3_name_service_version, buffer(2,2))
  subtree:add_le(fld_codesysv3_name_service_request_id, buffer(4,4))

  return pkg_type, version, request_id
end

function dissect_name_service_response_nodeinfo_v0400(buffer, tree)
  local subtree = tree:add(fld_codesysv3_name_service_response_nodeinfo, buffer):append_text(" Version 4.00")

  local offset = 0

  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_max_channels, buffer(offset,2))
  offset = offset + 2

  -- FIXME: if this byte indicates big endian, are the following multi-byte fields big endian as well?
  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_byte_order, buffer(offset,1))
  offset = offset + 1

  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_addr_difference, buffer(offset,1))
  offset = offset + 1

  local parent_addr_len = buffer(offset,2):le_uint()
  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_parent_addr_size, buffer(offset,2))
  offset = offset + 2

  local node_name_len = buffer(offset,2):le_uint()
  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_node_name_length, buffer(offset,2))
  offset = offset + 2

  local device_name_len = buffer(offset,2):le_uint()
  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_device_name_length, buffer(offset,2))
  offset = offset + 2

  local vendor_name_len = buffer(offset,2):le_uint()
  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_vendor_name_length, buffer(offset,2))
  offset = offset + 2

  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_target_type, buffer(offset,4))
  offset = offset + 4

  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_target_id, buffer(offset,4))
  offset = offset + 4

  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_target_version, buffer(offset,4))
  offset = offset + 4

  local subtree_flags = subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_flags, buffer(offset,4))
  subtree_flags:add_le(fld_codesysv3_name_service_response_nodeinfo400_flags_encrypted_comm_supported, buffer(offset,4))
  subtree_flags:add_le(fld_codesysv3_name_service_response_nodeinfo400_flags_encrypted_comm_required, buffer(offset,4))
  offset = offset + 4

  local serial_number_len = buffer(offset,1):le_uint()
  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_serial_number_length, buffer(offset,1))
  offset = offset + 1

  local oem_data_len = buffer(offset,1):le_uint()
  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_oem_data_length, buffer(offset,1))
  offset = offset + 1

  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_block_drv_type, buffer(offset,1))
  offset = offset + 1

  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_reserved_byte, buffer(offset,1))
  offset = offset + 1

  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_reserved_dword, buffer(offset,4))
  offset = offset + 4
  
  subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_reserved_dword, buffer(offset,4))
  offset = offset + 4

  if parent_addr_len > 0 then
    subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_parent_address, buffer(offset, parent_addr_len*2))
    offset = offset + parent_addr_len*2 + 2
  end

  if node_name_len > 0 then
    subtree:add_packet_field(fld_codesysv3_name_service_response_nodeinfo400_node_name, buffer(offset, node_name_len*2), ENC_UTF_16 + ENC_STRING + ENC_LITTLE_ENDIAN)
    offset = offset + node_name_len*2 + 2
  end

  if device_name_len > 0 then
    subtree:add_packet_field(fld_codesysv3_name_service_response_nodeinfo400_device_name, buffer(offset, device_name_len*2), ENC_UTF_16 + ENC_STRING + ENC_LITTLE_ENDIAN)
    offset = offset + device_name_len*2 + 2
  end

  if vendor_name_len > 0 then
    subtree:add_packet_field(fld_codesysv3_name_service_response_nodeinfo400_vendor_name, buffer(offset, vendor_name_len*2), ENC_UTF_16 + ENC_STRING + ENC_LITTLE_ENDIAN)
    offset = offset + vendor_name_len*2 + 2
  end

  if serial_number_len > 0 then
    subtree:add_packet_field(fld_codesysv3_name_service_response_nodeinfo400_serial_number, buffer(offset, serial_number_len), ENC_ASCII)
    offset = offset + serial_number_len
  end

  if oem_data_len > 0 then
    subtree:add_le(fld_codesysv3_name_service_response_nodeinfo400_oem_data, buffer(offset, oem_data_len))
    offset = offset + oem_data_len
  end
end

function dissect_name_service_request(buffer, tree)
  local subtree = tree:add(fld_codesysv3_name_service_request, buffer)

  local offset = 0
  dissect_name_service_header(buffer, subtree)
  offset = offset + 8

  -- TODO: string handling
  --if buffer:len() - offset >= 2 then
  --  subtree:add(fld_codesysv3_name_service_request_name, buffer)
  --end
end

function dissect_name_service_response(buffer, tree)
  local subtree = tree:add(fld_codesysv3_name_service_response, buffer)

  local offset = 0
  local pkg_type, version, _ = dissect_name_service_header(buffer, subtree)
  offset = offset + 8

  -- TODO: Add more pkg_types
  if pkg_type == 0xC280 then
    -- TODO: Add more versions
    if version == 0x0400 then
      dissect_name_service_response_nodeinfo_v0400(buffer(offset), subtree)
    end
  end
end

-- TODO
-- function dissect_channel_service(buffer, tree)
-- end


local udp_port = DissectorTable.get("udp.port")
udp_port:add(1740, codesys_protocol)
udp_port:add(1741, codesys_protocol)
udp_port:add(1742, codesys_protocol)
udp_port:add(1743, codesys_protocol)
