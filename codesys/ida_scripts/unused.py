def get_cbsize():
        """
        Returns the size of the addressable codebyte for the processor.
        
        Returns:
            Integer representing the number of 8-bit bytes in an
            addressable codebyte.
        """
        return (ida_idp.ph_get_cnbits()+7)/8

def get_data_value(addr):
        """
        Returns the data item value at an address based on its size.
        
        Args:
            addr: Integer representing a program address.
        """
        size = (ida_bytes.get_item_end(addr) - addr)*get_cbsize()
        if size == 1:   return ida_bytes.get_byte(addr)
        if size == 2:   return ida_bytes.get_16bit(addr)
        if size == 4:   return ida_bytes.get_32bit(addr)
        if size == 8:   return ida_bytes.get_64bit(addr)

        assert(False), "Unhandled data size {}".format(size)
        return None