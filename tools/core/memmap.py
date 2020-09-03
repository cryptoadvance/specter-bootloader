"""Bootloader: operations on embedded memory map."""

# Types representing sequence of bytes, for type checking
_byteslike = (bytes, bytearray)

# Opening XML-like tag
_opening_tag = b'<memory_map:lebin>'
# Closing XML-like tag
_closing_tag = b'</memory_map:lebin>'
# Minimum length of a memory map
_memmap_min_len = (1+4)
# Maximum length of a memory map
_memmap_max_len = (1+256)
# Maximum allowed size of payload (16 megabytes)
_firmware_size_max = 16 * 1024 * 1024

# Mapping between element indexes and its (name, minimum, maximum)
_element_names = {
    0: ('bootloader_size', 1, _firmware_size_max),
    1: ('main_firmware_start', None, None),
    2: ('main_firmware_size', 1, _firmware_size_max)
}


def get_memmap(firmware):
    """Returns a memory map embedded in the firmware."""
    if not isinstance(firmware, _byteslike):
        raise TypeError("Firmware should be bytes-like")
    if len(firmware) > _firmware_size_max:
        raise TypeError("Firmware is larger than allowed")

    # Search for memory map record in the firmware
    idx = firmware.find(_opening_tag)
    if idx < 0:
        raise ValueError("Firmware has no embedded memory map")
    idx += len(_opening_tag)

    # Ensure there is no more records of such type
    idx2 = firmware.find(_opening_tag, idx)
    if idx2 >= 0:
        raise ValueError("Firmware contains more than one memory map")

    # Search for closing tag and calculate  length
    idx_end = firmware.find(_closing_tag, idx)
    if idx_end < 0:
        raise ValueError("Memory map record has no closing tag")

    # Defode memory map
    map_bin = firmware[idx: idx_end]
    if len(map_bin) < _memmap_min_len or len(map_bin) > _memmap_max_len:
        raise ValueError("Memory map has incorrect format")
    elem_size = map_bin[0]
    if elem_size != 4 and elem_size != 8:
        raise ValueError("Memory map has incorrect format")
    if len(map_bin) < elem_size + 1 or ((len(map_bin) - 1) % elem_size) != 0:
        raise ValueError("Memory map has incorrect format")
    n_elem = (len(map_bin) - 1) // elem_size
    if n_elem < len(_element_names):
        raise ValueError("Memory map has incorrect format")

    # Decode elements creating a dictionary
    memmap = {}
    for i in range(n_elem):
        off = 1 + i * elem_size
        elem_bytes = map_bin[off: off + elem_size]
        elem = int.from_bytes(elem_bytes, byteorder='little')
        name, min_value, max_value = _element_names[i]
        if min_value is not None and elem < min_value:
            raise ValueError("Memory map has incorrect format")
        if max_value is not None and elem > max_value:
            raise ValueError("Memory map has incorrect format")
        memmap[name] = elem

    return memmap
