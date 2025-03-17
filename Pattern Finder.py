import struct
import ctypes
from ctypes import wintypes
import time
import signal
import re


# ====== CONFIGURATION ======
# Pattern to search for (use ?? for wildcards)
# Format: space-separated hex bytes
PATTERN_STRING = "?? ?? ?? ?? ?? ?? ?? ??"

# Field offsets for verification
FIELD_OFFSETS = {
    'Field1': 0x00,
    'Field2': 0x00,
    'Field3': 0x00,
    'Field4': 0x00,
    'Field5': 0x00
}

# Limit number of instances to find
MAX_INSTANCES = 2

# Search parameters
CHUNK_SIZE = 512 * 1024  # Scan memory in 512KB chunks
REGION_SIZE_LIMIT = 20 * 1024 * 1024  # Skip memory regions larger than 20MB

# ====== END CONFIGURATION ======

# Windows API constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100

# Flag to track if scan should continue
scanning = True

# Debug settings
DEBUG = False

def debug_print(*args, **kwargs):
    """Print debug information if DEBUG is enabled"""
    if DEBUG:
        print(*args, **kwargs)

def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully abort scanning"""
    global scanning
    scanning = False
    debug_print("\nScan aborted by user. Finishing current operation...")

# Initialize signal handler for Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """Structure for VirtualQueryEx"""
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

def parse_pattern(pattern_string):
    """Parse a string pattern into a list of bytes with wildcards (None)"""
    pattern_parts = pattern_string.strip().split()
    pattern = []
    
    for part in pattern_parts:
        if part == "??":
            pattern.append(None)  # None represents a wildcard
        else:
            try:
                pattern.append(int(part, 16))
            except ValueError:
                raise ValueError(f"Invalid hex value in pattern: {part}")
    
    return pattern

def read_memory(process_handle, address, size):
    """Read memory from a process using ReadProcessMemory"""
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    
    success = ctypes.windll.kernel32.ReadProcessMemory(
        process_handle, 
        ctypes.c_void_p(address), 
        buffer, 
        size, 
        ctypes.byref(bytes_read)
    )
    
    if success and bytes_read.value > 0:
        return buffer.raw[:bytes_read.value]
    
    debug_print(f"Failed to read memory at 0x{address:X}")
    return None

def read_int32(process_handle, address):
    """Read a 32-bit integer from memory"""
    data = read_memory(process_handle, address, 4)
    if data:
        try:
            return struct.unpack("I", data)[0]
        except struct.error:
            return None
    return None

def read_bool(process_handle, address):
    """Read a boolean value from memory"""
    data = read_memory(process_handle, address, 1)
    if data:
        return data[0] != 0
    return None

def dump_memory(process_handle, address, size=128):
    """Dump memory region for debugging"""
    data = read_memory(process_handle, address, size)
    if not data:
        debug_print(f"Failed to read memory at 0x{address:X}")
        return
    
    debug_print(f"Memory dump at 0x{address:X}:")
    for i in range(0, len(data), 16):
        line = data[i:i+16]
        hex_values = ' '.join(f"{b:02X}" for b in line)
        ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line)
        debug_print(f"0x{address+i:X}: {hex_values.ljust(48)} | {ascii_values}")

def find_pattern_in_data(data, pattern, start_offset=0):
    """Find all instances of a pattern with wildcards in a data buffer"""
    data_len = len(data)
    pattern_len = len(pattern)
    
    matches = []
    
    for i in range(start_offset, data_len - pattern_len + 1):
        match = True
        wildcard_values = {}
        
        for j, pattern_byte in enumerate(pattern):
            if pattern_byte is None:  # Wildcard
                wildcard_values[j] = data[i + j]
            elif data[i + j] != pattern_byte:
                match = False
                break
        
        if match:
            matches.append((i, wildcard_values))
            
    return matches

def search_for_pattern(process_handle, pattern):
    """Search for a byte pattern in process memory"""
    # Map all accessible memory regions
    memory_regions = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    
    debug_print("Mapping memory regions...")
    while ctypes.windll.kernel32.VirtualQueryEx(
        process_handle, 
        ctypes.c_void_p(address), 
        ctypes.byref(mbi), 
        ctypes.sizeof(mbi)
    ) and scanning:
        # Get base_address as an integer
        base_address = mbi.BaseAddress
        if base_address:
            base_address_int = ctypes.cast(base_address, ctypes.c_void_p).value
        else:
            address += 0x1000
            continue
            
        # Check if the memory region is committed and readable
        if (mbi.State & MEM_COMMIT and 
            mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE) and
            not (mbi.Protect & PAGE_GUARD)):
            
            memory_regions.append((base_address_int, mbi.RegionSize))
        
        # Move to the next memory region
        next_address = base_address_int + mbi.RegionSize
        if next_address <= base_address_int:  # Check for overflow
            break
            
        address = next_address
        
        # Break if we've wrapped around or exceeded reasonable address space
        if address > 0x7FFFFFFF:
            break
    
    debug_print(f"Found {len(memory_regions)} readable memory regions")
    
    # Prioritize regions in a specific address range
    priority_regions = [(addr, size) for addr, size in memory_regions if 0x02000000 <= addr <= 0x03000000]
    other_regions = [(addr, size) for addr, size in memory_regions if addr < 0x02000000 or addr > 0x03000000]
    
    sorted_regions = priority_regions + other_regions
    
    # Search for pattern in memory
    pattern_hits = []
    region_count = 0
    
    for base_address, region_size in sorted_regions:
        if not scanning:
            break
            
        region_count += 1
        if region_count % 10 == 0:
            debug_print(f"\rScanning region {region_count} of {len(sorted_regions)}...", end="", flush=True)
        
        # Skip very large regions (unlikely to be useful and slow to scan)
        if region_size > REGION_SIZE_LIMIT:
            continue
        
        # Read memory in chunks
        current_address = base_address
        end_address = base_address + region_size
        
        while current_address < end_address and scanning:
            bytes_to_read = min(CHUNK_SIZE, end_address - current_address)
            chunk_data = read_memory(process_handle, current_address, bytes_to_read)
            
            if not chunk_data:
                current_address += CHUNK_SIZE
                continue
            
            # Search for pattern
            matches = find_pattern_in_data(chunk_data, pattern)
            
            for offset, wildcard_values in matches:
                match_address = current_address + offset
                pattern_hits.append((match_address, wildcard_values))
            
            current_address += bytes_to_read
    
    debug_print(f"\nFound {len(pattern_hits)} occurrences of the pattern")
    return pattern_hits

def verify_structure(process_handle, address):
    """Verify if an address contains the expected structure by checking fields"""
    # Check for expected values at defined offsets
    field1 = read_int32(process_handle, address + FIELD_OFFSETS['Field1'])
    if field1 is None or field1 < 0 or field1 > 10000000:
        return None
    
    field2 = read_int32(process_handle, address + FIELD_OFFSETS['Field2'])
    if field2 is None or field2 < 0 or field2 > field1:
        return None
    
    field3 = read_int32(process_handle, address + FIELD_OFFSETS['Field3'])
    if field3 is None or field3 < 0 or field3 > 1000:
        return None
    
    field4 = read_int32(process_handle, address + FIELD_OFFSETS['Field4'])
    if field4 is None or field4 < 0 or field4 > 10:
        return None
    
    field5 = read_bool(process_handle, address + FIELD_OFFSETS['Field5'])
    if field5 is None:
        return None
    
    # If all checks pass, return the field values
    return {
        'Field1': field1,
        'Field2': field2,
        'Field3': field3,
        'Field4': field4,
        'Field5': field5
    }

def find_structures_in_process(pid):
    """Find memory structures in a process by pattern matching"""
    # Parse the pattern string
    pattern = parse_pattern(PATTERN_STRING)
    if not pattern:
        debug_print("Error parsing pattern. Please check the format.")
        return []
    
    debug_print(f"Using pattern: {' '.join(['??' if b is None else f'{b:02X}' for b in pattern])}")
    
    # Open the process
    process_handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 
        False, 
        pid
    )
    
    if not process_handle:
        raise RuntimeError(f"Failed to open process (PID: {pid}). Error code: {ctypes.get_last_error()}")
    
    try:
        debug_print(f"Scanning process with PID: {pid}")
        
        # Search for the pattern
        pattern_hits = search_for_pattern(process_handle, pattern)
        
        # Verify each hit
        instances = []
        for hit_address, wildcard_values in pattern_hits:
            if not scanning:
                break
                
            fields = verify_structure(process_handle, hit_address)
            if fields:
                # Create a formatted pattern string showing the actual values
                formatted_pattern = []
                for i, byte in enumerate(pattern):
                    if byte is None:  # Wildcard
                        wildcard_byte = wildcard_values.get(i, 0)
                        formatted_pattern.append(f"{wildcard_byte:02X}")
                    else:
                        formatted_pattern.append(f"{byte:02X}")
                
                instance_info = {
                    'address': hit_address,
                    'pattern': ' '.join(formatted_pattern),
                    'fields': fields
                }
                
                instances.append(instance_info)
                
                debug_print(f"\nFound structure instance at 0x{hit_address:X}")
                debug_print(f"  Pattern: {instance_info['pattern']}")
                for field_name, value in fields.items():
                    debug_print(f"  {field_name}: {value}")
                
                # Dump memory around the instance
                dump_memory(process_handle, hit_address, 128)
                
                # If we've found enough instances, stop the search
                if len(instances) >= MAX_INSTANCES:
                    break
        
        return instances
            
    finally:
        ctypes.windll.kernel32.CloseHandle(process_handle)

class ScanResult:
    def __init__(self):    
        self.address = None
        self.field1 = None
        self.field2 = None
        self.state = None
        self.time_consumed = 0

def analyze_process(pid):
    """Main function to scan a process and find matching structures"""
    start_time = time.time()
    result = ScanResult()
    
    try:
        # Find structures in the process
        instances = find_structures_in_process(pid)
        
        if not instances or len(instances) == 0:
            print("No matching structures found.")
            return result
        
        # Use the first instance if found
        instance = instances[0]
        result.address = instance['address']
        result.field1 = instance['fields']['Field1']
        result.field2 = instance['fields']['Field2']
        result.state = instance['fields']['Field4']
        
        print(f"Found {len(instances)} matching structures.")
        print(f"First match at address: 0x{result.address:X}")
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
    
    finally:
        result.time_consumed = time.time() - start_time
        print(f"Analysis completed in {result.time_consumed:.2f} seconds.")
    
    return result

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python memory_pattern_finder.py <PID>")
        sys.exit(1)
    
    try:
        pid = int(sys.argv[1])
        analyze_process(pid)
    except ValueError:
        print("Error: PID must be a valid integer")
        sys.exit(1)