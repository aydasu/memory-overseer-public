import ctypes
from ctypes import wintypes
import re

# ====== CONFIGURATION ======
# Window title pattern (regex)
WINDOW_TITLE_PATTERN = r"Example"
# ====== END CONFIGURATION ======

def enum_windows_callback(hwnd, windows_list):
    """Callback for EnumWindows - collects window information"""
    # Skip windows with no title or that are invisible
    if not ctypes.windll.user32.IsWindowVisible(hwnd):
        return True
    
    length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
    if length == 0:
        return True
    
    # Get window title
    buffer = ctypes.create_unicode_buffer(length + 1)
    ctypes.windll.user32.GetWindowTextW(hwnd, buffer, length + 1)
    title = buffer.value
    
    # Get process ID
    pid = wintypes.DWORD()
    ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    
    # Add to our list
    windows_list.append((hwnd, title, pid.value))
    return True

def find_windows_by_pattern(pattern):
    """Find windows matching the title pattern"""
    windows_list = []
    
    # Setup callback function
    EnumWindowsProc = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        wintypes.HWND,
        ctypes.py_object
    )
    
    # Enumerate all windows
    ctypes.windll.user32.EnumWindows(
        EnumWindowsProc(enum_windows_callback), 
        ctypes.py_object(windows_list)
    )
    
    # Filter by pattern
    pattern_re = re.compile(pattern, re.IGNORECASE)
    return [(hwnd, title, pid) for hwnd, title, pid in windows_list 
            if pattern_re.search(title)]

def main():
    """Find windows matching the pattern and display information"""
    print(f"Searching for windows matching: {WINDOW_TITLE_PATTERN}")
    
    # Find matching windows
    matching_windows = find_windows_by_pattern(WINDOW_TITLE_PATTERN)
    
    # Display results
    if not matching_windows:
        print("No matching windows found.")
        return
    
    print(f"Found {len(matching_windows)} matching windows:")
    for i, (hwnd, title, pid) in enumerate(matching_windows):
        print(f"{i+1}. HWND: 0x{hwnd:X}, PID: {pid}, Title: '{title}'")

if __name__ == "__main__":
    main()