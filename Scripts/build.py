import argparse
import os
import subprocess
import glob
import pefile

# Constants
BLACKOUT_END: bytes = b'BLACK-END'
PAGE_SIZE: int = 0x1000

def generate_shellcode_header(bin_path, output_path, section):
    """Generates a C header file with shellcode and its size."""
    attribute = f"__attribute__(( section(\".{section}\") ))" if section else ""
    
    with open(bin_path, 'rb') as bin_file, open(output_path, 'w') as c_file:
        data = bin_file.read()
        c_file.write(f'{attribute} unsigned char BlackoutBytes[] = {{\n')

        for i in range(0, len(data), 12):
            line = ', '.join(f'0x{byte:02X}' for byte in data[i:i + 12])
            c_file.write(f'    {line},\n')

        c_file.write(f'}};\n\nunsigned int BlackoutSize = {len(data)};\n')
    
    print(f'Generated shellcode header in {output_path}.')
