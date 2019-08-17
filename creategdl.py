import idaapi
import idc
import os


idaapi.autoWait()
# Optionally, run `symchk  /s srv*c:\symbols*https://msdl.microsoft.com/download/symbols c:\windows\system32\*.dll` to download all symbols to local cache
os.environ['_NT_SYMBOL_PATH'] = 'C:\\symbols'
idaapi.load_and_run_plugin("pdb", 3)
idc.gen_simple_call_chart("out.gdl", "gdl", 0x1000)
idc.Exit(0)
