#Developed for fun by Jonathan Berkeley - 2020
#https://opensource.org/licenses/MIT
#Shared under MIT license. I am not liable for any claims or damages. Read MIT license for more details.
#Please give credit if you use/repurpose this source :)

import sys
import os
import glob
import time
import subprocess
import ctypes
try:
    import psutil
except ModuleNotFoundError:
    print("Required package psutil was not found, attempting automatic install")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])

try: 
    import psutil
except ModuleNotFoundError:
    print("Required package 'psutil' could not be automatically installed. Install psutil and try again.")
    sys.exit(1)

#Change this string to the name of the process you wish to target ===============================================
target_process = ""
if target_process == "":
    print("You need to enter a process  name in the target process field within the python file")
    sys.exit(5)

#Change this string if you want a different logfile name
logfile = open("pyject.log", "a+")
def main():
    dlls = None
    logfile.writelines("\nNew session:\n");
    
    try:
        dlls = glob.glob("*.dll")
        if not dlls:
            raise Exception('\t(ERROR) No DLL(s) found to inject (Exitting)\n')
        for dll in dlls:
            logfile.write("\t(INFO) Preparing to load " + str(dll) + "\n")
    except Exception as ex:
        print(ex)
        logfile.write("\t" + str(ex));
        safe_exit(2)
    
    logfile.write("\t(INFO) Waiting for " + target_process + "\n")
    process_id = -1
    while process_id == -1:
        if os.name == "nt":
            _ = os.system("cls")
        else:
            _ = os.system("clear")
        print("Waiting for "+ target_process +" to start...")
        process_id = if_proc_running_get_id(target_process)
        time.sleep(1)
    time.sleep(5)
    
    logfile.write("\t(INFO) " + target_process + " found with process id: " + str(process_id) + "\n")
    print(target_process, "found with pid", process_id)
    
    if process_id != 0:
        for dll in dlls:
            logfile.write("\t(INFO) Attempted to inject " + dll + " into " + str(process_id) + "\n")
            #Critical zone
            try:
                if inject_into_process(os.path.abspath(dll), process_id):
                    print("Injection appears to have succeeded for " + dll)
                    logfile.write("\t(SUCCESS) Injection of " + dll + " into " + str(process_id) + " seems to have succeeded\n")
                else:
                    print("Injection appears to have failed for " + dll)
                    logfile.write("\t(ERROR) Injection of " + dll + " into " + str(process_id) + " seems to have failed\n")
            except Exception as ex:
                logfile.write("\t(ERROR) Failed to inject " + dll + " into " + str(process_id) + " (Exitting)\n")
                print(ex)
                safe_exit(3)

            time.sleep(2)
    else:
        logfile.write("\t(ERROR) Error getting " + target_process + " process id (Exitting)\n")
        safe_exit(4)
    
    safe_exit(0)

#Generalised this function for easier reuse
def if_proc_running_get_id(proc_str):
    proc_str += ".exe"
    for process in psutil.process_iter():
        try:
            if proc_str.lower() in process.name().lower():
                return process.pid
        except:
            pass
    return -1

def inject_into_process(dll_path, pid):
    k32 = ctypes.windll.kernel32
    long_pid = ctypes.c_ulong(pid)
    
    #Open process
    process_handle = k32.OpenProcess((0x000F0000 | 0x00100000 | 0xFFF), 0, pid)
    if not process_handle:
        logfile.write("\t(ERROR) Getting process handle\n")
        return False
    
    #Find load library
    encoded_dll_path = dll_path.encode("ascii")
    req_write_size = len(encoded_dll_path)
    kernel_module_handle = k32.GetModuleHandleA("kernel32.dll".encode("ascii"))
    if not kernel_module_handle:
        logfile.write("\t(ERROR) Getting kernel module\n")
        return False
    load_lib = k32.GetProcAddress(kernel_module_handle, "LoadLibraryA".encode("ascii"))
    if not load_lib:
        logfile.write("\t(ERROR) Getting LoadLibraryA address\n")
        return False
    
    #Virtual allocation
    dll_address = ctypes.c_long(0)
    virt_alloc = k32.VirtualAllocEx(process_handle, None, ctypes.c_int(req_write_size), 0x00001000, 0x40)
    if not virt_alloc:
        logfile.write("\t(ERROR) Virtual allocation failed\n")
        return False
    
    #Write to process memory
    write_proc = k32.WriteProcessMemory(process_handle, virt_alloc, encoded_dll_path, req_write_size, None)
    if not write_proc:
        logfile.write("\t(ERROR) Writing to process memory failed\n")
        return False
    
    #Create remote thread in process
    new_thread = k32.CreateRemoteThread(process_handle, None, None, ctypes.c_long(load_lib), ctypes.c_long(virt_alloc), None, None)
    if new_thread:
        return True

def safe_exit(code):
    logfile.close()
    sys.exit(code)

if __name__ == "__main__":
    main()
