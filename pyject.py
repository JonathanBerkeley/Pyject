# Developed for fun - 2020

import sys
import os
import glob
import time
import subprocess
import ctypes
from ctypes import wintypes

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

# Change this string to the name of the process you wish to target ===============================================
target_process = ""
if target_process == "":
    print("You need to enter a process name in the target_process field within the python file")
    sys.exit(5)

# Logfile logs details about each session
logfile = open("pyject.log", "a+")


def main():
    if os.name != "nt":
        print("Script targets Windows operating systems only. (Exiting)")
        sys.exit(0)

    dlls = None
    logfile.writelines("\nNew session:\n")

    try:
        dlls = glob.glob("*.dll")
        if not dlls:
            raise Exception('\t(ERROR) No DLL(s) found to inject (Exiting)\n')
        for dll in dlls:
            logfile.write("\t(INFO) Preparing to load " + str(dll) + "\n")
    except Exception as ex:
        print(ex)
        logfile.write(str(ex))
        safe_exit(2)

    logfile.write("\t(INFO) Waiting for " + target_process + "\n")
    process_id = -1
    while process_id == -1:
        _ = os.system("cls")
        print("Waiting for ", target_process, " to start...")
        process_id = if_proc_running_get_id(target_process)
        time.sleep(1)

    # Sleep to allow target program time to load
    time.sleep(3)

    logfile.write("\t(INFO) " + target_process + " found with process id: " + str(process_id) + "\n")
    print(target_process, "found with pid", process_id)

    if process_id != 0:
        for dll in dlls:
            logfile.write("\t(INFO) Attempted to inject " + dll + " into " + str(process_id) + "\n")
            # Critical zone
            try:
                if inject_into_process(os.path.abspath(dll), process_id):
                    print("Injection appears to have succeeded for ", dll)
                    logfile.write(
                        "\t(SUCCESS) Injection of " + dll + " into " + str(process_id) + " seems to have succeeded\n")
                else:
                    print("Injection appears to have failed for ", dll)
                    logfile.write(
                        "\t(ERROR) Injection of " + dll + " into " + str(process_id) + " seems to have failed\n")
            except Exception as ex:
                print(ex)
                logfile.write("\t(ERROR) Failed to inject " + dll + " into " + str(process_id) + " (Exiting)\n")
                safe_exit(3)

            time.sleep(2)
    else:
        logfile.write("\t(ERROR) Error getting " + target_process + " process id (Exiting)\n")
        safe_exit(4)

    safe_exit(0)


# Generalised this function for easier reuse
def if_proc_running_get_id(proc_str):
    proc_str += ".exe"
    for process in psutil.process_iter():
        if proc_str.lower() in process.name().lower():
            return process.pid
    return -1


def inject_into_process(dll_path, pid):
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)

    # Following section sets the arguments and return types for various kernel32 functions
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE

    k32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
    k32.GetModuleHandleA.restype = wintypes.HMODULE

    k32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
    k32.GetProcAddress.restype = wintypes.LPVOID

    k32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    k32.VirtualAllocEx.restype = wintypes.LPVOID

    k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t,
                                       ctypes.c_size_t]

    k32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID,
                                       wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD]

    # Open process
    process_handle = k32.OpenProcess(2035711, False, pid)
    if not process_handle:
        print("Getting process handle failed")
        logfile.write("\t(ERROR) Getting process handle (Error code: {0})\n".format(ctypes.get_last_error()))
        return False

    # Obtain handle to kernel32 module in memory
    encoded_dll_path = dll_path.encode("ascii")
    req_write_size = len(encoded_dll_path) + 1
    kernel_module_handle = k32.GetModuleHandleA("kernel32.dll".encode("ascii"))
    if not kernel_module_handle:
        print("Getting kernel module handle failed")
        logfile.write("\t(ERROR) Getting kernel module (Error code: {0})\n".format(ctypes.get_last_error()))
        return False

    # Find load library
    load_lib = k32.GetProcAddress(kernel_module_handle, "LoadLibraryA".encode("ascii"))
    if not load_lib:
        print("Getting LoadLibraryA address failed")
        logfile.write("\t(ERROR) Getting LoadLibraryA address (Error code: {0})\n".format(ctypes.get_last_error()))
        return False

    # Virtual allocation
    virt_alloc = k32.VirtualAllocEx(process_handle, None, req_write_size, 0x00001000, 0x40)
    if not virt_alloc:
        print("Virtual allocation failed")
        logfile.write("\t(ERROR) Virtual allocation failed (Error code: {0})\n".format(ctypes.get_last_error()))
        return False

    # Write to process memory
    write_proc = k32.WriteProcessMemory(process_handle, virt_alloc, encoded_dll_path, req_write_size, 0)
    if not write_proc:
        print("Writing to process memory failed")
        logfile.write("\t(ERROR) Writing to process memory failed (Error code: {0})\n".format(ctypes.get_last_error()))
        return False

    # Create remote thread in process
    return k32.CreateRemoteThread(process_handle, None, 0, k32.LoadLibraryA, virt_alloc,
                                  0, None)


def safe_exit(code):
    logfile.close()
    sys.exit(code)


if __name__ == "__main__":
    main()
