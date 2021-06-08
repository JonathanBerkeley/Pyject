# pyject.py - A process injector that supports multiple DLLs
Windows DLL injector made in python 3.

Include the DLLs you wish to inject in the same directory.

It will attempt to inject all DLLs that are in the same directory as itself.
     
#### You will need to fill in the name of the process you wish to target inside the code (shown below). It is marked near the top of the file with a comment
- target_process = ""

#### Dependencies:
- Requires 'psutil'. Will automatically attempt to install this on first run. If it fails, you will need to manually install psutil.

