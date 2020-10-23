# pyject.py - A process injector that supports multiple DLLs
Windows multiple DLL injector in python

You must include the DLLs you wish to inject in the same directory. It will attempt to inject all DLLs that are in the same directory as itself.

You will need to fill in the target process inside the code (shown below). It is marked near the top of the file with a comment
target_process = ""

Requires 'psutil'. Will automatically attempt to install this on first run. If it fails you will need to manually download this package.
