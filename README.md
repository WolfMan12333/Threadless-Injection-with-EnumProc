# Threadless-Injection-with-EnumProc
Threadless Injection injects a trampoline at the start of the target function instead of stomping it with the entire payload. This trampoline will redirect the execution to the main shellcode injected in a Memory Hole.
It also prepends a fixed shellcode to the start of the main shellcode. The fixed shellcode is responsible for removing the trampoline from the target function, restoring the original bytes, and passing the execution back to the target function when the main shellcode completes execution. This means that the hooked function will get executed with its original parameters when the main payload is executed.
And It has added Process Enumeartion function to not putting hardcoded PID of the process.
