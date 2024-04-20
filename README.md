# Threadless-Injection-with-EnumProc
Threadless Injection injects a trampoline at the start of the target function instead of stomping it with the entire payload. This trampoline will redirect the execution to the main shellcode injected in a Memory Hole (explained later in this module).
