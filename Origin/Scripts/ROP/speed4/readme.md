Leaks stack values.
so we get canary, base addr or binary, addr of user input
there is execve() in plt, call it with proper args
no gadget to set rdx to 0, used printf to do that and then other registers to call execve(binsh,0,0).
