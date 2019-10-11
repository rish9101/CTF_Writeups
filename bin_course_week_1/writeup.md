# WRITEUP FOR HITCON-2014 PWN CHALLENGE stkof


## Vulnerability

This was a binary with heap overflow vulnerability and an unlink vulnerability(it was running with libc 2.23 so no T-Cache).

## Exploit

Before going to the exploit we look at the functionality of the binary. The binary asks for an option and works accordingly.
Option 1 - Mallocs a chunk and stores the pointer in a global array.
Option 2 - Edits the chunk at given index of the global array. This is where the heap overflow is asks the user for the size of content, making no check if it is greater than chunk size.
Option 3 - Deletes the Chunk. It basically frees the chunk at the specified index in array and zeroes out the pointer at that array location.
Option 4 - It basically asks for an array index. Then calculates its content's length using STRLEN and then outputs "TODO" or "..."


First I allocated 5 chunks on the heap. Then I edit **3rd chunk** and overflow **chunk 4's headers** such that chunk 3 is unlinked when chunk 4 is freed. The forward and backward pointer set up in chunk 3 point to some address in the global array(namely 0x602140). Now since this address points to the global array. Thus after unlink we have a write access into the global array. So now whenever I edit *chunk2* I am actually editing the values in the global array.

Now I edit *chunk 2* to write `strlen@got` at chunk 1's index in global array. So when I edit chunk 1 I am actually editing chunk 2. Then I edit *chunk 1* to write `puts@plt` at `strlen@got`. Then I again edit *chunk 2* to write  `puts@got` address(we want to leak a libc address) at chunk 1's index. Then I call option 4 on *chunk 1* to get the libc address of puts. 

Now to call "/bin/sh". I follow the same procedure and write `atoi@got` at chunk 1's index(as atoi takes user input so we don't have to write /bin/sh into memory). Then I edit *chunk 1* to write system's address at `atoi@got`. Next I simply send /bin/sh as an argument and shell is spawned. :)
