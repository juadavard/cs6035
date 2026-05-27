IRC
HTTP
DNS
FTP, SCP, or HTTP file transfers.

Identify the file downloaded / files 
servers,... lots of filters
1 - 4

Task 5 Cracking password

6 ICMP analysis script python

Start doing 5 and let running jhon the ripper
Do 1 - 4, read documentation on wireshark and make a plan to analysis
and maybe mark by actions / status
there are multiple stages in the conversation mark them


ftp or irc and ( irc.response.command != "PONG" and irc.request.command != "PONG" and irc.request.command != "PING" and  irc.response.command != "PING" )


ftp or (irc and !(irc.request.command == "PING" or irc.request.command == "PONG"))

ftp or ftp-data or (irc and !(irc.request.command == "PING" or irc.request.command == "PONG" or irc.response.command == "PING" or irc.response.command == "PONG"))

this one works
ftp or ftp-data or (irc and !(irc.request.command == "PING" or irc.request.command == "PONG" or irc.response.command == "PING" or irc.response.command == "PONG" or irc.response.trailer contains "PONG"))

Current working one
ftp or ftp-data or (irc and !(irc.request.command == "PING" or irc.request.command == "PONG" or irc.response.command == "PING" or irc.response.command == "PONG" or irc.response.trailer contains "PONG"))




459
tcp.stream eq 459 or ftp or ftp-data or (http and ip.src == 10.0.0.7 )

DCC SEND file_2600.guess.txt 199 0 955 191.
DCC SEND file_2600.guess.txt 167772164 61610 955 191.

tcp.stream eq 459 or ftp or ftp-data or (tcp and tcp.dstport ==61610 ) 


tcp.stream eq 2617


-----BEGIN PGP MESSAGE-----
Version: Keybase OpenPGP v2.1.15
Comment: https://keybase.io/crypto

wYwDkfkgL4rwQiUBA/93N5CdLm5pb5+XSxKxgpjkOgLkLLucJFWzB9mUDAzNp3OX
o1ZHarirFN/HH/HZWZ0Lm2ArN6ayxb7aUwXymhjrH8bi5VxH40lj7q/3Remek5HS
010oC3S6ZWyblw5vozqAu2ATFMONdxpPFcKUVGcBwFP1LCpmQE0rO+Ohsl0+wdLB
AQHhXbtPIzmCLuzPBTs0nIFVyg2oiOHUm2ISlLSlDcwgzuTgNfOLxr6NuUsAv+v0
xgZCez7lIAA9921abe+d9FIVxi3BwEfwffJ14yWzkTXy4ClwmYIhOd59gmwRjtwk
GhehdsAxgwB7reZCKeDwMW5ZF3aVnW3QQaqWbKeuBQCfDUlZy6RL89K5fiqsVLVP
qmFTiZl/xhpUfR13NKIQJcX03ESM1CcYydedKhM0qhEjb1yjBdvKo1L/1jzp6qVe
I8uke5P0SE9dsGY9XLD+1gSiJD2f6voRykp6ZS8F1j0GewLrOdtQZ9PxQ9Yxg7Tr
EZfdrHunY9DTbmXPy4bk+O1CzjzSsCwbMAa7itq68ekkH3vnkkLAH7ELlKPhzpOC
KgeQXVsCTd30kzrTRbBYcDoVw3hRBbDl+5Cz/YgqFhMGa5gg39cOaYbSRcvzQ+1t
jNGg9Qwjn66cmFoaQr7VEdQRhC1QKeXZHzB4+lJygD1l7AM4ntpZFMgf8w5hdTZB
qMWpgRZs7F6QwZjkq0oPWXm2UtdXP0Qz4JrCJH2OmMIJiMsEu8NMYpoROhD/0R1X
Ek2dXjBt7EUcmDCd+zm0LRWl
=EFcJ
-----END PGP MESSAGE-----
sf....

(tcp or udp) and ip.addr != 168.63.129.16 and ip.addr != 169.254.169.254



