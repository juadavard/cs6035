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


----------

459
tcp.stream eq 459 or ftp or ftp-data or (http and ip.src == 10.0.0.7 )

DCC SEND file_2600.guess.txt 199 0 955 191.
DCC SEND file_2600.guess.txt 167772164 61610 955 191.

Conversation
tcp.stream eq 459 or ftp or ftp-data or (tcp and tcp.dstport ==61610 ) 

----------

Transmission of Code 1
tcp.stream eq 2617
tcp.stream eq 459 or tcp.stream eq 2617
20.109.1.166
197181	5289.970110	20.109.1.166	10.0.0.7	HTTP	1388	HTTP/1.1 200 OK  (text/html)


-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v2.1.15
Comment: https://keybase.io/crypto

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
MIciZTnxZA/o8dPNhEKApSxElS+GJA==
=C7zZ
-----END PGP PRIVATE KEY BLOCK-----

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

==== You found Flag 2! ====
Enter your GTID: 904203773

Your hash is:  2997c303034c112bb92cdefe60e078197c6046492762c13378a35a69eeaf347965b8ebea0a94230f6391992af4db4459d842403cece9b38dcfa35ecac6c5c884


--------

Some type of hash
tcp.stream eq 3408
+.
......\i..........................F.....^.R.I.t.R...t.R...t.R...t.R...t.].R.8X..d
....].!.4.........R.#.R.#.)......Nc.....................j.....V.P...................4.......p.\.........P...................!.V.4.......P...................4.......#.).N)...encode..hashlib..sha256.	hexdigest)...input_value.
encoded_inputs....& ..flag4.py.
obscure_inputr........s(..........&..&..(.M....>.>.-..(..2..2..4..4.....c.....................N.....R.p.\.........P...................!.V.4.......P...................4.......#.).s...._CS6035-FlaG_-Nova).r....r....r....)..
secret_keys.... r
.....obscure_constantr........s........&.J....>.>.*..%../../..1..1r....c...........................R.P...................\.........\.........V.4.......4.........U.u...u.F ..q"^.,...........^.8X..d	....W.,...........M.W.,...........N.K"..	...u.p.4.......#.u...u.p.i.)...)...join..range..len)...hash1..hash2..is....&& r
.....combine_hashesr........s?.......
.7.7.%...E.
.BS..T.BS.Q.A.....
.E.H......8.BS..T..U..U...Ts.....&A..c...........................\.........R.4.........\.........R.4.......P...................4.......p.V.'.......g.....\.........R.4.........R.#.\.........V.4.......p.\	........4.......p.\.........W.4.......p.\.........R.V.4.........R.#.).z.==== You found Flag 4! ====z.Enter your GTID : z.Error: GTID cannot be empty.Nz.Combined hash   :  )...print..input..stripr....r....r....)...u_input.
first_hash..second_hash..combineds....    r
.....mainr!.......s[.......	.
'..(.......(..)../../..1.G.....
..,..-.........w..'.J.."..$.K....j..6.H....
.
.....*r......__main__).r....r....r....r....r!.....__name__..r....r
.....<module>r%.......s3.................5....2....V.....+.$....z.......F.....r....

------

frame.time >= "Jan 6, 2026 21:37:00" &&
frame.time <= "Jan 6, 2026 21:48:00" and http

197177	5289.969361	10.0.0.7	20.109.1.166	HTTP	588	GET / HTTP/1.1 
http://www.necrocryptors.com/

2997c303034c112bb92cdefe60e078197c6046492762c13378a35a69eeaf347998636436cb8ce57c7432cef6469ed245532438f98af559ede98727a5ce194c70

---
frame.time >= "Jan 6, 2026 21:37:00" &&
frame.time <= "Jan 6, 2026 21:48:00" and dns and dns.qry.name contains "necro"

196516	5286.968418	168.63.129.16	10.0.0.7	DNS	97	Standard query response 0x5e19 A www.necrocryptors.com A 20.109.1.166

196514	5286.961511	168.63.129.16	10.0.0.7	DNS	171	Standard query response 0xe541 HTTPS www.necrocryptors.com SOA ns-cloud-e1.googledomains.com

----
1.5
227614	5737.247920	64.86.243.186	10.0.0.7	IRC	151	Response (@time=2026-01-06T21:51:29.834Z)
@time=2026-01-06T21:51:29.834Z :ByteRunner!~SolarFlar@52.166.115.95 PRIVMSG MestreDosMagos :hey


---

tcp.port == 54658
tcp.stream eq 675

howdy
whats up man
ok you know the drill. confirm you are really hackpt
Bc6e547fa5333adf8709439a92a484d9
thats not right
ugh forgot to generate the new one
1 sec
NzkgNmYgNzUgMjAgNjYgNmYgNzUgNmUgNjQgMjAgNzQgNjggNjUgMjAgNjYgNmMgNjEgNj
nop
NzkgNmYgNzUgMjAgNjYgNmYgNzUgNmUgNjQgMjAgNzQgNjggNjUgMjAgNjYgNmMgNjEgNjc
got it npw
*now
ok back to the convo?


~/john/run/john --mask=?d?d?d?d?d?d?d zip_hash.txt
0901009          (password_protected.zip/script.py)     
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size [KiB]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0901009          (password_protected.zip/script.py)     
1g 0:00:00:51 DONE (2026-05-28 16:56) 0.01926g/s 79206p/s 79206c/s 79206C/s 2709109..3632009
Use the "--show" option to display all of the cracked passwords reliably
Session completed
testbed@testbed:~/MITM$ ~/john/run/john --mask=?d?d?d?d?d?d?d zip_hash.txt --show


 cat script.py 
aW1wb3J0IGhhc2hsaWINCg0KDQpkZWYgZ2VuZXJhdGVfaGFzaChndGlkKToNCiAgICAjIEdlbmVyYXRlcyBhIGNvbWJpbmVkIFNIQS0yNTYgaGFzaCBiYXNlZCBvbiBHVElEIGFuZCBhIHNlY3JldCBzdHJpbmcNCiAgICBndGlkX2hhc2ggPSBoYXNobGliLnNoYTI1NihndGlkLmVuY29kZSgpKS5oZXhkaWdlc3QoKQ0KICAgIHNlY3JldF9oYXNoID0gaGFzaGxpYi5zaGEyNTYoYiJDUzYwMzUtU1AyMDI2LUJZNSIpLmhleGRpZ2VzdCgpDQogICAgcmV0dXJuIGd0aWRfaGFzaCArIHNlY3JldF9oYXNoDQoNCg0KZGVmIG1haW4oKToNCiAgICBwcmludCgiPT09PSBZb3UgZm91bmQgRmxhZyA1LjMhID09PT0iKQ0KICAgIGd0aWQgPSBpbnB1dCgiRW50ZXIgeW91ciBHVElEOiAiKS5zdHJpcCgpDQogICAgaWYgbm90IGd0aWQ6DQogICAgICAgIHByaW50KCJFcnJvcjogR1RJRCBjYW5ub3QgYmUgZW1wdHkuIFBsZWFzZSB0cnkgYWdhaW4uIikNCiAgICAgICAgcmV0dXJuDQogICAgZmluYWxfaGFzaCA9IGdlbmVyYXRlX2hhc2goZ3RpZCkNCiAgICBwcmludCgiWW91ciBoYXNoIGlzOiIsIGZpbmFsX2hhc2gpDQoNCg0KaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoNCiAgICBtYWluKCkNCg==testbed@testbed:~/MITM/output$ python
Command 'python' not found, did you mean:

base64 -d script.py > decoded.py

testbed@testbed:~/MITM/output$ cat decoded.py 
import hashlib


def generate_hash(gtid):
    # Generates a combined SHA-256 hash based on GTID and a secret string
    gtid_hash = hashlib.sha256(gtid.encode()).hexdigest()
    secret_hash = hashlib.sha256(b"CS6035-SP2026-BY5").hexdigest()
    return gtid_hash + secret_hash


def main():
    print("==== You found Flag 5.3! ====")
    gtid = input("Enter your GTID: ").strip()
    if not gtid:
        print("Error: GTID cannot be empty. Please try again.")
        return
    final_hash = generate_hash(gtid)
    print("Your hash is:", final_hash)


if __name__ == "__main__":
    main()


----
ftp or ftp-data
251535	6520.310133	10.0.0.7	10.0.0.6	FTP	67	Request: USER 

// Ftp ip address 10.0.0.6
251537	6520.310495	10.0.0.6	10.0.0.7	FTP	88	Response: 331 Please specify the password.

251768	6527.457365	10.0.0.7	10.0.0.6	FTP	82	Request: PASS X9f$3jR9wL6!zQ1U32145

252343	6540.579694	10.0.0.7	10.0.0.6	FTP	73	Request: RETR file_5324.bn

+.
......\i..........................F.....^.R.I.t.R...t.R...t.R...t.R...t.].R.8X..d
....].!.4.........R.#.R.#.)......Nc.....................j.....V.P...................4.......p.\.........P...................!.V.4.......P...................4.......#.).N)...encode..hashlib..sha256.	hexdigest)...input_value.
encoded_inputs....& ..flag4.py.
obscure_inputr........s(..........&..&..(.M....>.>.-..(..2..2..4..4.....c.....................N.....R.p.\.........P...................!.V.4.......P...................4.......#.).s...._CS6035-FlaG_-Nova).r....r....r....)..
secret_keys.... r
.....obscure_constantr........s........&.J....>.>.*..%../../..1..1r....c...........................R.P...................\.........\.........V.4.......4.........U.u...u.F ..q"^.,...........^.8X..d	....W.,...........M.W.,...........N.K"..	...u.p.4.......#.u...u.p.i.)...)...join..range..len)...hash1..hash2..is....&& r
.....combine_hashesr........s?.......
.7.7.%...E.
.BS..T.BS.Q.A.....
.E.H......8.BS..T..U..U...Ts.....&A..c...........................\.........R.4.........\.........R.4.......P...................4.......p.V.'.......g.....\.........R.4.........R.#.\.........V.4.......p.\	........4.......p.\.........W.4.......p.\.........R.V.4.........R.#.).z.==== You found Flag 4! ====z.Enter your GTID : z.Error: GTID cannot be empty.Nz.Combined hash   :  )...print..input..stripr....r....r....)...u_input.
first_hash..second_hash..combineds....    r
.....mainr!.......s[.......	.
'..(.......(..)../../..1.G.....
..,..-.........w..'.J.."..$.K....j..6.H....
.
.....*r......__main__).r....r....r....r....r!.....__name__..r....r
.....<module>r%.......s3.................5....2....V.....+.$....z.......F.....r....




+
��\i���F�^RItRtRtRtRt]R8Xd
]!4R#R#)�Nc�j�VP4p\P!V4P4

This is bytecode for python 3.14.5


==== You found Flag 4! ====
Enter your GTID : 904203773
Combined hash   :   2f98cd0902421c2abb23d2ff65e47a1e7f67484a206ac73e78a95e64e3a3387a


-------



BoobyTables
| project SrcPublicIps, BytesSrcToDest
| summarize  Talker = sum(BytesSrcToDest ) by SrcPublicIps
| order by Talker


BoobyTables
| where DestPort in (80,443)
| summarize Port = make_set(DestPort) by SrcPublicIps


192.168.1.10 X
10.0.0.99
52.136.4.16|1|1|1|1|128|60
40.87.182.8|1|1|1|1|128|60

172.171.247.132|0|1|5|5|570|665
91.196.152.1|1|1|2|1|218|74

BoobyTables
| where SrcPublicIps == "10.0.0.99"
| project packet_data, SrcPublicIps




import hashlib

def obscure_input(input_value):
    encoded_input = input_value.encode()
    return hashlib.sha256(encoded_input).hexdigest()

def obscure_constant():
    secret_key = b"_CS6035-Kust0-Qu3rYL33t"
    return hashlib.sha256(secret_key).hexdigest()

def main():
    print("==== You found Flag 7! ====")
    
    # Input prompt for GTID
    u_input = input("Enter your GTID : ").strip()

    if not u_input:
        print("Error: GTID cannot be empty.")
        return

    # Obfuscated hash generation
    first_hash = obscure_input(u_input)
    second_hash = obscure_constant()
    
    # Concatenating the hashes directly
    combined = first_hash + second_hash

    # Displaying the final combined hash
    print("Combined hash   :  ", combined)

if __name__ == "__main__":
    main()

==== You found Flag 7! ====
Enter your GTID : 904203773
Combined hash   :   2997c303034c112bb92cdefe60e078197c6046492762c13378a35a69eeaf3479f2ac2d53d234f75ffd43b641e7fba4d15974dfe54c694ed26d4279e6eafb48a6
