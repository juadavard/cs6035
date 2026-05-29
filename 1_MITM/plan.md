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