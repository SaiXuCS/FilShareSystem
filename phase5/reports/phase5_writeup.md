# Trust Model
* Group Server The group server is mostly trustworthy. It will only issue tokens to properly authenticated clients and will properly enforce the constraints on group creation, deletion,
and management specied in previous phases of the project. However, the group server is not securely protected, in this phase, it can be compromised and thus leaking user secrets.
* File Servers In this phase of the project, le servers will be assumed to be largely untrusted. In particular, le servers might leak les to unauthorized users or attempt to steal user tokens.
* Client We will assume that clients are not trustworthy. Specically, clients may attempt to obtain tokens that belong to other users and/or modify the tokens issued to them by the group server to acquire additional permissions.
* Other Principals  All communications in the system might be intercepted by a active attacker that can insert, reorder, replay, or modify messages.

# Threats to Protect Against
## Secrets Leakage  
Since the group server is not securely protected, it may be compromised and secrets may be leaked from the group server to unauthorized attackers. There should be mechanism for ensuring that secrets leaked from the group server will not cause any further problems. The proposed mechanism will also ensure same level of security as in previous phases.

## User Impersonation
Since group server may leak the secrets to unauthorized Principals, they may utilize the stolen secrets and try to connect with the group server pretending they are legit users. There must be a mechanism to authenticate user with the assumption that secrets stored in the group server may appear public to attackers.

## Server impersonation
Since group server leaks the secrets to unauthorized Principals, there is also possibility that these attacker pretends to be the authentic server that user wants to connect. There must be a mechanism to make sure the server's identity; namely user shall be able to detect bogus servers and reject connection.

## Attacker Analysis:
any malicious attacker may try to write program that steal secrets stored inside the group server. Most attack programs we assume server one purpose: attacker the server, and copy all the secrets within the server into their machine. The secrets will be public to them. This attack will make our system entirely unsafe because anyone stealing the secreting can impersonate legit users or servers. Our current authentication process uses Diffie Hellman key agreement.

Login phase:  g, p are stored in client app and group server

User calculate W = h(password), pick a random a

U-->G: username, request for exchange DH key, iv, {g^a mod p} W

Group Server retrieve W = h(password) using username, decrypt with W and iv, get g^a mod p.

Group Server pick a random b

G-->U: {g^b mod p}W

Both user and group server calculate K =  g^ab mod p

User pick a random number n as challenge

U-->G: {n}K

G-->U: n

In above case, if the shared secrets are leaked. Then attacker can brute force the password of a specific user, calculate the secret and compare with the leaked secret in an offline mode. If the attacker has no target, he can initialize an offline codebook attack, which will be much easier because our shared secrets do not contain salt. When the collision is found, the attacker can login using the username and the password without any issue. To brute force a 128-bit MD5 secret is not so hard; thus, anyone that have access to the secrets can impersonate any user in the group server. On the other hand, if user wants to connect to the group server, attackers can utilize the knowledge of secrets to decrypt the DH key, and complete the DH exchange. The user will believe that he is connecting to the true server because only the server shares the secret. Attackers then might make malicious moves by pretending to be the server.

## Countermeasure:
To prevent group server from compromised, a better way is to keep secrets secure even if information is leaked. During authentication, group server needs to verify that user truly knows the secret, not anyone stealing the secrets and pretending to be him. User needs to verify that the server he is connection with is the authentic server, not anyone having the secrets pretends to be the server. We use an Secure remote protocol to authenticate the user followed by a public key authentication to authenticate the server. The secure remote protocol is SRP6 from BouncyCastle, in which the hash function is SHA256. The SRP protocol will make sure user cannot be impersonated even if the secrets are stolen from the group server. The problem with SRP lies in the possibility of server impersonation because server do not need to have the knowledge of secrets. When the group server is compromised, attacker can get g^w mod p, and then attacker can pretend to be the group server to communicate with client without decipher g^w mod p to get W since the symmetric key between client and group server can be directly derived from g^w mod p. Therefore, a public key authentication is followed to make sure the server is authentic. The mechanism is to use RSA and signature to send challenge so that client knows that he is talking with real group server. In general, the login process is divided into two parts: 1) SRP for authenticating user 2) Public Key for authenticating server

### Algorithm:
Set up Phase:
User pick an administrator username, password. P and g are pre-stored in group server.
Group server calculate w = h(password), store<username, g^w mod p>

Login Phase (Part 1 SRP):

P and G are pre-stored in client program

User enter username u, password pass, pick a random BigInteger b

U-->G:	g^b mod p

G pick a random BigInteger s, a 32-bit u

G-->U: g^s+g^w mod p, u

Both user calculate symmetric K = g^s(b+uw)

User pick a random number challenge C1, group server pick a random number challenge C2

U-->G: {C1}K

G-->U: C1,{C2}K

U-->G: C2

(Part2 Public Key)

U encrypt the challenge using group public key,and send it to group server

U->G: {challenge}K-1g

G: group server decrypt it to get challenge, and send signed encrypted challenge back to client

G->U: {{challenge}K}Kg

U: client decrypt this message and compare the challenge with the challenge he sent before


Create New User:

U choose a username, password

U-->G: {name, password}K, HMAC

G decrypt message, calculate W, store <username, g^w mod p>



### Analysis:
* The first process is to authenticate user. By using SRP protocol, no secrets are directly stored inside the group server. If the server is compromised, only g^w mod p is known, attacker cannot get w, because the assumption that brute force the exponent of modular is difficult. The symmetric key will be g^ s(b + uW) mod p. Knowing g^w mod p from user side will not help figuring out the key; in fact, user has to know w to calculate the symmetric key, which requires users to know the exact password. Using SRP, we can make sure that even if the secrets are compromised, no one can impersonate user. However, since serve does not need to know w to calculate symmetric key, it is possible that the attacker can pretend to be the server. The second process described in next paragraph will handle this issue. Besides the impersonation problem, if any modification happens during the communication, the challenge exchange will detect that, which will make sure both server and client establish the same symmetric key. Since the protocol uses Diffie hellman, it can prevent replay attack by choosing fresh key and challenge each time.

* After client calculate the symmetric key K. He should send a challenge, which is encrypted by the public key of group server. And only the real group server can encrypt this message to get challenge. Then group server encrypted this challenge using group symmetric key and sign it using group server’s private key. After client receive this signed encrypted challenge, he needs decrypt it and compare challenge with the challenge he sent before. Since this challenge exchange using public key happens only after the user authentication has been completed, and the attacker cannot impersonate legit users to pass the authentication, the attacker cannot perform as a man-in-the-middle that asks server to sign the challenge for him. Therefore, at this point, we know that the server is the true server we want to connect with.
