# Model Analysis

For key agreement, the algorithm we use is Diffie Hellman and public key crypto, provided by bouncy castle. For hashing, we use MD5 for generating weak secret, and sha256 for signing tokens. For symmetric encryption, we use AES with 128 bit key length from bouncy castle. To encrypt token and objects, we use the SealedObject java class along with Envelope

## T1 Unauthorized Token Issuance 
Due to the fact that clients are untrusted, we
must protect against the threat of illegitimate clients requesting tokens from the group
server. Your implementation must ensure that all clients are authenticated in a secure
manner prior to issuing them tokens. That is, we want to ensure that Alice cannot
request and receive Bob's security token from the group server.

Thread analysis:In the current system, user login is not protected with authentication, which means any user is able to login with a valid username. However, if malicious user can access others’ account and get token of others, they are able to upload, delete, create user or file with the identity of others, which cause security problem--which means group server needs to authenticate user. In the meantime, although the group server is entirely trustworthy, we cannot guarantee if someone pretends to be the group server, so user also need to authenticate group server. To solve this threat, it is important to do mutual authentication during login phase 


Algorithm: 

Set up Phase (when there is no account) :

U choose a username, password

U-->G: name, h(password)

G store(username, h(password))



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


Creating New User：

U choose a username, password

U-->G: {name, h(password)}K

G decrypt message, store (name, h(password))



The set up phase is where we first time run group server and there is no administrator account. We can assume that this process is safe and unmonitored, because the setup is ran offline. It is impossible for an attacker to get in touch with a new group server and register an account as the administrator. The secret shared between user and group server is the 128-bit MD5 hash of password. Since the group server is trustworthy, it will not be compromised or leak any complementary information. Therefore, the secret is safe as long as it only stays in the server, which true because it is only used for encrypt DH key. The transmission is then encrypted with 128-bit AES whose key is the secret, where brute-force is the only way for an attacker to break the message. After exchanging DH public key, they can generate a symmetric key, which will be used to encrypt following communication. This will make sure that each time such session key is fresh, and even if the session key is known, it cannot be used to recover older messages. We can prevent replay attack because attacker cannot decrypt the DH key without knowing W, where W is safe unless the group server is compromised. For the same reason, if anyone doesn’t know W, there are unable to pretend to be the group server because they cannot decrypt the key sent by user. Since g and p is hidden inside the group server and client, attackers have no access to them. Even if g and p are leaked by cracking the program, they cannot pass the mutual authentication without know secret W, which is not stored anywhere other than the group server. Under the assumption that the group server is trustworthy, W will not be retrieved by attackers, which also prevents the offline password guessing attack. The only possible way to break the system is through a brute force online attack. 

## T2: Token Modiﬁcation/Forgery 
Users are expected to attempt to modify their tokens to increase their access rights, and to attempt to create forged tokens. Your implementation of the UserToken interface must be extended to allow ﬁle servers (or anyone else) to determine whether a token is in fact valid. Speciﬁcally, it must be possible for a third-party to verify that a token was in fact issued by a trusted group server and was not modiﬁed after issuance.

Thread analysis: If user can forge tokens, this mean they can be members in any group by changing token info and still get accepted by file server. Then they would have access to group files without authorization. To prevent this problem, it is important to verify the validity of the token before accepting it--that is, token should only be accepted if it comes from a trustworthy group server, and is not corrupted. A digital signature shall be used to prove the integrity. 


Algorithm:  

digital signature

G decrypted token using private key  {token}K^-1G      token = {group, issuer, subject}

G-->U: {token}Ksymmetric(G-U), {{hash of  token}K^-1G}Ksymmetric(G-U)

U-->F: {{hash of  token}K^-1G}Ksymmetric(U-F),{token}Ksymmetric(U-F), {Ksymmetric(U-F)}K^-1F


F first get Ksymmetric between U and F using its private key, then decrypt {{hash of  token}K^-1G}Ksymmetric(U-F) to get signedhash value of token. Finally encrypt signature using G’s public key  {{hash of  token}K^-1G}KG

F verify if the signed  hash value of token is equal to the hash value of token sent by U

Note:Group server don’t sign the token, we sign the hash value of token


We need to prevent the user to change the token they receive from group, otherwise users can modify the privilege they have, because file client will decide whether user can access a group based on the token. So file server need to have method to make sure that the token they receive from file client is the original token sent by group server, it needs group server to sign the token they send. In group server, after the password login step, our user have a 128bits shared symmetric key Ksymmetric(G-U) with group server by Deff-hellman exchange(Ksymmetric= g^ab mod p). But the problem is: how could we sign the Token object? So we need to serialized token object to a byte array and then sign it. The question is the size of serialized token object is 338 bytes, which exceed the maximal size of RSA can sign(the maximal bytes RSA can encrypt is 245 bytes, but the serialize token object is 288 bytes). So I decide to sign the hash code of this token object instead of the whole object. I use SHA256 to create a 256bits hash value of token object. And then sign the hash value of token using private key of group server. To prevent others from using group public key to see the token, after signed the hash value, I use the Ksymmetric(G-U) to encrypt the signed hash value, so that only client can use public key of group server to see the token hash value. Meanwhile, group server also encrypt the serialized token object using Ksymmetric(G-U). Since the signed hash value of token is used to make sure that token is unmodified, and this encrypt token object is used for user’s identity. 
After user receive the  signed hash value which is encrypted by the Ksymmetric(G-U). He can decrypt both the signed hash value and toke object using its Ksymmetric(G-U). The server need to send both serialized token object and the signed hash value of token to the file server. So the client need to share a 128bits Ksymmetric(U-F) with file server so that it can encrypt both the token and the signed hash value. The client use the public key of file server to encrypt the Ksymmetric(U-F), and use this Ksymmetric(U-F) to encrypt the signed hash value and the token object. After file server receive all information, it can first use its private key to decrypt to get the Ksymmetric(U-F). Then use the Ksymmetric(U-F) to decrypt to get both signed hash value and toke object. Then file server use group server public key to encrypt the signature to get the hash value of token sent by group server. The file server uses SHA256 to obtain a 256bits hash value from the token object sent from client. If two hash values are same, it means the token sent from client is the token sent from group server.

## T3 Unauthorized File Servers 
The above trust model assumes that properly authenticated ﬁle servers are guaranteed to behave as expected. In order for this guarantee to mean anything, your implementation must ensure that if a user attempts to contact some server, s, then they actually connect to s and not some other server s0. Note that any user may run a ﬁle server. As such, the group server can not be required to know about all ﬁle servers. Your mechanism for enabling users to authenticate ﬁle servers should require communication between only the user and the ﬁle server, and possibly client-side application conﬁguration changes. Hint: You may wish to look into how SSH allows users to authenticate servers.


Thread analysis: 
Since anyone can run a file server, malicious user can pretend to be the server we want to connect with. If we send token or upload file to them, they will have access to user token and the files. To prevent the threat, it is important to authenticate the file server before user should send token for future moves. 

Algorithm: 

Public key crypto

User choose a 128 bit AES key K randomly generated by bouncy castle

U-->F : {K}kf

F decrypt K using its private key

F-->U: Ok

U and F communicate through the shared key, described in model 4


We only need to authenticate file server because the user is already authenticated when he is connected to the group server. In our current model, we assume there are no proactive attackers, which means they can only eavesdrop without modifying the transmitted data. We thus do not need to worry about the symmetric K being replaced by man-in-the-middle. Also we assume that the file server is not compromised for leaking its private key. Whatever encrypted using file server’s public key shall only be able to decrypted be the true file server. If anyone pretends to be the file server, he cannot retrieve the symmetric key and thus cannot decrypt any message coming toward him. Therefore, the integrity and confidentiality are ensured through the public key exchange. 


## T4: Information Leakage via Passive Monitoring 
Since our trust model assumes the existence of passive attackers (e.g., nosy administrators), you must ensure that all communications between your client and server applications are hidden from outside observers. This will ensure that ﬁle contents remain private, and that tokens cannot be stolen in transit.

Thread analysis: Since all of our communication will suffer from passive attackers, the information we send during communications are exposed to others. So to make sure other cannot get our information, we need to encrypted the information and then send them. We can use diff-hellman to share a symmetric key. And use symmetric key to encrypted message which will be send through network.


Algorithm: 

DH key for Group Server 
The set-up phase is completed in the first threat model, where a DH symmetric key is generated after the mutual authentication. User and group server now shares a symmetric DH key. The encryption is AES by bouncy castle 

To get updated token:

U--> G: request to get a new token

Group server put token in envelope, seal and encrypt the envelope, using the established DH key, {new token}Kdh

G-->U: {new token}Kdh

U receive the message and decrypt with Kdh


To create new user:

U-->G:  request to create new user, {username, password, token}Kdh

G decrypt with Kdh and make operations


To add/remove new user to group:

U-->G: request to add/remove user, {username, group name, token}Kdh

G decrypt with Kdh and make operations



To get members of a group:

U--> G: request to get a new token

G-->U: {list of members}Kdh

U receive the message and decrypt with Kdh



Public key for File Server
The set up phase is completed in thread model 3, where  a challenge and a symmetric key is send encrypted with file server’s public key. Now the user and file server shares a symmetric key K generated during mutual authentication described in threat model 3. The encryption is AES by bouncy castle 


To upload file:

U-->F: request to upload a file, {destination, file}K

F decrypt {file}K and store the file 



To download file:

U-->F: request to download a file

F--> U: {file}K

User decrypt the file 



To list all files:

U-->F: request to list all files

F--> U: {list}K

User decrypt the list and display 



We can assume that the symmetric keys are safe because their transmissions are encrypted by previous key agreement protocols. Because all messages (token, files) are encrypted with the symmetric key before transmission, they are safe from eavesdroppers. Since both the group and file server is assumed to be reliable after authentication, we won’t be worried about the symmetric key being leaked to attackers. Also, the encryption algorithm we use is AES , which prevents chosen-text attacker. Attacker has to brute the 128-bit AES key to break the message. For each session, the symmetric key is different because they are generated from either DH or randomly from bouncy castle AES. Knowing the symmetric key for one session does not help decrypting other messages. The entire transmission is encrypted, so we can assume that no eavesdropper can understand the message. 
