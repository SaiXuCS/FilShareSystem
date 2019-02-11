# Used Algorithm

For initial key agreement, the algorithm we use is Diffie Hellman, and public key crypto, provided by bouncy castle. For hashing, we use MD5 for generating weak secret, and sha256 for signing tokens. For symmetric encryption, we use AES with 128 bit key length from bouncy castle. To encrypt token and objects, we use the SealedObject java class along with Envelope. To ensure integrity, we use Hmac in bouncy castle with SHA256 digest and 128 bit aes.


## T1 Unauthorized Token Issuance
Due to the fact that clients are untrusted, we
must protect against the threat of illegitimate clients requesting tokens from the group
server. Your implementation must ensure that all clients are authenticated in a secure
manner prior to issuing them tokens. That is, we want to ensure that Alice cannot
request and receive Bob's security token from the group server.


Thread analysis:In the current system, user login is not protected with authentication, which means any user is able to login with a valid username. However, if malicious user can access others’ account and get token of others, they are able to upload, delete, create user or file with the identity of others, which cause security problem--which means group server needs to authenticate user. In the meantime, although the group server is entirely trustworthy, we cannot guarantee if someone pretends to be the group server, so user also need to authenticate group server. To solve this threat, it is important to do mutual authentication during login phase. In the latest model, since the attacker is active, we need to prevent the replay attack during login, and potential modification of the communication.  


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
U-->G: {name, h(password)}K （HMAC and sequence number are described later)
G decrypt message, store (name, h(password))


The set up phase is where we first time run group server and there is no administrator account. We can assume that this process is safe and unmonitored, because the setup is ran offline. It is impossible for an attacker to get in touch with a new group server and register an account as the administrator. The secret shared between user and group server is the 128-bit MD5 hash of password. Although MD5 is vulnerable to collision resistance, the account and password are created only by the administrator, who we assume are conscientious enough not to purposefully use key that are chosen for collision attack. Since the group server is trustworthy, it will not be compromised or leak any complementary information. Therefore, the secret is safe as long as it only stays in the server, which true because it is only used for encrypt DH key. The transmission is then encrypted with 128-bit AES whose key is the secret, where brute-force is the only way for an attacker to break the message. After exchanging DH public key, they can generate a symmetric key, which will be used to encrypt following communication. This will make sure that each time such session key is fresh, and even if the session key is known, it cannot be used to recover older messages, which prevents any offline attack. We can prevent replay attack because during each session, the encryption key is different. Since the weak secret W is safe unless the group server is compromised, if anyone doesn’t know W, there are unable to pretend to be the group server because they cannot decrypt the key sent by user. Since g and p is hidden inside the group server and client, attackers have no access to them. Even if g and p are leaked by cracking the program, they cannot pass the mutual authentication without know secret W, which is not stored anywhere other than the group server. The modification attack can be prevented through exchanging the challenge, if the key is corrupted, then it is infeasible to get the same result for encrypting a challenge. Under the assumption that the group server is trustworthy, W will not be retrieved by attackers, which also prevents the offline password guessing attack. Using the weak secret only for encryption leave it hard to break. The only possible way to break the system is through a brute force online attack.




## T2: Token Modiﬁcation/Forgery
Users are expected to attempt to modify their tokens to increase their access rights, and to attempt to create forged tokens. Your implementation of the UserToken interface must be extended to allow ﬁle servers (or anyone else) to determine whether a token is in fact valid. Speciﬁcally, it must be possible for a third-party to verify that a token was in fact issued by a trusted group server and was not modiﬁed after issuance.

Thread analysis: If user can forge tokens, this mean they can be members in any group by changing token info and still get accepted by file server. Then they would have access to group files without authorization. To prevent this problem, it is important to verify the validity of the token before accepting it--that is, token should only be accepted if it comes from a trustworthy group server, and is not corrupted. A digital signature shall be used to prove the integrity. Later threat model 7 will talk about the stolen token problem, namely the server ID.


Algorithm:   digital signature
Assume we have established a symmetric key between group server and client in threat model 1, and a key between file server and client in model 3

G decrypted token using private key  {token}K^-1G      token = {group, issuer, subject, serverID}

G-->U: {token}Ksymmetric(G-U), {{hash of  token}K^-1G}Ksymmetric(G-U). HMAC of previous message combined in one envelope

User decrypt token and signed token using Ksymmetric(G-U), and encrypt with Ksymmetric(U-F)

U-->F: {{hash of  token}K^-1G}Ksymmetric(U-F),{token}Ksymmetric(U-F), HMAC of previous message combined in one envelope


F first get Ksymmetric between U and F using its private key, then decrypt {{hash of  token}K^-1G}Ksymmetric(U-F) to get signedhash value of token. Finally encrypt signature using G’s public key  {{hash of  token}K^-1G}KG

F verify if the signed  hash value of token is equal to the hash value of token sent by U

Note:Group server don’t sign the token, we sign the hash value of token


We need to prevent the user to change the token they receive from group, otherwise users can modify the privilege they have, because file client will decide whether user can access a group based on the token. So file server need to have method to make sure that the token they receive from file client is the original token sent by group server, it needs group server to sign the token they send. In group server, after the password login step, our user have a 128bits shared symmetric key Ksymmetric(G-U) with group server by Deff-hellman exchange(Ksymmetric= g^ab mod p). In threat model 3, a fresh symmetric key is also established between file server and client. Both ensure that during each session, the encrypted token and signed token are different, which prevents replay attack to file server. The protection of symmetric key also provides confidentiality. The signed token by group server will ensure that the token is not modified by user or any attacker. The token and signed token cannot be brute forced offline because all encryption keys are unknown. Even if the key in one session is broken, it does not help to decrypt tokens in other sessions. To be more specific about implementation decision, we need to serialized token object to a byte array and then sign it. The question is the size of serialized token object is 338 bytes, which exceed the maximal size of RSA can sign(the maximal bytes RSA can encrypt is 245 bytes, but the serialize token object is 288 bytes). So I decide to sign the hash code of this token object instead of the whole object. Trimming down from 338 bytes to 245 bytes can still provide good randomness. I use SHA256 to create a 256 bits hash value of token object. And then sign the hash value of token using private key of group server. Since the signed hash value of token is used to make sure that token is unmodified, and this encrypt token object is used for user’s identity.









## T3 Unauthorized File Servers
The above trust model assumes that properly authenticated ﬁle servers are guaranteed to behave as expected. In order for this guarantee to mean anything, your implementation must ensure that if a user attempts to contact some server, s, then they actually connect to s and not some other server s0. Note that any user may run a ﬁle server. As such, the group server can not be required to know about all ﬁle servers. Your mechanism for enabling users to authenticate ﬁle servers should require communication between only the user and the ﬁle server, and possibly client-side application conﬁguration changes. Hint: You may wish to look into how SSH allows users to authenticate servers.


Thread analysis:
Since anyone can run a file server, malicious user can pretend to be the server we want to connect with. If we send token or upload file to them, they will have access to user token and the files. To prevent the threat, it is important to authenticate the file server before user should send token for future moves.

Algorithm: Public key crypto
User choose a 128 bit AES key K randomly generated by bouncy castle, a random challenge n
U-->F : {K}kf, n
F decrypt K using its private key
F-->U: {n}K
U encrypt n with K, and compare if they are the same

The man-in-the-middle attack can be prevented by sending challenged. The symmetric key K is protected by the file server’s public key, which ensures its confidentiality. If the key is replaced by the attacker,  the file server cannot send back the correct encrypted challenge. User can detect the error and end the connection. We don’t need to worry about the replay attack to the file server, because anyone can establish a symmetric key with the file server, and there is no harm doing that. What we concern is replay attack to the user, which is also prevented because user choose a random challenge to authenticate file server. Attacker cannot answer the challenge without knowing the file server’s private key. We assume the private key is safe.  If anyone pretends to be the file server, he cannot retrieve the symmetric key and thus cannot decrypt any message coming toward him. Therefore, the integrity and confidentiality are ensured through the public key exchange.


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


We can assume that the symmetric keys are safe because their transmissions are encrypted by previous key agreement protocols. Because all messages (token, files) are encrypted with the symmetric key before transmission, they are safe from eavesdroppers. Since both the group and file server is assumed to be reliable after authentication, we won’t be worried about the symmetric key being leaked to attackers. Also, the encryption algorithm we use is AES , which prevents chosen-text attacker. Attacker has to brute the 128-bit AES key to break the message. For each session, the symmetric key is different because they are generated from either DH or randomly from bouncy castle AES. Knowing the symmetric key for one session does not help decrypting other messages. The entire transmission is encrypted, so we can assume that no eavesdropper can understand the message. HMAC and sequence number are discussed later to prevent replay, reorder or modification. The confidentiality in this model, however, are ensured by symmetric encryption.











## T5 Message Reorder, Replay, or Modication
After connecting to a properly
authenticated group server or le server, the messages sent between the user and the
server might be reordered, saved for later replay, or otherwise modied by an active
attacker. You must provide users and servers with a means of detecting message
tampering, reordering, or replay. Upon detecting one of these exceptional conditions,
it is permissible to terminate the client/server connection.

Thread Analysis: If all communication is recorded any recorder, then they may apply an offline brute force attack to try to decrypt the communication. What’s worse is that they may connect the group server or file server by pretending to be us. Therefore, we have to ensure the freshness for the encryption key we use each time so that they cannot apply replay attack or decrypting all communications. On the other hand, they can modify data for any purposes, it is important detect changes, which means some kind of signature is necessary to protect integrity. To prevent replay attack, a random challenge shall be included for each command. To prevent reorder attack, a sequence number shall be included for each command.

Algorithm:
Set Up Phase:
During the mutual authentication process in thread model 1 and 3, we have already established a fresh symmetric key during each session. Assuming the key between server and client is Ks
User generates a random 128-bit AES key K, picks a random challenge n
U-->F/G: {K,n}Ks
F/G-->U: {{n}K}Ks
U encrypt n, and compare with {n}K
After the key exchange, both (group/file) server and (group/file) client initialize communication sequence s = 0

Communication between client and server:
Assume Ks = shared key between server and client      K = hmac key
User choose sha256 to calculate the hash, and encrypt with the symmetric key K to get HMAC
U-->F/G: {request,token, s}Ks, HMAC(request,token, s||K)
Server calculate HMAC and compare with HMAC(request,token, s||K). Then Server compare if s equals their local s
F/G-->U: {ok,s+1}Ks, HMAC(ok,s+1 ||K)
User calculate HMAC and compare whether message is corrupted, and then compare if s+1 equals their local s plus 1.

All communication will all follow the same pattern by sending the message and a corresponding HMAC code.


During the set-up phase, the shared key is described in threat 1 where a strong password protocol is applied between group server and group client to generate a Diffie Hellman key, which ensures the freshness. As to the file server side, a random AES key is generated by bouncy castle during each session. Each session a different key will be generated, so Brute forcing one session in either server does not help decrypting the rest, which prevents offline recording attack. Also, replaying the same message does not help because each time a different key is generated for encryption. By replaying the message, the attacker will not be able to answer the challenge, whose access will then be denied. The HMAC key is transfer along with a random challenge. Firstly, a man in the middle shall not be able to replace the key because it is protected by the shared key established earlier. Second, because a random challenge is send to ensure both client and server all use the same HMAC key, if the transmission is modified, it is infeasible to pass the challenge with the correct key; therefore, the user can detect this and end the connection. Then the HMAC is based on the aes key and SHA-256. Since SHA256 is safe for its second preimage, it is infeasible to modify the message while still getting the correct HMAC. In this case, we can detect any modified data. The sequence number will make sure that the message is arriving in desired order; if the sequence number doesn’t match up, then we know there is a reorder attack, so either the user or server will end the connection. The replay attack is also prevented because 1) attacker cannot replay the message in a different session because the fresh key 2) attacker cannot replay the message in the same session because if so, the sequence of the replayed command won’t match with the local sequence number. Here we assume the protocol is like TCP where there is an acknowledgement after a message is sent, so there is no package lost during the communication. The server will only be able to accept one command of a specific sequence number. Since The group server is safe from leaking, so no secrets will be leaked, no secrets are stored in file server. Attackers can only apply an online attack to try to break the system.


## T6 File Leakage
Since file servers are untrusted, files may be leaked from the server
to unauthorized principals. You must develop a mechanism for ensuring that les
leaked from the server are only readable by members of the appropriate group. As
in previous phases of the project, we stress that the group server cannot be expected
to know about all le servers to which its users may wish to connect. Further, your
proposed mechanism must ensure that some level of security is maintained as group
memberships change.


Thread analysis: If the file server leaks file to others, then the file stored inside the file server shall be protected by encryption whose key shall not be known by the file server, this key used to encrypt file should be known among the group that upload this shared file. The group member of this shared file shall all be able to see the file, which means there shall be a shared secret among group members. In the same time, when someone leaves the group, he shall not be able to see or decrypt anything new or modified. This means the shared secret within groups shall be renewed when someone drops the group.

Algorithm:
Set Up Phase:
In previous model, we established a symmetric key Kgu between client and group server, and another symmetric key Kfu between client and file server.
User choose sha256 to calculate the hash, and encrypt with the symmetric key Kgu to get HMAC
U-->G:	  {request to create a group, group name, token}Kgu, HMAC(group name, token||Kgu)
Group server decrypt the message, hash and encrypt it with Kgu, and compare.
G--U: OK
G generate a large number n, a random 128-bit aes key K, store <group name, K, n>


Upload File:
U-->G: request to encrypt file
Group server choose a random number n
G-->U: {n}Kgu
U-->G: {group, token, n}Kgu , HMAC(group,token,n||Kgu)
G verify n
G--U: { ArrayList<Entries> }Kgu
Group server read an ArrayList <Entries> from the file stored in disk. This arraylist store a list of 128 bits AES key and iv for this group, which are used to loop encrypted group shared file.(Entries is serializable object stored key and iv)
U: user decrypt the envelope to get ArrayList<Entries>
U-->F: { {file}nested encrypted using key stored in ArrayList, n: the size of ArrayList<Entries> you receive before, group}Kfu, HMAC({file}nested encrypted, n, group||Kfu)
F decrypt message using Kfu, calculate HMAC and compare, store <{file}nested encrypt, n: the size of ArrayList<Entries>> in file.
F-->U: okay

Download File:
U--> G: send request to get the group name of the file you want to donwload
G--> U: {<file, groupame>}Kgu, send group name to U
U-->G: send <groupname>Kgu to get the ArrayList<Entries> of this group
G-->U: send <ArrayList<Entries>>Kgu to U
U-->F: send <filename>Kgu request to download a file
File server make sure user is in the group of the file, then file server read encrypted shared file from disk
F--> U: ({ encrypted file }Kfu, n: the size of ArrayList<Entries> used to encrypt file, HMAC( {file}H^n(k) ||Kfu)
U: User decrypt the file, calculate HMAC and compare, use a series of key and iv stored in ArrayList<Entries> to create a series of ciphers, use the first n ciphers to decrypt the encrypted share file

Delete a user from group:
U-->G: request to delete user from a group
Group server pick a random n
G-->U: {n}Kgu
U-->G: {group, token, user to be deleted,n}Kgu , HMAC(group,token,user to be deleted,n||Kgu)
G: calculate HMAC and compare, then remove the user from group list and then create a new AES key and iv, append them into corresponding ArrayList<Entries> and store this new ArrayList into group file.


To make sure that even if file server leak the file, others cannot see the file content, so we need to have a group secret key to encrypt the shared file uploaded by the group members and only the group member can decrypt this file using secret key. I choose to use a series of keys to encrypt shared file. Every time when a user is removed from the group, the Group server will add a new secret key to the corresponding ArrayList<Entries>. So if the user is removed from the group, he only has past ArrayList<Entries>, which cannot decrypt the file uploaded by group member after he was removed from group.

When user upload a file, he will first try to get ArrayList<Entries> from Group server based on the group name of this file. After user get the ArrayList, he will use this ArrayList to construct a series of cipher to encrypt the file he want to upload and send the nested encrypted file and the size of this ArrayList to file server(Since when user want to decrypt the file, he also need to know how much ciphers he used to encrypt file, so that he can decrypt it). Then file server store this encrypted file and size of ArrayList in the disk.

When user want to download a file, he first need to know which group this file belong to, so user send request to file server to get the groupname of this file. Then user send to group server his token and groupname to get the ArrayList<Entries> of this group.  Then he send request to file server to get the nested encrypted file and the number of ciphers used to encrypt it. Then user use the first n entries in ArrayList to create n ciphers and then decipher the encrypted file.






## T7 Token Theft
one of its clients and attempt to pass it off to another user. You must develop a mechanism for ensuring that any stolen tokens are usable only on the server at which the theft took place.


Thread analysis: if the token is leaked from any file server, then the user can have access to other people’s raw token. It is then important to make sure that such leak only happens to the leaking server, which means the token should be bounded to the file server, so that nowhere else can use it.

Set Up Phase:
First time running the file server, file server will initialize an ID
User connecting to the server, user will enter the id for the file server
Assuming the shared key Kgu, Kfu, HMAC key K1 for group server , K2 for file server, group public key

Creating Token:
U-->G: {request for token, username, serverID}Kgu, HMAC(request for token, username, serverID||K1)
G-->U: {token, {token}K-1G}Kgu, HMAC(token, {token}K-1G || K1),
Where token = {issuer, group, subject, serverID}

User send token, and file server verify token as described in threat model 2. Besides,
If  serverID not the same as local file server ID, then file server will end the connection.


We can assume the communication between group server and file server are safe, which are described in previous models. The server id can bound the token to a specific server, since the token is signed by the group server, there is no way to change the server id so that the token can be used somewhere else. The model says that group server cannot be aware of any existence of file server, here we assume that there is no connection, communication or authentication between servers. In fact, the group server does not need to know where the server ID comes from, or whether it is valid; it could even be random. It only needs to add the ID in the token to make the token unique, without know whether there is actually a server having this ID. Since in previous models, the message cannot be modified by any attackers, the token cannot be modified, if the server ID doesn’t match, then the access will be denied. We assume that each file server will have its unique ID, in this case, we limit a token only in a specific file server
