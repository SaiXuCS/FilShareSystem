Sai Xu                sax2@pitt.edu                saixu
ZiNan Zhuang          ziz19@pitt.edu               ziz19
Benek, Samuel Anthony smb173@pitt.edu



Security Requirements：

Property 1: “Correctness.” Correctness states that if file f is shared with members of group g, then only members of group g should be able to read, modify, delete, or see the existence of f. Without this requirement, any user could access any file, which is contrary to the notion of group-based file sharing.

Property 2: ”Private Repository”: The private repository is the repository that only user himself can access. User can upload their personal file to it and modify it. It prevents others from changing or downloading a personal file.

Property 3: “Administrators.” Any user u can create a group g and needs the approval of the system administer. After the system administer agrees to your application, u then becomes the administrator of group g. Administrators are important for a system like this because there are permissions(privileges) that the group creator may not want all the group members to possess.

Property 4: “Logins.” A user must login with a username and password to identify themselves.Their username and password must be same as their recent updated version. It will prevent them from logging in using an old password.

Property 5: “Account Security.” For any user u, only u or an administrator may delete u’s account. Otherwise, any user could delete any other user, which would be problematic. 

Property 6: “Group Security.” Only an administrator can delete a group. This is to prevent users from arbitrarily deleting their own groups and ruining things for their group members.

Property 7: “Gatekeeping.” Only the administrator of group g can add a user u to g. The user who created the group should maintain the right to approve who gets to join their group. If any user could join any group they wanted, any user could get access to any file simply by joining that group. 

Property 8: “Shared Repository”: Every group should have a shared repository, where every member can access and upload file or download file from it. It separates personal files and group files.

Property 9: “Group Application.” User u must request the administrator for u to be allowed into group g. This is the simplest way for the administrator of g to know that u wants access to g’s files. If any group member is given the right to invite a user into the group, there can be potential information leak.

Property 10: “Protected Sharing.” Any member of group g can attempt to upload a file f and share it with g, but f will be stored in a buffer folder until it has been reviewed by the administrator. This is to prevent malicious files from entering the file server. 

Property 11: “Protected Downloading.”: When a user downloads the file, there should be an extra authentication before the downloading is allowed. If they want to upload some files, they should also authenticate their account info before uploading them. If anyone for some reason, has access to the logged in account, they can download those group sharing files without any permission, or they can upload any malicious files. This should be prohibited. 

Property 12e file, this mechanism allows them to retrieve what they deleted. Meanwhile, if any update of the files in the server leads to unexpected issues, group members can safely roll back to un-updated files. 

Property 13: “User rank”: When users apply for the account, they should be given rank, from 1 to 3, and lower rank users cannot read and download high rank users’ files even in public repository. Even within the group, there may be levels of confidentiality that need to be respected. It is good for the administrator to have to option to keep portions of the group from seeing certain material. 

Property 14: “System Administration.” In the Group Authentication Server, there are system administrators. System administrators handles account problems, create and delete groups, and all group establishment needs a system administrator to agree. This is to prevent any user from arbitrarily creating a group. 

Property 15: “Apply for account”: The account to access the group server as well as file servers should not be created by users. Instead, the system administrators will provide an account name and initial password. User information will be verified before the administrator will create the account. This is for authorization purposes—the system should ensure that user be authorized before accessing the system. Allowing creating accounts without limitation or authorization may lead to anonymous user problems.  

Property 16: “Usual Working Place”: When the user logs into the group server system for authentication, the IP address should be recorded. If any unusual IP is detected, there should be another security check before the user can access the file system. This is to prevent any accidental leaking of a user account, which could be used by unauthorized users. 

Property 17: “One Login User”: for any reasons, if a same user account is used to log into the system, the account should be logged out immediately. The user is probably accessing the system using a different computer, but forgot to log out on the previous one. However, this is to prevent the account from being stolen before any serious damage could happen.  

Property 18: “Inactive Behavior”: if the user passes the group authentication, but in a following period of time does not make any action (i.e., leave the system in the background, leave the computer, or forgets to log out), the system should log out the user for safety reasons. If the user is not near his computer, anyone can theoretically make use of his account and do something malicious. 

Property 19: “Log system”: Groups and the system have their own log system. The system log will record who performs account activities such as login, logout, and group creation time. The group log system should record the modification to a file. It will help us to repair errors and catch any attackers.

Property 20: “Delete Limitation”: Groups files should maintain their integrity by prohibiting users from arbitrarily deleting files. Unless the file is uploaded by the user himself, any deletion shall be limited. The user can only delete their own file, and for others files, especially important files, the deletion shall be approved by the administrator. 

Property 21: “Signed File”: Every file in the file server shall be given a signature. When a user downloads these files, they shall check the signature to ensure integrity. If for any reason, some files are shared among members without using the file server, the integrity can be ensured. This is to prevent anyone from counterfeiting shared files with the same name. When uploading the modified file, the signature shall be regenerated after its safety is checked. 

Property 22: “Completion Check”: Before and after downloading, the size of files shall be checked to make sure it is correctly downloaded. If multiple files are stored in multiple file servers, there could be bugs that result in some of the files not being downloaded correctly. If there are thousands of files, it is hard to check integrity. The system should compare the size of files—if they don’t match, there could be a chance where some files are lost during downloading process. 

Property 23: “Cut Off the Root”: when a group is deleted, all the files stored previously in the file server shall be immediately deleted without any delay. If there is cache or residue of the project, any users in the system may find it and use it for malicious purposes. They may also try to create storage issues that leave the system vulnerable to information leak. 

Property 24: “User Reset”: When a user quits the group, the group server shall update the information immediately. When a user account is deleted, its group list shall be reset to none. The user shall not be able to still have access to the shared files after leaving the group. If the account is deleted and later reactivated, it shall not automatically belong to the previous joined groups. 


Threat Models
Publishing Company
This sort of file sharing system could be used in a publishing company. A group could consist of the author of a book, any publishers authorized to work on it, the editor, illustrators, etc. These are all people who would want to see the content of the book they are working on, but to prevent plagiarism, they would not want anyone else to see this content.
For this model, we assume that the publishers do not have malicious intent against the creators. This is because the publishers would act as the group administrators, and the administrators have a significant amount of power over the other members of the groups and the associated files. We also assume that the users will be responsible with their login information, meaning that they will remember it and not allow anyone else to learn it. If a user cannot verify who they are, the security of the system is undermined.

Relevant Security Requirements:

Property 1: “Correctness.”: Only people related to this book should be able to read, and download this book. 

Property 2: ”Private Repository”: The private repository is the repository where only user himself can access. Authors and publishers can have their own version of book, and they can upload this book, or revise it. It gives every opportunity to finish this book, since everyone can propose their favorite version of the book.

Property 3: “Administrators.” The publisher should be the administer of this group.

Property 5: “Account Security.” For any user u, only u or an administrator may delete u’s account. 

Property 6: “Group Security.” Only the administrator can delete g. Other people such as author or printer cannot delete each other.

Property 7: “Gatekeeping.” Only publisher can add more related people to this group.

Property 8: “Shared Repository”: The author can upload his book in the public repository. Every related creator can access and upload a file or download a file from it. They can also post their discussions in it. It separates general files and discussions from their private work.

Property 11: “Protected Downloading.”: When users download the file, there should be an extra authentication before the downloading is allowed. It will prevent theft to steal their book draft.

Property 13: “User rank”: When users apply for the account, they should be given a rank, from 1 to 3, and lower rank users cannot read and download high rank users’ files even in the public repository. Some people such as the printer shouldn’t see this book before it is finished, and they will be given a lower rank.

Property 14: “System Administration” In the publishing file sharing system, there should be system administrators, who handle authors and other people’s accounts, create and delete groups, and all group establishment needs the system administrator to agree. This system administrator should be the manager of all those publishing programs.

Property 15: “Apply for account”: The account to access the group server as well as file servers should not be created by the author. Instead, the system administrators will provide an account name and initial password to creators. People’s info will be verified before the administrator creates the account. This is for authorization purposes to ensure that only registered people can access the system. Allowing the creation of accounts without limitation or authorization may lead to anonymous user problems.

Property 23: “Cut Off the Root”: When a group is deleted, all the files stored previously in the file server shall be immediately deleted without any delay. If there is any cache or residue of the project, any users in the system may find it and use it for malicious purposes. They may also try to create storage issues that leave the system vulnerable to information leak. Such as others can know the content of all books before we sell it.

Property 24: “User Reset”: When the user quits the group, the group server shall update the information immediately. When the user account is deleted, its group list shall be reset to none. The user shall not be able to still have access to the shared files after leaving the group. And for any reason, if the account is deleted and later reactivated, it shall not automatically belong to the previous joined groups. 






Tutorial Class Company:
This file sharing system can be used in an education company such as teaching students math or literature. A group could consist of the all student in one course, such as if there are 10 student studying math, they will be in one group and the administer of this group will be the teacher of this class. Any student who has registered for this course can be authorized to this group. Students in the group can upload their homework to their personal repository and teachers can view submitted homework. Students cannot view other students’ homework since homework is stored in the private repository. But teachers can put the studying material in the public repository, so all students in this class group can download this material. However, this system gives the teacher a higher rank, so the studying material put out by teacher will have higher rank, and cannot be modified or deleted by students. 

We assume that the students may want to copy others’ homework, so all students must upload their homework to their own private repository. It will only give himself and teacher the right to read and download this homework. This file system will not connect with the outer internet. 


Relevant Security Requirements:

Property 1: “Correctness.”: Only students in this course should be able to read and download the course materials. For instance, assignments, projects, or practice tests should be limited to only those who are in this course for confidentiality purpose. 

Property 2: ”Private Repository”: the private repository is the repository where only the user himself can access. Students can upload their homework, or revise it. It prevents classmates from cheating and using others’ effort.

Property 3: “Administrators.” Teachers should be the group administrator because there are permissions(privileges) that students in this group should not have. 

Property 6: “Group Security.” Only the administrator can delete a group. Students should not have the right to delete the course group for any purpose. 

Property 7: “Gatekeeping.” Only the teacher can invite students into the group. Students who are not enrolled in the course should not be invited by students who are in the course. 

Property 8: “Shared Repository”: Teachers can upload course material in the public repository. Every student can access and upload a file or download a file from it. They can also post their discussion in it. It separates general files and discussion from their private homework.

Property 14: “System Administration” In the teaching file sharing system, there should be system administrators, who handle student accounts, create and delete groups, and all group establishment needs system administrators to agree. This is to prevent any user from arbitrarily creating group. 

Property 15: “Apply for account”: The account to access the group server as well as file servers should not be created by students. Instead, the system administrators will provide an account name and initial password to students. Student info will be verified before the administrator creates the account. This is for authorization purpose to ensure that only registered student can access the system. Allowing the creation of accounts without limitation or authorization may lead to anonymous user problems.

Property 18: “Inactive Behavior”: if students in a period of time do not make any action (i.e., leave the system in the background, leave the computer, or forget to log out), the system should log out the student for safety reasons. If the user is not near his computer, anyone can theoretically make use of his account, and do something malicious. 

Property 22: “Completion Check”: before and after downloading, the size of files shall be checked to make sure it is correctly downloaded. If multiple files are stored in multiple file servers, there could be bugs that result in some of the files not being downloaded correctly. If there are thousands of files, it is hard to check integrity. The system should compare the size of files—if they don’t match, there could be a chance where some files are lost during downloading process. All teaching materials should retain their integrity for education quality. Any error for downloading teaching material could delay study progress. 

Property 24: “User Reset”: When students drop the course, the group server shall update the information immediately. When the user account is deleted, its group list shall be reset to none. Students shall not be able to remain in the class when they are not enrolled in the course. The roster should remain consistent with any updates. 
