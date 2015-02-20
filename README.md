# git-hook-prereceive-ACLs
Perl script for Git Prereceive Hook that control access based on branch,user and file based on ACL file

This script is perfect for Atlassian Stash Prereceive Plugin. For other sw you have to customized some variables taken by ENV

## Parameters
 - $1 ACLs rules files: File with the Access Control List
 - $2 dryrun: For testing purpose


## ACL file format
 - 4 columns: BRANCH (without refs/head/ prefix), USER(s), FILE, ACTION (ALLOW, DENY)
 - BRANCH, USER and FILE admit reg expression
 - USER admit reg expression and list separeted by comma
 - Rules are read from top to bottom and the last ACTION affected is applied

## Example ACL file
```
.*          .*		      pom.xml		     DENY
master		    joe,mike	 .*		          ALLOW
feature-.*	 .*		      release.notes	DENY
```
