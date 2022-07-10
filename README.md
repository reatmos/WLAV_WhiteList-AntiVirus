# WLAV_WhiteList-AntiVirus
File Scan Program based on WhiteList

![WLAV](https://user-images.githubusercontent.com/66520964/178129065-8900c732-e973-4979-a6d7-f0f72813b57a.png)​

====================

[Project File(sln) Requirements]
1. QT
2. QT Visual Studio Extension
3. Openssl
4. Python

====================

[Project Setting - VC++ Directory]
Include Directory
- C:\\Users\\[User]\\AppData\\Local\\Programs\\Python\\Python[Version]\\include
- C:\\Program Files\\OpenSSL-Win64\\include

Library Directory
- C:\\Users\\[User]\\AppData\\Local\\Programs\\Python\\Python[Version]\\libs
- C:\\Program Files\\OpenSSL-Win64\lib\\VC

[Project Setting - Linker - Input]
Additional dependencies
- libcrypto64MD.lib
- libcrypto64MT.lib
- libssl64MD.lib
- libssl64MT.lib
- python[version].lib
