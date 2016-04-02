# crackhash
#这是一个破解hash值的python 脚本，方便我们平时做渗透时使用！
crackHash.py 0.3 ( https://github.com/ym2011/penetration )

Usage: 
------

  python crackHash.py <加密算法> 选项


目前支持的加密算法是:
--------------------------------------------

  MD4       - RFC 1320
  MD5       - RFC 1321
  SHA1      - RFC 3174 (FIPS 180-3)
  SHA224    - RFC 3874 (FIPS 180-3)
  SHA256    - FIPS 180-3
  SHA384    - FIPS 180-3
  SHA512    - FIPS 180-3
  RMD160    - RFC 2857
  GOST      - RFC 5831
  WHIRLPOOL - ISO/IEC 10118-3:2004
  LM        - Microsoft Windows hash
  NTLM      - Microsoft Windows hash
  MYSQL     - MySQL 3, 4, 5 hash
  CISCO7    - Cisco IOS type 7 encrypted passwords
  JUNIPER   - Juniper Networks $9$ encrypted passwords
  LDAP_MD5  - MD5 Base64 encoded
  LDAP_SHA1 - SHA1 Base64 encoded
  
  备注: for LM / NTLM it is recommended to introduce both values with this format:
  备注： 关于LM / NTLM，建议使用如下的格式
         python crackHash.py LM   -h 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7
         python crackHash.py NTLM -h 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7
以下是有效的选项:
------------------

  -h <hash 值>  如果只是想破解单一的hash值，可以使用该选项 和单一的hash 值

  -f <文件>     如果想破解多个hash 值， 可以使用该选项，文件中每行一个hash值，并且hash 值必须是同一种类型的


使用举例:
---------

  +++破解单一的hash 值
     python crackHash.py MD5 -h 098f6bcd4621d373cade4e832627b4f6
   
   
  +++破解带有特定字符的JUNIPER  加密的密码
     python crackHash.py JUNIPER -h "\$9\$LbHX-wg4Z"
  
  +++如果无法破解该hash值，可以翻墙进行google搜索
     python crackHash.py LDAP_SHA1 -h "{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA=" -g
   
  +++破解多个hash 值，其中文件里面必须是一行一个hash值
     python crackHash.py MYSQL -f mysqlhashesfile.txt
     

源代码:
-----------------------------------
https://github.com/ym2011/crackhash
