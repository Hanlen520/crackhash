#!/usr/bin/python
#-*- coding:utf-8 -*-
########################################################################################################
#
# crackhash.py - v0.3 20160329  https://github.com/ym2011/crackhash
#
# 在线破解hash的小脚本。  
# 
#####################################################################################################
try:
    import sys
    import hashlib
    import urllib2
    import getopt
    from os import path
    from urllib import urlencode
    from re import search, findall
    from random import seed, randint
    from base64 import decodestring, encodestring
    from cookielib import LWPCookieJar
except:
    print """
运行出错:

  以下的python 库尚未安装：
  
  该应用程序需要的库：sys, hashlib, urllib, urllib2, os, re, random, getopt, base64 and cookielib.
  
  请检查这些依赖库是否安装在您的操作系统上
  
  提示：安装这些库的格式为：
  
  apt-get install 库名字
  
  例如: apt-get install httplib2
  
  或者使用以下方式：
  
  easy_install httplib2
  
"""
    sys.exit(1)

try:
    from httplib2 import Http
except:
    print """
运行出错:

  Python 依赖库： httplib2  尚未被安装在您的系统中. 
  
  请在使用该程序之前安装该依赖库。 
  
"""
    sys.exit(1)

try:
    from libxml2 import parseDoc
except:
    print """
   
运行出错:

  Python 依赖库： libxml2 尚未被安装在您的系统中. 

  如果缺失该依赖库，部分插件将无法正常工作。
  
  请在使用该程序之前安装该依赖库。

"""

########################################################################################################
### 定义常量
########################################################################################################

MD4 = "md4"
MD5 = "md5"
SHA1 = "sha1"
SHA224 = "sha224"
SHA256 = "sha256"
SHA384 = "sha384"
SHA512 = "sha512"
RIPEMD = "rmd160"
LM = "lm"
NTLM = "ntlm"
MYSQL = "mysql"
CISCO7 = "cisco7"
JUNIPER = "juniper"
GOST = "gost"
WHIRLPOOL = "whirlpool"
LDAP_MD5 = "ldap_md5"
LDAP_SHA1 = "ldap_sha1"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b8pre) Gecko/20101213 Firefox/4.0b8pre",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) chromeframe/10.0.648.205",
    "Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01",
    "Opera/9.80 (Windows NT 6.1; U; pl) Presto/2.7.62 Version/11.00",
    "Opera/9.80 (X11; Linux i686; U; pl) Presto/2.6.30 Version/10.61",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.861.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.872.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.812.0 Safari/535.1",
]


########################################################################################################
### 定义破解网站
########################################################################################################


class NETMD5CRACK:
    name = "netmd5crack"
    url = "http://www.netmd5crack.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
		 # 如果成功破解，返回true，如果不能被破解，则返回false
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://www.netmd5crack.com/cgi-bin/Crack.py?InputHash=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        regexp = r'<tr><td class="border">%s</td><td class="border">[^<]*</td></tr></table>' % (hashvalue)
        match = search(regexp, html)

        if match:
            match2 = search("Sorry, we don't have that hash in our database", match.group())
            if match2:
                return None
            else:
                return match.group().split('border')[2].split('<')[0][2:]


class BENRAMSEY:
    name = "benramsey"
    url = "http://tools.benramsey.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://tools.benramsey.com/md5/md5.php?hash=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<string><!\[CDATA\[[^\]]*\]\]></string>', html)

        if match:
            return match.group().split(']')[0][17:]
        else:
            return None


class GROMWEB:
    name = "gromweb"
    url = "http://md5.gromweb.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):

        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5.gromweb.com/query/%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        if response:
            return response.read()

        return response


class HASHCRACKING:
    name = "hashcracking"
    url = "http://md5.hashcracking.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5.hashcracking.com/search.php?md5=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'\sis.*', html)

        if match:
            return match.group()[4:]

        return None


class VICTOROV:
    name = "hashcracking"
    url = "http://victorov.su"
    supported_algorithm = [MD5]

    def isSupported(self, alg):

        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://victorov.su/md5/?md5e=&md5d=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r': <b>[^<]*</b><br><form action="">', html)

        if match:
            return match.group().split('b>')[1][:-2]

        return None


class THEKAINE:
    name = "thekaine"
    url = "http://md5.thekaine.de"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5.thekaine.de/?hash=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<td colspan="2"><br><br><b>[^<]*</b></td><td></td>', html)

        if match:

            match2 = search(r'not found', match.group())

            if match2:
                return None
            else:
                return match.group().split('b>')[1][:-2]


class TMTO:
    name = "tmto"
    url = "http://www.tmto.org"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://www.tmto.org/api/latest/?hash=%s&auth=true" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'text="[^"]+"', html)

        if match:
            return decodestring(match.group().split('"')[1])
        else:
            return None


class MD5_DB:
    name = "md5-db"
    url = "http://md5-db.de"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5-db.de/%s.html" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        if not response:
            return None

        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(
            r'<strong>Es wurden 1 m.gliche Begriffe gefunden, die den Hash \w* verwenden:</strong><ul><li>[^<]*</li>',
            html)

        if match:
            return match.group().split('li>')[1][:-2]
        else:
            return None


class MY_ADDR:
    name = "my-addr"
    url = "http://md5.my-addr.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php"

        # 创立参数，浏览器POST时发送数据的参数
        params = {"md5": hashvalue,
                  "x": 21,
                  "y": 8}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", html)
		# 通过搜索进行匹配html中包含<span class='middle_title'>Hashed string</span>: [^<]*</div> 的字符串
		# 这样操作将会得到包含密码的html代码片段

        if match:
            return match.group().split('span')[2][3:-6]
			# 将匹配到的字符串以span 分割，分割2次，选取分割后的第2段（0段，1段，2段），截取第二段第4字符到倒数第六字符之间的字符串
			# 得到的字符串便是我们的hash 被破解后的密码明文
        else:
            return None


class MD5PASS:
    name = "md5pass"
    url = "http://md5pass.info"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = self.url

        # 创建查询URL（其中包含POST的参数）
        params = {"hash": hashvalue,
                  "get_pass": "Get Pass"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None
		
		# 此处为匹配响应的textview 中出现password结果的字符串

        match = search(r"Password - <b>[^<]*</b>", html)

        if match:
		# 此处使用匹配对含有passwordde 字符串进行分段，取第二段中的0-倒数第二字段
            return match.group().split('b>')[1][:-2]
        else:
            return None


class MD5DECRYPTION:
    name = "md5decryption"
    url = "http://md5decryption.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = self.url

        # 建立post 参数
        params = {"hash": hashvalue,
                  "submit": "Decrypt It!"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None
		
		# 根据响应的textview 筛选出包含密码的字符串
        match = search(r"Decrypted Text: </b>[^<]*</font>", html)

        if match:
		# 对匹配到的字符串，抽取出其中的密码字段
            return match.group().split('b>')[1][:-7]
        else:
            return None


class MD5CRACK:
    name = "md5crack"
    url = "http://md5crack.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5crack.com/crackmd5.php"

        # 建立post 参数
        params = {"term": hashvalue,
                  "crackbtn": "Crack that hash baby!"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'Found: md5\("[^"]+"\)', html)

        if match:
            return match.group().split('"')[1]
        else:
            return None


class MD5_DECRYPTER:
    name = "md5-decrypter"
    url = "http://md5-decrypter.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = self.url

        # 建立post 参数
        params = {"data[Row][cripted]": hashvalue}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = findall(r'<b class="res">[^<]*</b>', html)

        if match:
            return match[1].split('>')[1][:-3]
        else:
            return None


class AUTHSECUMD5:
    name = "authsecu"
    url = "http://www.authsecu.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):

        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://www.authsecu.com/decrypter-dechiffrer-cracker-hash-md5/script-hash-md5.php"

        # 建立post 参数
        params = {"valeur_bouton": "dechiffrage",
                  "champ1": "",
                  "champ2": hashvalue,
                  "dechiffrer.x": "78",
                  "dechiffrer.y": "7"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = findall(r'<td><p class="chapitre---texte-du-tableau-de-niveau-1">[^<]*</p></td>', html)

        if len(match) > 2:
            return match[1].split('>')[2][:-3]
        else:
            return None


class HASHCRACK:
    name = "hashcrack"
    url = "http://hashcrack.com"
    supported_algorithm = [MD5, SHA1, MYSQL, LM, NTLM]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://hashcrack.com/indx.php"

        hash2 = None
        if alg in [LM, NTLM] and ':' in hashvalue:
            if alg == LM:
                hash2 = hashvalue.split(':')[0]
            else:
                hash2 = hashvalue.split(':')[1]
        else:
            hash2 = hashvalue

        # 删除可能出现的字符 '*'
        if alg == MYSQL and hash2[0] == '*':
            hash2 = hash2[1:]

        # 建立post webform参数
        params = {"auth": "8272hgt",
                  "hash": hash2,
                  "string": "",
                  "Submit": "Submit"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(
            r'<div align=center>"[^"]*" resolves to</div><br><div align=center> <span class=hervorheb2>[^<]*</span></div></TD>',
            html)

        if match:
            return match.group().split('hervorheb2>')[1][:-18]
        else:
            return None


class OPHCRACK:
    name = "ophcrack"
    url = "http://www.objectif-securite.ch"
    supported_algorithm = [LM, NTLM]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 检查hashvalue 是否有 ':' 字符
        if ':' not in hashvalue:
            return None
		#彩虹表无法破解该NTLM hash值，因为缺少一个有效的LM hash 并且 有可能是一个空值
        if hashvalue.split(':')[0] == "aad3b435b51404eeaad3b435b51404ee":
            return None

        # 创建查询URL and the headers
        url = "http://www.objectif-securite.ch/en/products.php?hash=%s" % (hashvalue.replace(':', '%3A'))

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(
            r'<table><tr><td>Hash:</td><td>[^<]*</td></tr><tr><td><b>Password:</b></td><td><b>[^<]*</b></td>', html)

        if match:
            return match.group().split('b>')[3][:-2]
        else:
            return None


class C0LLISION:
    name = "c0llision"
    url = "http://www.c0llision.net"
    supported_algorithm = [MD5, LM, NTLM]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 检查hashvalue 是否有 ':' 字符
        if alg in [LM, NTLM] and ':' not in hashvalue:
            return None

        # 寻找参数 "hash[_csrf_token]" 
        response = do_HTTP_request("http://www.c0llision.net/webcrack.php")
        html = None
        if response:
            html = response.read()
        else:
            return None
        match = search(r'<input type="hidden" name="hash._csrf_token." value="[^"]*" id="hash__csrf_token" />', html)
        token = None
        if match:
            token = match.group().split('"')[5]

        # 创建查询URL
        url = "http://www.c0llision.net/webcrack/request"

        # 建立post 参数
        params = {"hash[_input_]": hashvalue,
                  "hash[_csrf_token]": token}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = None
        if alg in [LM, NTLM]:
            html = html.replace('\n', '')
            result = ""

            match = search(r'<table class="pre">.*?</table>', html)
            if match:
                try:
                    doc = parseDoc(match.group())
                except:
                    print "提示: 需要安装 libxml2 插件."
                    return None
                lines = doc.xpathEval("//tr")
                for l in lines:
                    doc = parseDoc(str(l))
                    cols = doc.xpathEval("//td")

                    if len(cols) < 4:
                        return None

                    if cols[2].content:
                        result = " > %s (%s) = %s\n" % (cols[1].content, cols[2].content, cols[3].content)

				#返回 （结果，另起一行打印结果，或者返回空值）
                return (result and result.split()[-1] or None)

        else:
            match = search(r'<td class="plaintext">[^<]*</td>', html)

            if match:
                return match.group().split('>')[1][:-4]

        return None


class REDNOIZE:
    name = "rednoize"
    url = "http://md5.rednoize.com"
    supported_algorithm = [MD5, SHA1]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = ""
        if alg == MD5:
            url = "http://md5.rednoize.com/?p&s=md5&q=%s&_=" % (hashvalue)
        else:
            url = "http://md5.rednoize.com/?p&s=sha1&q=%s&_=" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        return html


class CMD5:
    name = "cmd5"
    url = "http://www.cmd5.org"
    supported_algorithm = [MD5, NTLM]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

		#查找隐藏的参数
        response = do_HTTP_request("http://www.cmd5.org/")
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="[^"]*" />', html)
        viewstate = None
        if match:
            viewstate = match.group().split('"')[7]

        match = search(
            r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField1" id="ctl00_ContentPlaceHolder1_HiddenField1" value="[^"]*" />',
            html)
        ContentPlaceHolder1 = ""
        if match:
            ContentPlaceHolder1 = match.group().split('"')[7]

        match = search(
            r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField2" id="ctl00_ContentPlaceHolder1_HiddenField2" value="[^"]*" />',
            html)
        ContentPlaceHolder2 = ""
        if match:
            ContentPlaceHolder2 = match.group().split('"')[7]

        # 创建查询URL
        url = "http://www.cmd5.org/"

        hash2 = ""
        if alg == MD5:
            hash2 = hashvalue
        else:
            if ':' in hashvalue:
                hash2 = hashvalue.split(':')[1]

        # 建立post 参数
        params = {"__EVENTTARGET": "",
                  "__EVENTARGUMENT": "",
                  "__VIEWSTATE": viewstate,
                  "ctl00$ContentPlaceHolder1$TextBoxq": hash2,
                  "ctl00$ContentPlaceHolder1$InputHashType": alg,
                  "ctl00$ContentPlaceHolder1$Button1": "decrypt",
                  "ctl00$ContentPlaceHolder1$HiddenField1": ContentPlaceHolder1,
                  "ctl00$ContentPlaceHolder1$HiddenField2": ContentPlaceHolder2}

        header = {"Referer": "http://www.cmd5.org/"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params, header)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<span id="ctl00_ContentPlaceHolder1_LabelResult">[^<]*</span>', html)

        if match:
            return match.group().split('>')[1][:-6]
        else:
            return None


class AUTHSECUCISCO7:
    name = "authsecu"
    url = "http://www.authsecu.com"
    supported_algorithm = [CISCO7]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL and the headers
        url = "http://www.authsecu.com/decrypter-dechiffrer-cracker-password-cisco-7/script-password-cisco-7-launcher.php"

        # 建立post 参数
        params = {"valeur_bouton": "dechiffrage",
                  "champ1": hashvalue,
                  "dechiffrer.x": 43,
                  "dechiffrer.y": 16}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = findall(r'<td><p class="chapitre---texte-du-tableau-de-niveau-1">[^<]*</p></td>', html)

        if match:
            return match[1].split('>')[2][:-3]
        else:
            return None


class CACIN:
    name = "cacin"
    url = "http://cacin.net"
    supported_algorithm = [CISCO7]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL and the headers
        url = "http://cacin.net/cgi-bin/decrypt-cisco.pl?cisco_hash=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<tr>Cisco password 7: [^<]*</tr><br><tr><th><br>Decrypted password: .*', html)

        if match:
            return match.group().split(':')[2][1:]
        else:
            return None


class IBEAST:
    name = "ibeast"
    url = "http://www.ibeast.com"
    supported_algorithm = [CISCO7]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL and the headers
        url = "http://www.ibeast.com/content/tools/CiscoPassword/decrypt.php?txtPassword=%s&submit1=Enviar+consulta" % (
        hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<font size="\+2">Your Password is [^<]*<br>', html)

        if match:
            return match.group().split('is ')[1][:-4]
        else:
            return None


class PASSWORD_DECRYPT:
    name = "password-decrypt"
    url = "http://password-decrypt.com"
    supported_algorithm = [CISCO7, JUNIPER]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL and the parameters
        url = ""
        params = None
        if alg == CISCO7:
            url = "http://password-decrypt.com/cisco.cgi"
            params = {"submit": "Submit",
                      "cisco_password": hashvalue,
                      "submit": "Submit"}
        else:
            url = "http://password-decrypt.com/juniper.cgi"
            params = {"submit": "Submit",
                      "juniper_password": hashvalue,
                      "submit": "Submit"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'Decrypted Password:&nbsp;<B>[^<]*</B> </p>', html)

        if match:
            return match.group().split('B>')[1][:-2]
        else:
            return None


class HASHCHECKER:
    name = "hashchecker"
    url = "http://www.hashchecker.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL and the headers
        url = "http://www.hashchecker.com/index.php"

        # 建立post 参数
        params = {"search_field": hashvalue,
                  "Submit": "search"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<td><li>Your md5 hash is :<br><li>[^\s]* is <b>[^<]*</b> used charlist :2</td>', html)

        if match:
            return match.group().split('b>')[1][:-2]
        else:
            return None


class MD5HASHCRACKER:
    name = "md5hashcracker"
    url = "http://md5hashcracker.appspot.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5hashcracker.appspot.com/crack"

        # 建立post 参数
        params = {"query": hashvalue,
                  "submit": "Crack"}

        # Make the firt request
        response = do_HTTP_request(url, params)

        # Build the second URL
        url = "http://md5hashcracker.appspot.com/status"

        # Make the second request
        response = do_HTTP_request(url)

        # 分析响应
        if response:
            html = response.read()
        else:
            return None
        match = search(r'<td id="cra[^"]*">not cracked</td>', html)

        if not match:
            match = search(r'<td id="cra[^"]*">cracked</td>', html)
            regexp = r'<td id="pla_' + match.group().split('"')[1][4:] + '">[^<]*</td>'
            match2 = search(regexp, html)
            if match2:
                return match2.group().split('>')[1][:-4]

        else:
            return None


class PASSCRACKING:
    name = "passcracking"
    url = "http://passcracking.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://passcracking.com/index.php"

        # 建立post 参数
        boundary = "-----------------------------" + str(
            randint(1000000000000000000000000000, 9999999999999999999999999999))
        params = ['--' + boundary,
                  'Content-Disposition: form-data; name="admin"',
                  '',
                  'false',

                  '--' + boundary,
                  'Content-Disposition: form-data; name="admin2"',
                  '',
                  '77.php',

                  '--' + boundary,
                  'Content-Disposition: form-data; name="datafromuser"',
                  '',
                  '%s' % (hashvalue),

                  '--' + boundary + '--', '']
        body = '\r\n'.join(params)

        # Build the headers
        headers = {"Content-Type": "multipart/form-data; boundary=%s" % (boundary),
                   "Content-length": len(body)}

        # 进行http 网络查询
        request = urllib2.Request(url)
        request.add_header("Content-Type", "multipart/form-data; boundary=%s" % (boundary))
        request.add_header("Content-length", len(body))
        request.add_data(body)
        try:
            response = urllib2.urlopen(request)
        except:
            return None

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<td>md5 Database</td><td>[^<]*</td><td bgcolor=.FF0000>[^<]*</td>', html)

        if match:
            return match.group().split('>')[5][:-4]
        else:
            return None


class ASKCHECK:
    name = "askcheck"
    url = "http://askcheck.com"
    supported_algorithm = [MD4, MD5, SHA1, SHA256]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://askcheck.com/reverse?reverse=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'Reverse value of [^\s]* hash <a[^<]*</a> is <a[^>]*>[^<]*</a>', html)

        if match:
            return match.group().split('>')[3][:-3]
        else:
            return None


class FOX21:
    name = "fox21"
    url = "http://cracker.fox21.at"
    supported_algorithm = [MD5, LM, NTLM]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        hash2 = None
        if alg in [LM, NTLM] and ':' in hashvalue:
            if alg == LM:
                hash2 = hashvalue.split(':')[0]
            else:
                hash2 = hashvalue.split(':')[1]
        else:
            hash2 = hashvalue

        # 创建查询URL
        url = "http://cracker.fox21.at/api.php?a=check&h=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        xml = None
        if response:
            try:
                doc = parseDoc(response.read())
            except:
                print "INFO: You need libxml2 to use this plugin."
                return None
        else:
            return None

        result = doc.xpathEval("//hash/@plaintext")

        if result:
            return result[0].content
        else:
            return None


class NICENAMECREW:
    name = "nicenamecrew"
    url = "http://crackfoo.nicenamecrew.com"
    supported_algorithm = [MD5, SHA1, LM]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        hash2 = None
        if alg in [LM] and ':' in hashvalue:
            hash2 = hashvalue.split(':')[0]
        else:
            hash2 = hashvalue

        # 创建查询URL
        url = "http://crackfoo.nicenamecrew.com/?t=%s" % (alg)

        # 建立post 参数
        params = {"q": hash2,
                  "sa": "Crack"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'The decrypted version of [^\s]* is:<br><strong>[^<]*</strong>', html)

        if match:
            return match.group().split('strong>')[1][:-2].strip()
        else:
            return None


class JOOMLAAA:
    name = "joomlaaa"
    url = "http://joomlaaa.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):

        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://joomlaaa.com/component/option,com_md5/Itemid,31/"

        # 建立post 参数
        params = {"md5": hashvalue,
                  "decode": "Submit"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r"<td class='title1'>not available</td>", html)

        if not match:
            match2 = findall(r"<td class='title1'>[^<]*</td>", html)
            return match2[1].split('>')[1][:-4]
        else:
            return None


class MD5_LOOKUP:
    name = "md5-lookup"
    url = "http://md5-lookup.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5-lookup.com/livesearch.php?q=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<td width="250">[^<]*</td>', html)

        if match:
            return match.group().split('>')[1][:-4]
        else:
            return None


class SHA1_LOOKUP:
    name = "sha1-lookup"
    url = "http://sha1-lookup.com"
    supported_algorithm = [SHA1]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://sha1-lookup.com/livesearch.php?q=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<td width="250">[^<]*</td>', html)

        if match:
            return match.group().split('>')[1][:-4]
        else:
            return None


class SHA256_LOOKUP:
    name = "sha256-lookup"
    url = "http://sha-256.sha1-lookup.com"
    supported_algorithm = [SHA256]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://sha-256.sha1-lookup.com/livesearch.php?q=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<td width="250">[^<]*</td>', html)

        if match:
            return match.group().split('>')[1][:-4]
        else:
            return None


class RIPEMD160_LOOKUP:
    name = "ripemd-lookup"
    url = "http://www.ripemd-lookup.com"
    supported_algorithm = [RIPEMD]

    def isSupported(self, alg):

        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://www.ripemd-lookup.com/livesearch.php?q=%s" % (hashvalue)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<td width="250">[^<]*</td>', html)

        if match:
            return match.group().split('>')[1][:-4]
        else:
            return None


class MD5_COM_CN:
    name = "md5.com.cn"
    url = "http://md5.com.cn"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5.com.cn/md5reverse"

        # 建立post 参数
        params = {"md": hashvalue,
                  "submit": "MD5 Crack"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<b style="color:red;">[^<]*</b><br/><span', html)

        if match:
            return match.group().split('>')[1][:-3]
        else:
            return None


class DIGITALSUN:
    name = "digitalsun.pl"
    url = "http://md5.digitalsun.pl"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5.digitalsun.pl/"

        # 建立post 参数
        params = {"hash": hashvalue}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<b>[^<]*</b> == [^<]*<br>\s*<br>', html)

        if match:
            return match.group().split('b>')[1][:-2]
        else:
            return None


class MYINFOSEC:
    name = "myinfosec"
    url = "http://md5.myinfosec.net"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5.myinfosec.net/md5.php"

        # 建立post 参数
        params = {"md5hash": hashvalue}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<center></center>[^<]*<font color=green>[^<]*</font><br></center>', html)

        if match:
            return match.group().split('>')[3][:-6]
        else:
            return None


class MD5_NET:
    name = "md5.net"
    url = "http://md5.net"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://www.md5.net/cracker.php"

        # 建立post 参数
        params = {"hash": hashvalue}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<input type="text" id="hash" size="32" value="[^"]*"/>', html)

        if match:
            return match.group().split('"')[7]
        else:
            return None


class NOISETTE:
    name = "noisette.ch"
    url = "http://md5.noisette.ch"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5.noisette.ch/index.php"

        # 建立post 参数
        params = {"hash": hashvalue}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<p>String to hash : <input name="text" value="[^"]+"/>', html)

        if match:
            return match.group().split('"')[3]
        else:
            return None


class MD5HOOD:
    name = "md5hood"
    url = "http://md5hood.com"
    supported_algorithm = [MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
    # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://md5hood.com/index.php/cracker/crack"

        # 建立post 参数
        params = {"md5": hashvalue,
                  "submit": "Go"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<div class="result_true">[^<]*</div>', html)

        if match:
            return match.group().split('>')[1][:-5]
        else:
            return None


class XANADREL:
    name = "99k.org"
    url = "http://xanadrel.99k.org"
    supported_algorithm = [MD4, MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://xanadrel.99k.org/hashes/index.php?k=search"

        # 建立post 参数
        params = {"hash": hashvalue,
                  "search": "ok"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<p>Hash : [^<]*<br />Type : [^<]*<br />Plain : "[^"]*"<br />', html)

        if match:
            return match.group().split('"')[1]
        else:
            return None


class SANS:
    name = "sans"
    url = "http://isc.sans.edu"
    supported_algorithm = [MD5, SHA1]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://isc.sans.edu/tools/reversehash.html"

        # Build the Headers with a random User-Agent
        headers = {"User-Agent": USER_AGENTS[randint(0, len(USER_AGENTS)) - 1]}

        # 建立post 参数
        response = do_HTTP_request(url, httpheaders=headers)
        html = None
        if response:
            html = response.read()
        else:
            return None
        match = search(r'<input type="hidden" name="token" value="[^"]*" />', html)
        token = ""
        if match:
            token = match.group().split('"')[5]
        else:
            return None

        params = {"token": token,
                  "text": hashvalue,
                  "word": "",
                  "submit": "Submit"}

        # 使用指定的header
        headers["Referer"] = "http://isc.sans.edu/tools/reversehash.html"

        # 进行http 网络查询
        response = do_HTTP_request(url, params, headers)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'... hash [^\s]* = [^\s]*\s*</p><br />', html)

        if match:
            print "hola mundo"
            return match.group().split('=')[1][:-10].strip()
        else:
            return None


class BOKEHMAN:
    name = "bokehman"
    url = "http://bokehman.com"
    supported_algorithm = [MD4, MD5]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        # 创建查询URL
        url = "http://bokehman.com/cracker/"

        # 建立post 参数 from the main page
        response = do_HTTP_request(url)
        html = None
        if response:
            html = response.read()
        else:
            return None
        match = search(r'<input type="hidden" name="PHPSESSID" id="PHPSESSID" value="[^"]*" />', html)
        phpsessnid = ""
        if match:
            phpsessnid = match.group().split('"')[7]
        else:
            return None
        match = search(r'<input type="hidden" name="key" id="key" value="[^"]*" />', html)
        key = ""
        if match:
            key = match.group().split('"')[7]
        else:
            return None

        params = {"md5": hashvalue,
                  "PHPSESSID": phpsessnid,
                  "key": key,
                  "crack": "Try to crack it"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<tr><td>[^<]*</td><td>[^<]*</td><td>[^s]*seconds</td></tr>', html)

        if match:
            return match.group().split('td>')[1][:-2]
        else:
            return None


class GOOG_LI:
    name = "goog.li"
    url = "http://goog.li"
    supported_algorithm = [MD5, MYSQL, SHA1, SHA224, SHA384, SHA256, SHA512, RIPEMD, NTLM, GOST, WHIRLPOOL, LDAP_MD5,
                           LDAP_SHA1]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        hash2 = None
        if alg in [NTLM] and ':' in hashvalue:
            hash2 = hashvalue.split(':')[1]
        else:
            hash2 = hashvalue

        # 确认初始字符 '*'
        if alg == MYSQL and hash2[0] != '*':
            hash2 = '*' + hash2

        # 创建查询URL
        url = "http://goog.li/?q=%s" % (hash2)

        # 进行http 网络查询
        response = do_HTTP_request(url)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<br />cleartext[^:]*: [^<]*<br />', html)

        if match:
            return match.group().split(':')[1].strip()[:-6]
        else:
            return None


class WHREPORITORY:
    name = "Windows Hashes Repository"
    url = "http://nediam.com.mx"
    supported_algorithm = [LM, NTLM]

    def isSupported(self, alg):
        if alg in self.supported_algorithm:
            return True
        else:
            return False

    def crack(self, hashvalue, alg):
        # 检查是否支持该种算法
        if not self.isSupported(alg):
            return None

        hash2 = None
        if ':' in hashvalue:
            if alg == LM:
                hash2 = hashvalue.split(':')[0]
            else:
                hash2 = hashvalue.split(':')[1]
        else:
            hash2 = hashvalue

        # 创建查询URL, parameters and headers
        url = ""
        params = None
        headers = None
        if alg == LM:
            url = "http://nediam.com.mx/winhashes/search_lm_hash.php"
            params = {"lm": hash2,
                      "btn_go": "Search"}
            headers = {"Referer": "http://nediam.com.mx/winhashes/search_lm_hash.php"}
        else:
            url = "http://nediam.com.mx/winhashes/search_nt_hash.php"
            params = {"nt": hash2,
                      "btn_go": "Search"}
            headers = {"Referer": "http://nediam.com.mx/winhashes/search_nt_hash.php"}

        # 进行http 网络查询
        response = do_HTTP_request(url, params, headers)

        # 分析响应
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = search(r'<tr><td align="right">PASSWORD</td><td>[^<]*</td></tr>', html)

        if match:
            return match.group().split(':')[1]
        else:
            return None


CRAKERS = [
		NETMD5CRACK,
		BENRAMSEY,
		GROMWEB,
		HASHCRACKING,
		VICTOROV,
		THEKAINE,
		TMTO,
		REDNOIZE,
		MD5_DB,
		MY_ADDR,
		MD5PASS,
		MD5DECRYPTION,
		MD5CRACK,
		MD5_DECRYPTER,
		AUTHSECUMD5,
		HASHCRACK,
		OPHCRACK,
		C0LLISION,
		CMD5,
		AUTHSECUCISCO7,
		CACIN,
		IBEAST,
		PASSWORD_DECRYPT,
		HASHCHECKER,
		MD5HASHCRACKER,
		PASSCRACKING,
		ASKCHECK,
		FOX21,
		NICENAMECREW,
		JOOMLAAA,
		MD5_LOOKUP,
		SHA1_LOOKUP,
		SHA256_LOOKUP,
		RIPEMD160_LOOKUP,
		MD5_COM_CN,
		DIGITALSUN,
		MYINFOSEC,
		MD5_NET,
		NOISETTE,
		MD5HOOD,
		XANADREL,
		SANS,
		BOKEHMAN,
		GOOG_LI,
		WHREPORITORY ]



########################################################################################################
### 生成方法
########################################################################################################

def configureCookieProcessor (cookiefile='/tmp/searchmyhash.cookie'):
	#设置一个COOKIE 处理去接收不同网站的COOOKIE，并且设置其路径
	
	cookieHandler = LWPCookieJar()
	if cookieHandler is not None:
		if path.isfile (cookiefile):
			cookieHandler.load (cookiefile)
			
		opener = urllib2.build_opener ( urllib2.HTTPCookieProcessor(cookieHandler) )
		urllib2.install_opener (opener)



def do_HTTP_request (url, params={}, httpheaders={}):
	'''
	Send a GET or POST HTTP Request.
	@return: HTTP Response
	'''

	data = {}
	request = None
	
	# If there is parameters, they are been encoded
	if params:
		data = urlencode(params)

		request = urllib2.Request ( url, data, headers=httpheaders )
	else:
		request = urllib2.Request ( url, headers=httpheaders )
		
	# Send the request
	try:
		response = urllib2.urlopen (request)
	except:
		return ""
	
	return response


def printSyntax ():
	"""Print application syntax."""
	
	print """%s 0.3 ( https://github.com/ym2011/crackhash )

Usage: 
------

  python %s <加密算法> 选项


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
         python %s LM   -h 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7
         python %s NTLM -h 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7


以下是有效的选项:
------------------

  -h <hash 值>  如果只是想破解单一的hash值，可以使用该选项 和单一的hash 值

  -f <文件>     如果想破解多个hash 值， 可以使用该选项，文件中每行一个hash值，并且hash 值必须是同一种类型的
                   

使用举例:
---------

  +++破解单一的hash 值
     python %s MD5 -h 098f6bcd4621d373cade4e832627b4f6
   
   
  +++破解带有特定字符的JUNIPER  加密的密码
     python %s JUNIPER -h "\$9\$LbHX-wg4Z"
  
   
  +++破解多个hash 值，其中文件里面必须是一行一个hash值
     python %s MYSQL -f mysqlhashesfile.txt
     

源代码:
-----------------------------------
https://github.com/ym2011/crackhash

""" % ( (sys.argv[0],) * 8 )



def crackHash (algorithm, hashvalue=None, hashfile=None):
	
	global CRAKERS
	
	#已被破解的hashes 存储
	crackedhashes = []
	
	# 检查是否能够被破解?
	cracked = False
	
	# 是否为有效输入.
	if (not hashvalue and not hashfile) or (hashvalue and hashfile):
		return False
	
	#
	hashestocrack = None
	if hashvalue:
		hashestocrack = [ hashvalue ]
	else:
		try:
			hashestocrack = open (hashfile, "r")
		except:
			print "\n无法读取输入的文件： (%s)\n请检查是否存在权限问题\n" % (hashfile)
			return cracked
	
	
	# 尝试破恶疾所有hashes...
	for activehash in hashestocrack:
		hashresults = []
		
		# 规范hash
		activehash = activehash.strip()
		if algorithm not in [JUNIPER, LDAP_MD5, LDAP_SHA1]:
			activehash = activehash.lower()
		
		# 输出提示信息
		print "\n正在破解hash: %s\n请稍等! ^-^ !" % (activehash)


		begin = randint(0, len(CRAKERS)-1)
		
		for i in range(len(CRAKERS)):
			
			# 选择网站去破解这些密文
			cr = CRAKERS[ (i+begin)%len(CRAKERS) ]()
			
			# 检查网站是否支持破解这种加密算法
			if not cr.isSupported ( algorithm ):
				continue
			
			# 正在分析 hash
			print "正在分析 %s (%s)..." % (cr.name, cr.url)
			
			# 破解hash
			result = None
			try:
				result = cr.crack ( activehash, algorithm )
			# 如果有问题，提示出错信息
			except:
				print "\n网络连接出错，请重试！\n或者留言到我的Github ：\nhttps://github.com/ym2011/crackhash"
				if hashfile:
					try:
						hashestocrack.close()
					except:
						pass
				return False
			
			# 看看是否有结果
			cracked = 0
			if result:
				
				# 看看能够支持该种加密算法...
				if algorithm in [MD4, MD5, SHA1,  SHA224, SHA384, SHA256, SHA512, RIPEMD]:
					# 重新计算hash 值，以便和得到的结果进行比较
					h = hashlib.new (algorithm)
					h.update (result)
					
					# 如果计算后的值和通过网站获得的值是一致的，证明破解成果
					if h.hexdigest() == activehash:
						hashresults.append (result)
						cracked = 2
				
				# 检查是否存在 hashlib 算法
				elif algorithm in [LDAP_MD5, LDAP_SHA1]:
					alg = algorithm.split('_')[1]
					ahash =  decodestring ( activehash.split('}')[1] )
					
					# 重新计算hash 值，以便和得到的结果进行比较
					h = hashlib.new (alg)
					h.update (result)
					
					# 如果计算后的值和通过网站获得的值是一致的，证明破解成果
					if h.digest() == ahash:
						hashresults.append (result)
						cracked = 2
				
				# 如果是NTLM hash
				elif algorithm == NTLM or (algorithm == LM and ':' in activehash):
					# 重新计算NTLM Hash值，以便和得到的结果进行比较
					candidate = hashlib.new('md4', result.split()[-1].encode('utf-16le')).hexdigest()
					
					# 如果是LM:NTLM 或者单个 NTLM hash
					if (':' in activehash and candidate == activehash.split(':')[1]) or (':' not in activehash and candidate == activehash):
						hashresults.append (result)
						cracked = 2
				
				# 如果是另外的加密算法，搜索所有的列表中的网站
				else:
					hashresults.append (result)
					cracked = 1
			
			# 是否破解hash?
			if cracked:
				print "\n***** HASH 破解成功!! *****\n破解后的明文是: %s\n" % (result)
				# 如果结果确定下来，便终止
				if cracked == 2:
					break
			else:
				print "...无法在该网站进行破解 %s\n" % (cr.name)
		
		
		# 存储结果，以便后用...
		if hashresults:
			
			
			resultlist = []
			for r in hashresults:
				#if r.split()[-1] not in resultlist:
					#resultlist.append (r.split()[-1])
				if r not in resultlist:
					resultlist.append (r)
					
			finalresult = ""
			if len(resultlist) > 1:
				finalresult = ', '.join (resultlist)
			else:
				finalresult = resultlist[0]
			
			# 破解后的hash存储
			crackedhashes.append ( (activehash, finalresult) )
	
	
	# 文件关闭
	if hashfile:
		try:
			hashestocrack.close ()
		except:
			pass
		
	# Show a resume of all the cracked hashes
	print "\n以下的hash已被破解:\n----------------------------------\n"
	print crackedhashes and "\n".join ("%s -> %s" % (hashvalue, result.strip()) for hashvalue, result in crackedhashes) or "没有破解成功."
	print
	
	return cracked


########################################################################################################
### MAIN CODE
########################################################################################################

def main():
	"""Main method."""


	###################################################
	# Syntax check
	if len (sys.argv) < 4:
		printSyntax()
		sys.exit(1)
	
	else:
		try:
			opts, args = getopt.getopt (sys.argv[2:], "gh:f:")
		except:
			printSyntax()
			sys.exit(1)
	
	
	###################################################
	# Load input parameters
	algorithm = sys.argv[1].lower()
	hashvalue = None
	hashfile  = None
	googlesearch = False
	
	for opt, arg in opts:
		if opt == '-h':
			hashvalue = arg
		elif opt == '-f':
			hashfile = arg
	
	
	###################################################
	# Configure the Cookie Handler
	configureCookieProcessor()
	
	# Initialize PRNG seed
	seed()
	
	cracked = 0
	
	
	###################################################
	# Crack the hash/es
	cracked = crackHash (algorithm, hashvalue, hashfile)
	
	###################################################
	# App is finished
	sys.exit()



if __name__ == "__main__":
    main()

