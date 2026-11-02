"""Bouwt index.html: zet de weekdata versleuteld in template.html.

Gebruik:  WACHTWOORD='...' python3 build.py data.json
data.json bevat de leesbare weekdata en wordt NOOIT gecommit (staat in .gitignore).
"""
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 310000
here = os.path.dirname(os.path.abspath(__file__))
pw = os.environ.get("WACHTWOORD")
if not pw:
    sys.exit("Zet het wachtwoord in de omgevingsvariabele WACHTWOORD.")
data = json.load(open(sys.argv[1], encoding="utf-8"))
saltfile = os.path.join(here, "salt.txt")
if not os.path.exists(saltfile):
    open(saltfile, "w").write(base64.b64encode(os.urandom(16)).decode())
salt = base64.b64decode(open(saltfile).read().strip())  # vast, zodat "onthoud mij" elke week blijft werken
iv = os.urandom(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode())
ct = AESGCM(key).encrypt(iv, json.dumps(data, ensure_ascii=False).encode(), None)
b = lambda x: base64.b64encode(x).decode()
payload = json.dumps({"salt": b(salt), "iv": b(iv), "iter": ITER, "ct": b(ct)})
tpl = open(os.path.join(here, "template.html"), encoding="utf-8").read()
open(os.path.join(here, "index.html"), "w", encoding="utf-8").write(tpl.replace("__PAYLOAD__", payload))
print("index.html gebouwd")
