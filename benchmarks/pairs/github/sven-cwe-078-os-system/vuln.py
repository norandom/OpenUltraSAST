# Provenance: SVEN train CWE-78 function pair from
# https://github.com/Internet-of-People/titania-os/commit/9b7805119938343fcac9dc929d8882f1d97cf14a
# file vuedj/configtitania/views.py function add_user
import crypt
import os


def add_user(username, password):
    encPass = crypt.crypt(password, "22")
    os.system("useradd -G docker,wheel -p " + encPass + " " + username)
