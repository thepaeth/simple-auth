from passlib.context import  CryptContext
import json, os

pwd_context=CryptContext(schemes=["bcrypt"],deprecated="auto")
def  get_password_hash(password):
    return pwd_context.hash(password)

userLists = ['user1', 'user2', 'user3', 'user4', 'user5']
passphrase = os.environ.get('passphrase', 'abc1234')

user_data = {}
for u in userLists:
    user_data[u] = {
        'userName': u,
        'fName': u,
        'lName': '{}Last'.format(u),
        'email': '{}@mail.com'.format(u),
        'password': get_password_hash('{}#{}'.format(u, passphrase)),
        'org': 'abc'
    }

json_object = json.dumps(user_data, indent=2)
with open("./users/sample.json", "w") as outfile:
    outfile.write(json_object)