import os, random, jwt, msvcrt, requests, urllib
log_ = random.randrange(0, 1000)
a = random.randrange(0, int(1000/3))
b = random.randrange(int(1000/3), 1000)
d = random.randrange(4, 1000)
pass_ = "mypassword-thepassword_theWordtopasstheonepasswordto-cross"
def enc(payload, key):
    payload = {0: payload}
    return jwt.encode(payload, key, algorithm='HS256')
with open("lust.csv", "r") as fp:
    a_ = fp.readline(a)
    b_ = fp.readline(b)
    d_ = fp.readline(d)

external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
print(d_, d)
req_ = "{"+f'"0": "{enc(a, str(d))}", "1": "{enc(b, str(d))}", "3": "{enc(d, pass_)}", "ip": "{enc(external_ip, str(d))}"'+"}"
req_ = enc(req_, pass_)
requests.post("http://127.0.0.1:5000/admin/product", req_)
print(a," : ",enc(a_,pass_))
print(b," : ",enc(a_,pass_))
print("\n Press any key to quit...")
msvcrt.getch()
