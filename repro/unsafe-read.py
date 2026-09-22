"""loads_unsafe 这一族入口的两段现象，四行读数。

跑法：PYTHONPATH=src .venv/bin/python repro/unsafe-read.py
"""

import pickle
from datetime import datetime, timezone

from freezegun import freeze_time

from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer

KEY = "secret-key"
TS = datetime(2011, 6, 24, tzinfo=timezone.utc)


def show(label, fn):
    try:
        print("   ", label, "->", fn())
    except Exception as e:
        print("   ", label, "-> RAISED {}.{}: {}".format(
            type(e).__module__, type(e).__name__, e))


print("(a) 签名校验过关、负载解不开")
writer = URLSafeSerializer(KEY, serializer=pickle)
reader = URLSafeSerializer(KEY)
token = writer.dumps({"id": 42})
print("    token:", repr(token))
print("    签名层判定:", reader.make_signer().validate(token))
show("loads_unsafe()", lambda: reader.loads_unsafe(token))
show("loads()", lambda: reader.loads(token))

print("(b) 过期 token")
s = URLSafeTimedSerializer(KEY)
with freeze_time(TS):
    tok = s.dumps({"id": 42})
print("    签名层判定:", s.make_signer().validate(tok))
show("loads_unsafe(max_age=10)", lambda: s.loads_unsafe(tok, max_age=10))
show("loads_unsafe()", lambda: s.loads_unsafe(tok))
show("loads(max_age=10)", lambda: s.loads(tok, max_age=10))
