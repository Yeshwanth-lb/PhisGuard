import os, ast
p = os.path.join("app", "parser", "email_parser.py")
with open(p) as f:
    src = f.read()
old_att = "        \"attachments\": attachments,"
new_att = old_att + chr(10) + "        ''attachment_hashes'': [a('sha256') for a in attachments],"
updated = src.replace(old_att, new_att)
with open(p, "w") as f:
    f.write(updated)
ast.parse(updated)
print("parser updated OK")
