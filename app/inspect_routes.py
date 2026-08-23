from server import app
for rule in app.url_map.iter_rules():
    print(f"{rule.endpoint}: {rule.rule} {rule.methods}")
