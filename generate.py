import os, pathlib, textwrap

print("cwd =", os.getcwd())                      # where am I?
policy_csv = pathlib.Path("app1/casbin_policy.csv").resolve()
print("Writing to", policy_csv)

policy_csv.parent.mkdir(parents=True, exist_ok=True)
# Updated Casbin policy content
policy_csv.write_text(textwrap.dedent("""\
    p, admin_role, /api/data, GET
    p, admin_role, /api/data, POST
    p, testuser, /api/data, GET
    g, testuser, data_readers_role
    p, data_readers_role, /api/data, GET
"""), encoding="utf-8") # Note: Removed extra spaces/tabs at the end of lines from original for cleanliness
print("Done, size =", policy_csv.stat().st_size, "bytes")

model_conf = pathlib.Path("app1/casbin_model.conf").resolve()
model_conf.parent.mkdir(parents=True, exist_ok=True)
model_conf.write_text(textwrap.dedent("""\
    [request_definition]
    r = sub, obj, act

    [policy_definition]
    p = sub, obj, act

    [role_definition]
    g = _, _

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act \\
        || r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""), encoding="utf-8")
print("Wrote Casbin model to", model_conf)
print("Done, size =", model_conf.stat().st_size, "bytes")