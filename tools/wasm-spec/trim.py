"""Trims a json-from-wast output: the source path becomes the file name, and the files of refused
features keep only what loading checks (their actions could never run), with the modules they
no longer reference deleted. Usage: trim.py <json> [refused]"""
import json, os, sys

path, refused = sys.argv[1], len(sys.argv) > 2 and sys.argv[2] == "refused"
with open(path) as f:
    doc = json.load(f)
doc["source_filename"] = os.path.basename(doc["source_filename"])
if refused:
    keep = ("module", "assert_invalid", "assert_malformed", "assert_unlinkable",
            "assert_uninstantiable", "register")
    # An assert_trap with a module (not an action) is an instantiation failure: kept too.
    doc["commands"] = [c for c in doc["commands"] if c["type"] in keep or "filename" in c]
    used = {c["filename"] for c in doc["commands"] if "filename" in c}
    d = path[: -len(".json")]
    for n in os.listdir(d):
        if n not in used:
            os.remove(os.path.join(d, n))
with open(path, "w") as f:
    json.dump(doc, f, separators=(",", ":"))
    f.write("\n")
