import json
import requests

REGISTRY_PATH = "model_registry.json" #replace with registry
HF_API = "https://huggingface.co/api"


def load_registry():
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def verify_author_exists(author):
    try:
        r = requests.get(f"{HF_API}/users/{author}", timeout=5)
        if r.status_code == 200:
            return True
        if r.status_code == 404:
            return False
        return None
    except requests.RequestException:
        return None


def check_namespace_integrity(model_id, expected_author):
    try:
        r = requests.get(f"{HF_API}/models/{model_id}", timeout=5)
        if r.status_code == 404:
            return False, "MODEL_DELETED", None
        data = r.json()
        current_author = data.get("author")
        if current_author != expected_author:
            return False, "NAMESPACE_TRANSFERRED", current_author
        return True, None, current_author
    except requests.RequestException as e:
        return None, "REQUEST_FAILED", str(e)


def audit_entry(entry):
    model_id = entry["model_id"]
    expected_author = entry["author"]
    flags = []

    author_exists = verify_author_exists(expected_author)
    if author_exists is False:
        flags.append(
            f"AUTHOR_DELETED: '{expected_author}' no longer exists — namespace is reclaimable"
        )
    elif author_exists is None:
        flags.append(f"AUTHOR_UNKNOWN: Could not verify '{expected_author}' account status")

    ok, reason, detail = check_namespace_integrity(model_id, expected_author)
    if reason == "MODEL_DELETED":
        flags.append(f"MODEL_DELETED: {model_id} not found — namespace may have been dropped")
    elif reason == "NAMESPACE_TRANSFERRED":
        flags.append(
            f"NAMESPACE_TRANSFERRED: expected author='{expected_author}', found='{detail}'"
        )
    elif reason == "REQUEST_FAILED":
        flags.append(f"REQUEST_FAILED: could not reach HuggingFace API — {detail}")

    return flags


if __name__ == "__main__":
    registry = load_registry()
    print(f"Auditing {len(registry['models'])} registered model(s)...\n")

    any_alerts = False
    for entry in registry["models"]:
        flags = audit_entry(entry)
        if flags:
            any_alerts = True
            for flag in flags:
                print(f"ALERT [{entry['model_id']}]: {flag}")

    if not any_alerts:
        print("All models passed audit.")