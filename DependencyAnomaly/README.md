Usage:
Install required libraries with: pip install -r requirements.txt
To demonstrate the detection logic without requiring a live codebase, this repository includes two dummy manifests: sbom_previous.json and sbom_current.json.
Ensure these two files are in the same directory as the script, then execute: python dependency.py
The expected output is ALERT: my-company-internal-utils@1.0.0 score=11 reasons=['Private Package', 'Brand New Package']
where my-company-internal-utils is the internal package meant to trigger a flag.