### PoC: Path Traversal in CPython's `multissltests.py`

This repository contains a self-contained Proof-of-Concept (PoC) script that demonstrates a path traversal vulnerability in the "Tools/ssl/multissltests.py" test suite of the CPython repo. The vulnerability exists in a test script that doesn't properly sanitize archive member names during extraction, allowing a malicious tarball to write files to an unintended location.

### Vulnerability Details

* **Vulnerable Component**: Tools/ssl/multissltests.py
* **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory 'Path Traversal')
* **Vulnerability Description**: The _unpack_src method of the AbstractBuilder class used tarfile.extractall() without a filter or proper path validation. This allowss an attacker to craft a malicious tar archive that, when processed by the script, could write a file to an arbitrary location on the filesystem.

### PoC Usage

This script automatically creates a malicious tarball and attempts to trigger the vulnerability. It requires no external dependencies beyond the CPython source tree.

* **One-Click Execution**:

    ```bash
    python3 PTpoc.py -m /path/
    ```

* **Arguments**:

    * `-m, --module`: Specify the path to the `multissltests.py` file. The script will attempt to auto-detect the path if not provided (but I suggests specifying it).
    * `-o, --output`: Specify a custom output directory for the sandbox (completely optional).

### Script Logic

1.  **Import the Vulnerable Code**: It dynamically imports the actual `multissltests.py` file from the CPython source tree.
2.  **Craft a Malicious Tarball**: It creates a compressed tar archive containing a file with a path traversal payload (e.g., `openssl-3.1.8/../../PWNED.txt`).
3.  **Trigger the Vulnerability**: It calls the `_unpack_src()` method, which unknowingly extracts the malicious file to a location outside the intended build directory.
4.  **Verify and Report**: It checks for the presence of the escaped file and generates a report with a clear pass/fail status, along with contextual information and an evidence folder.

### Before/After Patch
<img width="856" height="672" alt="image" src="https://github.com/user-attachments/assets/298e0ff8-79c8-44de-8221-69a00a115a8a" />

