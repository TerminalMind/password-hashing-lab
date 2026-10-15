# Password Cracking and Hashing Lab

Offline educational Python project with optional Hashcat and John the Ripper exercises.
Use the synthetic sample or hashes you own/have permission to audit. No network
connections, login attempts, or third-party Python packages are required.

## Quick start

Install Python 3.11+, extract this folder, and open a terminal inside it:

```text
python lab.py demo
python lab.py crack
python lab.py hash
python lab.py verify
python -m unittest discover -s tests -v
```

On Windows try `py` if `python` is unavailable. On Linux/macOS use `python3`.
No pip install step is needed. Hash/verify prompt for a practice password with
hidden input; use a normal terminal. The hash command creates
`password_record.json` without overwriting an existing file. For a second record:

```text
python lab.py hash --out password_record_2.json
python lab.py verify --record password_record_2.json
```

## Concepts

| Concept | Meaning |
|---|---|
| Hash | One-way digest, not encryption |
| Brute force | Enumerate candidates, hash each and compare |
| Dictionary search | Try candidates from a wordlist |
| Salt | Fresh random value per password record, stored with the digest |
| Password KDF | Deliberately expensive computation that slows guessing |

Salts need not be secret. Different salts make identical passwords produce different
records and prevent reuse of precomputed results across those records. A salt does
not make a weak password unguessable or make a fast hash expensive.
Raw SHA-256, including a simple salted SHA-256 construction, is unsuitable as a
standalone password-storage scheme because it is too fast.

The lab uses SHA-256 only for the cracking example. Password records use
PBKDF2-HMAC-SHA256, a 16-byte random salt, a 32-byte digest and 600,000 iterations.
This is a lab work factor, not a universal performance guarantee. Production
applications should use a maintained password library and an appropriate current
policy. Argon2id is another password KDF to study; it is not implemented here.

## Python brute-force experiment

The supplied target is SHA-256 of `cab1`, encoded in UTF-8 without a newline.

```text
python lab.py crack --hash-file sample_hash.txt --alphabet abc123 --max-length 4 --seconds 10
```

Expected output includes `status: found` and `password: cab1`. Search length is
1 through 4, in alphabet order: 6 + 6^2 + 6^3 + 6^4 = 1,554 possible candidates.
Try alphabet `abc`: no match is possible because the password contains `1`.

Limits: at most 1,000,000 possible candidates, length 1–8, and 60 seconds.
Results distinguish found, exhausted, and time_limit. Empty passwords are excluded.
Failure to find a match does not prove security. Exit codes: 0 success/found,
1 mismatch/exhausted/timeout, 2 invalid input/error.

`demo` also produces two salted records for the same password, verifies correct
and incorrect passwords, and compares three-run average derivation timings.
These CPU timings are illustrative, not reliable GPU cracking estimates.
Verification uses the saved salt/work factor and `hmac.compare_digest`.

## Hashcat (optional)

Official download: https://hashcat.net/hashcat/
A supported compute backend is needed. Run from this folder with Hashcat on PATH
(Windows may use `hashcat.exe`). Four-word dictionary exercise:

```text
hashcat -m 1400 -a 0 sample_hash.txt sample_words.txt --potfile-path lab_hashcat.potfile
hashcat -m 1400 sample_hash.txt --show --potfile-path lab_hashcat.potfile
```

Small exhaustive mask, exactly four characters from `abc123`:

```text
hashcat -m 1400 -a 3 sample_hash.txt -1 abc123 "?1?1?1?1" --potfile-disable
```

1400 is raw SHA2-256, attack mode 0 is dictionary, mode 3 is mask search.
The mask has 6^4 = 1,296 candidates and does not try shorter lengths.
Pot-file reuse is disabled for the mask so the earlier result does not skip it.
If no compatible device is detected, use the Python exercise; do not bypass
backend problems with `--force`.

## John the Ripper (optional)

Use a Jumbo build with raw SHA-256 support: https://www.openwall.com/john/

```text
john --format=raw-sha256 --wordlist=sample_words.txt --pot=lab_john.pot sample_hash.txt
john --format=raw-sha256 --show --pot=lab_john.pot sample_hash.txt
```

Your installation may require `./john` or `john.exe`. Non-Jumbo versions may lack
this format. Use --show if the hash was already recovered in a previous run.
The custom pot file keeps lab results separate.

Neither set of raw SHA-256 commands accepts the PBKDF2 JSON records: those use this
lab's application-specific format and are verified by `lab.py`.

## Suggested report

1. Record candidate count, attempts, time and search outcome.
2. Explain why removing `1` from the alphabet prevents success.
3. Compare two salts/digests for the same password.
4. Explain why salts prevent shared work while PBKDF2 makes individual guesses expensive.
5. Compare exhaustive and dictionary searches.
6. Explain that hashes are guessed and checked, not decrypted.

## Contents and tests

- lab.py: complete Python lab.
- sample_hash.txt: synthetic hash of cab1.
- sample_words.txt: four synthetic candidates.
- tests/test_lab.py: six automated tests.
- .gitignore: excludes password records and result/pot files.

Tests cover a known SHA-256 vector, Unicode verification, salt uniqueness, successful
and exhausted searches, timeout/search caps, and invalid record work factors.
Validation on Kali Linux: all six Python tests passed; correct-password verification returned MATCH and incorrect-password verification returned NO MATCH. John the Ripper recovered the synthetic password cab1 (1 hash cracked, 0 left). Hashcat was attempted but could not start because no compatible compute runtime was detected; Hashcat recovery is not yet verified.
Do not publish private hashes, passwords, or result files to GitHub.

## Official references

- https://hashcat.net/wiki/doku.php?id=example_hashes
- https://hashcat.net/wiki/doku.php?id=mask_attack
- https://www.openwall.com/john/doc/EXAMPLES.shtml
- https://www.openwall.com/john/doc/
- https://docs.python.org/3/library/hashlib.html
