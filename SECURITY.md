# Security Policy

This project is an educational offline lab, not a production authentication system.
Only audit passwords and hashes that you own or are authorized to test.

For ordinary bugs, open an issue with a synthetic reproduction. Do not put real
passwords, private hashes, or recovered credentials into an issue or pull request.
For a sensitive vulnerability, use GitHub private vulnerability reporting if enabled.
If no private reporting channel is available, open a minimal issue requesting one
without disclosing exploit details or sensitive data.

Use raw SHA-256 only for the supplied learning exercise. Password records use
salted PBKDF2. Never load or publish someone else's password material for this lab.
