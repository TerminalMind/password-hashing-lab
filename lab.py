"""Offline password hashing and bounded search lab; Python standard library only."""
import argparse
import getpass
import hashlib
import hmac
import itertools
import json
import secrets
import time
from pathlib import Path

ITERATIONS = 600_000
MAX_CANDIDATES = 1_000_000


def sha256(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def password_record(password, iterations=ITERATIONS):
    if not isinstance(iterations, int) or not 10_000 <= iterations <= 2_000_000:
        raise ValueError('Iterations must be 10,000–2,000,000')
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return {'algorithm': 'pbkdf2-sha256', 'iterations': iterations,
            'salt': salt.hex(), 'digest': digest.hex()}


def verify(password, record):
    if record.get('algorithm') != 'pbkdf2-sha256':
        raise ValueError('Unsupported record algorithm')
    count = record.get('iterations')
    if type(count) is not int or not 10_000 <= count <= 2_000_000:
        raise ValueError('Invalid iteration count')
    salt, digest = bytes.fromhex(record['salt']), bytes.fromhex(record['digest'])
    if len(salt) != 16 or len(digest) != 32:
        raise ValueError('Invalid salt or digest length')
    result = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, count)
    return hmac.compare_digest(result, digest)


def brute_force(target, alphabet='abc123', max_length=4, seconds=10):
    if len(target) != 64 or any(c not in '0123456789abcdefABCDEF' for c in target):
        raise ValueError('Expected one hexadecimal SHA-256 digest')
    if not alphabet or len(set(alphabet)) != len(alphabet):
        raise ValueError('Alphabet must be nonempty and contain unique characters')
    if not 1 <= max_length <= 8 or not 0 < seconds <= 60:
        raise ValueError('Length must be 1–8; time limit must be >0 and <=60 seconds')
    space = sum(len(alphabet)**n for n in range(1, max_length+1))
    if space > MAX_CANDIDATES:
        raise ValueError(f'Search space {space:,} exceeds lab cap of {MAX_CANDIDATES:,}')
    start, attempts, found, status = time.perf_counter(), 0, None, 'exhausted'
    for length in range(1, max_length+1):
        for chars in itertools.product(alphabet, repeat=length):
            if time.perf_counter()-start >= seconds:
                return {'status': 'time_limit', 'password': None, 'attempts': attempts,
                        'search_space': space, 'seconds': time.perf_counter()-start}
            candidate = ''.join(chars)
            attempts += 1
            if hmac.compare_digest(sha256(candidate), target.lower()):
                found, status = candidate, 'found'
                break
        if found is not None:
            break
    return {'status': status, 'password': found, 'attempts': attempts,
            'search_space': space, 'seconds': time.perf_counter()-start}


def demo():
    password = 'cab1'
    print('Sample password:', password)
    print('Raw SHA-256:', sha256(password))
    print('Brute force:', json.dumps(brute_force(sha256(password)), indent=2))
    a, b = password_record(password), password_record(password)
    print('Same password, two independently salted records:')
    print(json.dumps([a, b], indent=2))
    print('Correct password accepted:', verify(password, a))
    print('Wrong password accepted:', verify('wrong', a))
    # Each timing measures one derivation, not comparable real-world cracking throughput.
    for label, fn in [('SHA-256', lambda: sha256(password)),
                      ('PBKDF2-SHA256', lambda: hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(a['salt']), ITERATIONS))]:
        begin = time.perf_counter()
        for _ in range(3): fn()
        print(f'{label}: mean {(time.perf_counter()-begin)/3:.8f} seconds/derivation (3 runs; illustrative only)')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('demo')
    s = sub.add_parser('hash'); s.add_argument('--out', default='password_record.json')
    s = sub.add_parser('verify'); s.add_argument('--record', default='password_record.json')
    s = sub.add_parser('crack'); s.add_argument('--hash-file', default='sample_hash.txt')
    s.add_argument('--alphabet', default='abc123'); s.add_argument('--max-length', type=int, default=4)
    s.add_argument('--seconds', type=float, default=10)
    args = p.parse_args()
    try:
        if args.command == 'demo': demo()
        elif args.command == 'hash':
            password = getpass.getpass('Practice password (input hidden): ')
            # Exclusive create avoids overwriting an existing password record.
            with open(args.out, 'x', encoding='utf-8') as f:
                json.dump(password_record(password), f, indent=2)
            print('Saved salted record:', args.out)
        elif args.command == 'verify':
            record = json.loads(Path(args.record).read_text(encoding='utf-8'))
            if not isinstance(record, dict): raise ValueError('Expected a JSON object')
            ok = verify(getpass.getpass('Password (input hidden): '), record)
            print('MATCH' if ok else 'NO MATCH')
            return 0 if ok else 1
        else:
            result = brute_force(Path(args.hash_file).read_text(encoding='utf-8').strip(),
                                 args.alphabet, args.max_length, args.seconds)
            print(json.dumps(result, indent=2))
            return 0 if result['status'] == 'found' else 1
    except (OSError, ValueError, KeyError, TypeError) as e:
        p.exit(2, f'Error: {e}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
