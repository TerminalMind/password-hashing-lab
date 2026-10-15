import unittest
from unittest.mock import patch
import lab

class LabTests(unittest.TestCase):
    def test_known_sha256(self):
        self.assertEqual(lab.sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_salts_and_verification(self):
        a, b = lab.password_record('café', 10000), lab.password_record('café', 10000)
        self.assertNotEqual(a['salt'], b['salt'])
        self.assertNotEqual(a['digest'], b['digest'])
        self.assertTrue(lab.verify('café', a))
        self.assertFalse(lab.verify('wrong', a))

    def test_found(self):
        r = lab.brute_force(lab.sha256('ba'), 'ab', 2)
        self.assertEqual(r['password'], 'ba')
        self.assertEqual(r['attempts'], 5)
        self.assertEqual(r['search_space'], 6)

    def test_exhausted(self):
        self.assertEqual(lab.brute_force(lab.sha256('z'), 'ab', 2)['status'], 'exhausted')

    def test_limits(self):
        for args in [('bad', 'ab', 2), (lab.sha256('x'), 'aa', 2),
                     (lab.sha256('x'), 'abcdefghijklmnopqrstuvwxyz', 8)]:
            with self.assertRaises(ValueError): lab.brute_force(*args)
        with patch('lab.time.perf_counter', side_effect=[0, 11, 12]):
            self.assertEqual(lab.brute_force(lab.sha256('a'))['status'], 'time_limit')

    def test_bad_record(self):
        a = lab.password_record('test', 10000)
        a['iterations'] = 999999999
        with self.assertRaises(ValueError): lab.verify('test', a)

if __name__ == '__main__': unittest.main()
