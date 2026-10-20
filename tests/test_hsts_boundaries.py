import unittest
from auditor import audit


class HstsBoundaryTests(unittest.TestCase):
    def inactive(self, value):
        report=audit([('Strict-Transport-Security','max-age='+value)])
        return 'HSTS_INACTIVE' in {finding['rule'] for finding in report['findings']}

    def test_unicode_digits_are_invalid_without_crashing(self):
        for value in ('²','１２３','١٢٣'):
            with self.subTest(value=value):
                self.assertTrue(self.inactive(value))

    def test_long_positive_decimal_does_not_require_integer_conversion(self):
        self.assertFalse(self.inactive('9'*5000))

    def test_zero_and_leading_zero_values(self):
        self.assertTrue(self.inactive('0'*5000))
        self.assertFalse(self.inactive('0'*5000+'1'))

    def test_invalid_numeric_forms(self):
        for value in ('','-1','+1','1.5','1e6','1 2'):
            with self.subTest(value=value):
                self.assertTrue(self.inactive(value))
