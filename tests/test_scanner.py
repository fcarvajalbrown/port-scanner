"""Tests for PortScanner."""

import unittest
from unittest.mock import patch, MagicMock
from src.utils.scanner import PortScanner


class TestPortScanner(unittest.TestCase):
    """Test suite for PortScanner."""

    def test_load_domains(self):
        """Ensure domains are loaded from config."""
        scanner = PortScanner()
        self.assertIsInstance(scanner.domains, list)
        self.assertGreater(len(scanner.domains), 0)

    def test_resolve_domain_failure(self):
        """Ensure failed DNS resolution returns None for IP."""
        scanner = PortScanner()
        _, _, ip = scanner._resolve_domain({'id': 'test', 'host': 'this.domain.does.not.exist.invalid'})
        self.assertIsNone(ip)

    def test_port_mode_default(self):
        """Ensure default port mode is top100."""
        scanner = PortScanner()
        self.assertEqual(scanner.port_mode, 'top100')

    def test_port_mode_full(self):
        """Ensure full port mode is set correctly."""
        scanner = PortScanner(port_mode='full')
        self.assertEqual(scanner.port_mode, 'full')


if __name__ == '__main__':
    unittest.main()