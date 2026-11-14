import unittest

from authzdiff.scope import in_scope


class ScopeTests(unittest.TestCase):
    def test_exact_host_on_default_port(self):
        self.assertTrue(in_scope("https://api.example.com/v1/me", ("api.example.com",)))
        self.assertTrue(in_scope("http://api.example.com/", ("api.example.com",)))

    def test_host_without_port_does_not_cover_other_ports(self):
        self.assertFalse(in_scope("https://api.example.com:8443/", ("api.example.com",)))
        self.assertFalse(in_scope("http://127.0.0.1:8099/", ("127.0.0.1",)))

    def test_explicit_and_wildcard_port(self):
        self.assertTrue(in_scope("https://api.example.com:8443/", ("api.example.com:8443",)))
        self.assertFalse(in_scope("https://api.example.com/", ("api.example.com:8443",)))
        self.assertTrue(in_scope("https://api.example.com:8443/", ("api.example.com:*",)))

    def test_wildcard_subdomain(self):
        scope = ("*.lab.test",)
        self.assertTrue(in_scope("https://app.lab.test/", scope))
        self.assertFalse(in_scope("https://lab.test/", scope))
        self.assertFalse(in_scope("https://evil-lab.test/", scope))
        self.assertFalse(in_scope("https://app.lab.test.attacker.test/", scope))

    def test_userinfo_does_not_fool_the_check(self):
        self.assertFalse(in_scope("https://api.example.com@attacker.test/", ("api.example.com",)))

    def test_other_schemes_and_garbage_are_rejected(self):
        scope = ("*",)
        self.assertFalse(in_scope("ftp://api.example.com/", scope))
        self.assertFalse(in_scope("file:///etc/passwd", scope))
        self.assertFalse(in_scope("http://host:99999/", scope))
        self.assertFalse(in_scope("not a url", scope))

    def test_ipv6_and_case(self):
        self.assertTrue(in_scope("http://[::1]:8099/", ("[::1]:8099",)))
        self.assertTrue(in_scope("https://API.Example.com/", ("api.EXAMPLE.com",)))


if __name__ == "__main__":
    unittest.main()
