"""Synthetic transport tests: no network or credentials."""
import io
import os
import ssl
import unittest
import urllib.error
from unittest.mock import patch
import security_gate as subject


class TransportTests(unittest.TestCase):
    def test_only_registered_private_hosts_receive_the_configured_route(self):
        class Connection:
            def __init__(self,host,**kwargs):self.host=host
        with patch.dict(os.environ,{'INTERNAL_PROXY_ADDRESS':'gateway.invalid'}), \
             patch.object(subject.http.client,'HTTPSConnection',Connection),patch.object(subject.socket,'create_connection') as connect:
            conn=subject.PrivateServiceHTTPS.connection('vault.int.downops.win')
            conn._create_connection(('vault.int.downops.win',443),timeout=7)
            self.assertEqual(('gateway.invalid',443),connect.call_args.args[0])
            self.assertEqual(7,connect.call_args.args[1])
            self.assertFalse(hasattr(subject.PrivateServiceHTTPS.connection('example.invalid'),'_create_connection'))
        handler=subject.PrivateServiceHTTPS()
        self.assertTrue(handler._context.check_hostname)
        self.assertEqual(ssl.CERT_REQUIRED,handler._context.verify_mode)

    def test_transient_resolution_failure_is_bounded_and_can_recover(self):
        with patch.object(subject.urllib.request,'build_opener') as opener,patch.object(subject.time,'sleep') as sleep:
            opener.return_value.open.side_effect=[urllib.error.URLError('synthetic unavailable'),io.BytesIO(b'{"ok":true}')]
            self.assertEqual({'ok':True},subject.request('https://example.invalid'))
            self.assertEqual(2,opener.return_value.open.call_count)
            sleep.assert_called_once_with(1)

    def test_exhausted_transport_failures_are_not_success(self):
        with patch.object(subject.urllib.request,'build_opener') as opener,patch.object(subject.time,'sleep'):
            opener.return_value.open.side_effect=urllib.error.URLError('synthetic unavailable')
            with self.assertRaises(RuntimeError):subject.request('https://example.invalid')
            self.assertEqual(3,opener.return_value.open.call_count)

    def test_auth_failures_and_certificate_failures_are_not_retried(self):
        errors=[urllib.error.HTTPError('https://example.invalid',403,'synthetic',{},None),
                urllib.error.URLError(ssl.SSLCertVerificationError('synthetic invalid CA'))]
        for error in errors:
            with patch.object(subject.urllib.request,'build_opener') as opener,patch.object(subject.time,'sleep') as sleep:
                opener.return_value.open.side_effect=error
                with self.assertRaises(RuntimeError):subject.request('https://example.invalid')
                self.assertEqual(1,opener.return_value.open.call_count)
                sleep.assert_not_called()


if __name__=='__main__':unittest.main()
