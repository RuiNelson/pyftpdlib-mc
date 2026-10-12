# Copyright (C) 2007 Giampaolo Rodola' <g.rodola@gmail.com>.
# Use of this source code is governed by MIT license that can be
# found in the LICENSE file.

"""Tests for FTPMC (multiple data connections, see draft-ftpmc)."""

import ftplib
import os
import select
import socket
import struct
import threading

import pytest

from pyftpdlib.handlers.ftp.mc import MCPassive

from . import GLOBAL_TIMEOUT
from . import PASSWD
from . import USER
from . import FtpdThreadWrapper
from . import PyftpdlibTestCase
from . import close_client


def stripe_split(data, n, stripe):
    """Split data into what each connection carries."""
    parts = [bytearray() for _ in range(n)]
    for i in range(0, len(data), stripe):
        parts[(i // stripe) % n] += data[i : i + stripe]
    return parts


def stripe_join(parts, stripe):
    """Reassemble the data stream (draft-ftpmc Section 6.2); return
    None if the per-connection data is inconsistent.
    """
    n = len(parts)
    pos = [0] * n
    out = bytearray()
    i = 0
    while True:
        k = i % n
        chunk = parts[k][pos[k] : pos[k] + stripe]
        pos[k] += len(chunk)
        out += chunk
        if len(chunk) < stripe:
            break
        i += 1
    if any(pos[k] != len(parts[k]) for k in range(n)):
        return None
    return bytes(out)


def recv_all(sock):
    chunks = []
    while True:
        data = sock.recv(65536)
        if not data:
            return b"".join(chunks)
        chunks.append(data)


class TestMC(PyftpdlibTestCase):
    server_class = FtpdThreadWrapper

    def setUp(self):
        super().setUp()
        self.server = self.server_class()
        self.server.start()
        self.client = ftplib.FTP(timeout=GLOBAL_TIMEOUT)
        self.client.connect(self.server.host, self.server.port)
        self.client.login(USER, PASSWD)
        self.client.voidcmd("TYPE I")
        self.testfn = self.get_testfn()
        self.socks = []

    def tearDown(self):
        for s in self.socks:
            s.close()
        close_client(self.client)
        self.server.stop()
        MCPassive.timeout = 30
        super().tearDown()

    # --- helpers

    def enable(self, n, stripe=None):
        cmd = f"OPTS MC {n}" + (f" {stripe}" if stripe else "")
        parts = self.client.sendcmd(cmd).split()
        return int(parts[2]), int(parts[3])

    def mpsv(self):
        resp = self.client.sendcmd("MPSV")
        assert resp.startswith("224"), resp
        inner = resp[resp.index("(") + 1 : resp.rindex(")")]
        return [int(p) for p in inner.split("|")[3].split(",")]

    def connect_set(self, ports):
        socks = []
        for port in ports:
            s = socket.create_connection(
                (self.server.host, port), GLOBAL_TIMEOUT
            )
            socks.append(s)
            self.socks.append(s)
        return socks

    def receive_set(self, socks):
        parts = [None] * len(socks)

        def run(k, s):
            parts[k] = recv_all(s)

        threads = [
            threading.Thread(target=run, args=(k, s))
            for k, s in enumerate(socks)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return parts

    def send_set(self, socks, parts):
        for s, part in zip(socks, parts):
            s.sendall(part)
            s.close()

    def retr(self, data, n, stripe):
        with open(self.testfn, "wb") as f:
            f.write(data)
        n, stripe = self.enable(n, stripe)
        socks = self.connect_set(self.mpsv())
        resp = self.client.sendcmd("RETR " + self.testfn)
        assert resp.startswith("125"), resp
        parts = self.receive_set(socks)
        self.client.voidresp()
        assert stripe_join(parts, stripe) == data
        assert [len(p) for p in parts] == [
            len(p) for p in stripe_split(data, n, stripe)
        ]

    def stor(self, data, n, stripe):
        n, stripe = self.enable(n, stripe)
        socks = self.connect_set(self.mpsv())
        resp = self.client.sendcmd("STOR " + self.testfn)
        assert resp.startswith("125"), resp
        self.send_set(socks, stripe_split(data, n, stripe))
        self.client.voidresp()
        with open(self.testfn, "rb") as f:
            assert f.read() == data

    # --- negotiation

    def test_feat(self):
        assert " MC 16" in self.client.sendcmd("FEAT").splitlines()

    def test_opts(self):
        assert self.client.sendcmd("OPTS MC 3") == "200 MC 3 4096"
        assert self.client.sendcmd("OPTS MC 2 1") == "200 MC 2 1"
        # the stripe size is kept when absent
        assert self.client.sendcmd("OPTS MC 4") == "200 MC 4 1"
        # values above the server's limits are lowered
        assert self.client.sendcmd("OPTS MC 100") == "200 MC 16 1"
        resp = self.client.sendcmd("OPTS MC 2 4294967295")
        assert resp == f"200 MC 2 {16 * 1024 * 1024}"
        assert self.client.sendcmd("OPTS MC OFF") == "200 MC OFF"

    def test_opts_errors(self):
        for arg in ("", "0", "x", "2 0", "2 4294967296", "1 2 3", "-1"):
            with self.subTest(arg=arg):
                with pytest.raises(ftplib.error_perm) as cm:
                    self.client.sendcmd("OPTS MC " + arg)
                assert str(cm.value).startswith("501")

    def test_opts_disabled(self):
        self.server.handler.mc_max_connections = 0
        try:
            assert "MC" not in self.client.sendcmd("FEAT")
            with pytest.raises(ftplib.error_perm):
                self.client.sendcmd("OPTS MC 2")
        finally:
            self.server.handler.mc_max_connections = 16

    def test_mpsv_mprt_need_opts(self):
        for cmd in ("MPSV", "MPRT |1|127.0.0.1|2000,2001|"):
            with pytest.raises(ftplib.error_perm) as cm:
                self.client.sendcmd(cmd)
            assert str(cm.value).startswith("503")

    def test_opts_off_discards_set(self):
        self.enable(2)
        socks = self.connect_set(self.mpsv())
        self.client.sendcmd("OPTS MC OFF")
        for s in socks:
            assert s.recv(1) == b""

    # --- transfers

    def test_retr(self):
        data = os.urandom(100000)
        for size in (0, 1, 4095, 4096, 3 * 4096, 3 * 4096 + 1, 100000):
            for n, stripe in ((1, 4096), (3, 4096), (4, 1000), (5, 1)):
                with self.subTest(size=size, n=n, stripe=stripe):
                    self.retr(data[:size], n, stripe)

    def test_stor(self):
        data = os.urandom(100000)
        for size in (0, 1, 4095, 4096, 3 * 4096, 3 * 4096 + 1, 100000):
            for n, stripe in ((1, 4096), (3, 4096), (4, 1000), (5, 1)):
                with self.subTest(size=size, n=n, stripe=stripe):
                    self.stor(data[:size], n, stripe)

    def test_rest(self):
        data = os.urandom(50000)
        with open(self.testfn, "wb") as f:
            f.write(data)
        _n, stripe = self.enable(3, 1000)
        socks = self.connect_set(self.mpsv())
        self.client.sendcmd("REST 12345")
        self.client.sendcmd("RETR " + self.testfn)
        parts = self.receive_set(socks)
        self.client.voidresp()
        assert stripe_join(parts, stripe) == data[12345:]

    def test_appe(self):
        with open(self.testfn, "wb") as f:
            f.write(b"head")
        n, stripe = self.enable(3, 2)
        socks = self.connect_set(self.mpsv())
        self.client.sendcmd("APPE " + self.testfn)
        self.send_set(socks, stripe_split(b"0123456789", n, stripe))
        self.client.voidresp()
        with open(self.testfn, "rb") as f:
            assert f.read() == b"head0123456789"

    def test_list(self):
        with open(self.testfn, "wb"):
            pass
        _n, stripe = self.enable(3, 16)
        socks = self.connect_set(self.mpsv())
        self.client.sendcmd("NLST")
        parts = self.receive_set(socks)
        self.client.voidresp()
        listing = stripe_join(parts, stripe).decode()
        assert self.testfn in listing.split("\r\n")

    def test_ascii(self):
        self.client.voidcmd("TYPE A")
        n, stripe = self.enable(2, 3)
        socks = self.connect_set(self.mpsv())
        self.client.sendcmd("STOR " + self.testfn)
        self.send_set(socks, stripe_split(b"a\r\nb\r\nc\r\n", n, stripe))
        self.client.voidresp()
        with open(self.testfn, "rb") as f:
            expected = "a\nb\nc\n".replace("\n", os.linesep).encode()
            assert f.read() == expected

    # --- connection set rules

    def test_set_used_once(self):
        self.retr(b"hello", 2, 4096)
        with pytest.raises(ftplib.error_temp) as cm:
            self.client.sendcmd("RETR " + self.testfn)
        assert str(cm.value).startswith("425")
        # plain passive mode still works afterwards
        self.client.sendcmd("PASV")

    def test_preliminary_reply_waits_for_connections(self):
        with open(self.testfn, "wb") as f:
            f.write(b"x" * 10)
        self.enable(3, 4)
        ports = self.mpsv()
        self.client.putcmd("RETR " + self.testfn)
        socks = self.connect_set(ports[:2])
        # no reply until all three connections are open
        r, _, _ = select.select([self.client.sock], [], [], 0.2)
        assert not r
        socks += self.connect_set(ports[2:])
        assert self.client.getresp().startswith("150")
        parts = self.receive_set(socks)
        self.client.voidresp()
        assert stripe_join(parts, 4) == b"x" * 10

    def test_mpsv_timeout(self):
        MCPassive.timeout = 0.3
        with open(self.testfn, "wb") as f:
            f.write(b"x")
        self.enable(2)
        ports = self.mpsv()
        self.connect_set(ports[:1])
        with pytest.raises(ftplib.error_temp) as cm:
            self.client.sendcmd("RETR " + self.testfn)
        assert str(cm.value).startswith("425")

    def test_inconsistent_upload(self):
        self.enable(2, 4)
        socks = self.connect_set(self.mpsv())
        self.client.sendcmd("STOR " + self.testfn)
        # connection 1 carries one stripe too many
        self.send_set(socks, [b"aaaa", b"bbbbcccc"])
        with pytest.raises(ftplib.error_temp) as cm:
            self.client.voidresp()
        assert str(cm.value).startswith("426")
        # the stored data is a valid prefix
        with open(self.testfn, "rb") as f:
            assert f.read() == b"aaaabbbb"

    def test_reset_during_upload(self):
        self.enable(2, 4)
        socks = self.connect_set(self.mpsv())
        self.client.sendcmd("STOR " + self.testfn)
        socks[0].sendall(b"aaaa")
        socks[1].setsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
        )
        socks[1].close()
        with pytest.raises(ftplib.error_temp) as cm:
            self.client.voidresp()
        assert str(cm.value).startswith("426")

    def test_abor(self):
        self.enable(2)
        socks = self.connect_set(self.mpsv())
        self.client.sendcmd("STOR " + self.testfn)
        socks[0].sendall(b"x" * 4096)
        self.client.putcmd("ABOR")
        resp = self.client.getmultiline()
        if resp.startswith("426"):
            resp = self.client.getmultiline()
        assert resp.startswith(("226", "225")), resp
        for s in socks:
            assert s.recv(1) == b""

    def test_pasv_discards_set(self):
        self.enable(2)
        socks = self.connect_set(self.mpsv())
        self.client.sendcmd("PASV")
        for s in socks:
            assert s.recv(1) == b""

    def test_foreign_address_rejected(self):
        self.enable(2)
        ports = self.mpsv()
        handler = self.server.handler
        # pretend the control connection comes from elsewhere
        with self.server.lock:
            session = next(
                h
                for h in self.server.server.ioloop.socket_map.values()
                if isinstance(h, handler)
            )
            session.remote_ip = "192.0.2.1"
        s = socket.create_connection((self.server.host, ports[0]))
        self.socks.append(s)
        assert s.recv(1) == b""

    # --- active mode

    def test_mprt(self):
        data = os.urandom(30000)
        with open(self.testfn, "wb") as f:
            f.write(data)
        n, stripe = self.enable(3, 1000)
        listeners = []
        for _ in range(n):
            ls = socket.create_server((self.server.host, 0))
            ls.settimeout(GLOBAL_TIMEOUT)
            listeners.append(ls)
            self.socks.append(ls)
        ports = ",".join(str(ls.getsockname()[1]) for ls in listeners)
        self.client.putcmd(f"MPRT |1|{self.server.host}|{ports}|")
        socks = []
        for ls in listeners:
            s, _ = ls.accept()
            socks.append(s)
            self.socks.append(s)
        assert self.client.getresp().startswith("200")
        assert self.client.sendcmd("RETR " + self.testfn).startswith("125")
        parts = self.receive_set(socks)
        self.client.voidresp()
        assert stripe_join(parts, stripe) == data

    def test_mprt_errors(self):
        self.enable(2)
        host = self.server.host
        cases = (
            (f"|1|{host}|2000|", "501"),
            (f"|1|{host}|2000,2000|", "501"),
            (f"|1|{host}|2000,x|", "501"),
            ("|1|192.0.2.1|2000,2001|", "504"),
            (f"|1|{host}|1000,2001|", "504"),
            (f"|9|{host}|2000,2001|", "522"),
        )
        for arg, code in cases:
            with self.subTest(arg=arg):
                with pytest.raises(ftplib.Error) as cm:
                    self.client.sendcmd("MPRT " + arg)
                assert str(cm.value).startswith(code)
