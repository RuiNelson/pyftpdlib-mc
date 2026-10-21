# Copyright (C) 2007 Giampaolo Rodola' <g.rodola@gmail.com>.
# Use of this source code is governed by MIT license that can be
# found in the LICENSE file.

"""FTPMC: one transfer striped over several data connections.

See draft-ftpmc (https://github.com/RuiNelson/FTPMC). The data stream
is cut into stripes of S octets and stripe i travels on connection
i mod N. Only MODE S is implemented, so a connection set carries a
single transfer and each connection signals end-of-data by closing.

Uploads buffer future stripes and write only the contiguous stream prefix.
REST + STOR preserves the accepted prefix and removes any old tail before
receiving more data. With TYPE I, SIZE is sufficient to resume in a new
session with a different connection count and stripe size. ASCII restart is not
supported because file offsets need not match converted stream offsets.
"""

import errno
import os
import socket

from pyftpdlib.exceptions import _FileReadWriteError
from pyftpdlib.ioloop import _ERRNOS_RETRY
from pyftpdlib.ioloop import Acceptor
from pyftpdlib.ioloop import AsyncChat
from pyftpdlib.ioloop import timer
from pyftpdlib.log import debug
from pyftpdlib.log import logger
from pyftpdlib.utils import strerror

from .dispatchers import ActiveDTP
from .dispatchers import PassiveDTP

__all__ = ["MC_MAX_STRIPE", "MCActive", "MCDataSet", "MCPassive"]

# largest stripe size allowed by the protocol (fits in 32 bits)
MC_MAX_STRIPE = 4294967295
# largest chunk read from or written to a socket at once
_IO_CHUNK = 262144


class _BytesProducer:
    """Producer returning a bytes object once."""

    def __init__(self, data):
        self.data = data

    def more(self):
        data, self.data = self.data, b""
        return data


class _MCChannel(AsyncChat):
    """One data connection of a connection set. It only moves bytes
    between the socket and its buffers; striping is done by MCDataSet.
    """

    def __init__(self, sock, mcset, index):
        self.mcset = mcset
        self.index = index
        self.inbuf = bytearray()
        self.outbuf = bytearray()
        self.eof = False  # end-of-data received
        self.out_eof = False  # close once outbuf is drained
        self.finished = False  # all data sent and connection closed
        self._interest = None
        AsyncChat.__init__(self, sock, ioloop=mcset.ioloop)
        # stay idle until the transfer starts
        self.set_interest(0)

    def set_interest(self, events):
        """Set the IO events to wait for; 0 unregisters the socket."""
        if self._closed or events == self._interest:
            return
        registered = self._fileno in self.ioloop.socket_map
        if not events:
            if registered:
                self.del_channel()
        elif not registered:
            self.add_channel(events=events)
        else:
            self.ioloop.modify(self._fileno, events)
        self._interest = events

    def readable(self):
        return bool(self._interest and self._interest & self.ioloop.READ)

    def writable(self):
        return bool(self._interest and self._interest & self.ioloop.WRITE)

    def handle_read(self):
        room = self.mcset.buffer_limit - len(self.inbuf)
        if room <= 0:
            self.set_interest(0)
            return
        try:
            data = self.socket.recv(min(room, _IO_CHUNK))
        except OSError as err:
            if err.errno in _ERRNOS_RETRY:
                return
            self.mcset.channel_failed(self, err)
            return
        if not data:
            self.eof = True
            self.set_interest(0)
        else:
            self.inbuf += data
            self.mcset.tot_bytes_received += len(data)
            if len(self.inbuf) >= self.mcset.buffer_limit:
                self.set_interest(0)
        self.mcset.on_channel_input()

    def handle_write(self):
        if self.outbuf:
            try:
                with memoryview(self.outbuf) as view:
                    sent = self.socket.send(view[:_IO_CHUNK])
            except OSError as err:
                if err.errno in _ERRNOS_RETRY:
                    return
                self.mcset.channel_failed(self, err)
                return
            del self.outbuf[:sent]
            self.mcset.tot_bytes_sent += sent
        if not self.outbuf:
            if self.out_eof:
                # orderly close signals end-of-data in MODE S
                self.finished = True
                self.close()
                self.mcset.on_channel_finished()
                return
            self.set_interest(0)
        self.mcset.on_channel_drained()

    def handle_close(self):
        if not self._closed and not self.finished:
            self.mcset.channel_failed(self, None)

    def handle_error(self):
        self.mcset.channel_error(self)


class MCDataSet:
    """A connection set. It stands in for DTPHandler as the control
    channel's data_channel and implements the striping of
    draft-ftpmc Section 6.

    - (int) timeout: maximum time a transfer may stall with no
      progress before the client is kicked off (defaults 300).
    """

    timeout = 300

    def __init__(self, cmd_channel, n, stripe):
        self.cmd_channel = cmd_channel
        self.ioloop = cmd_channel.ioloop
        self.n = n
        self.stripe = stripe
        self.buffer_limit = max(2 * stripe, cmd_channel.mc_buffer_size)
        self.channels = [None] * n
        self.file_obj = None
        self.receive = False
        self.cmd = None
        self.transfer_finished = False
        self.tot_bytes_sent = 0
        self.tot_bytes_received = 0
        self._closed = False
        self._start_time = timer()
        self._idler = None
        self._lastdata = 0
        # current stripe and position inside it
        self._index = 0
        self._pos = 0
        # sending
        self._source = None
        self._source_done = False
        self._pending = bytearray()
        self._close_when_done = False
        # receiving
        self._ended = False
        self._data_wrapper = None
        self._had_cr = False

    def __repr__(self):
        return "<%s(%s)>" % (
            self.__class__.__name__,
            self.cmd_channel.get_repr_info(as_str=True),
        )

    __str__ = __repr__

    # --- connection set

    def add_socket(self, index, sock):
        """Add the data connection with the given connection index.
        Return False if the socket could not be used.
        """
        channel = _MCChannel(sock, self, index)
        if not channel.connected:
            channel.close()
            return False
        self.channels[index] = channel
        if self.complete and self.timeout:
            self._idler = self.ioloop.call_every(
                self.timeout, self.handle_timeout, _errback=self.handle_error
            )
        return True

    @property
    def complete(self):
        return all(ch is not None for ch in self.channels)

    @property
    def socket(self):
        return self.channels[0].socket if self.channels[0] else None

    def discard(self):
        """Close the connections of a set that never became the
        control channel's data_channel.
        """
        self._closed = True
        for ch in self.channels:
            if ch is not None:
                ch.close()

    # --- DTPHandler interface used by FTPHandler

    def use_sendfile(self):
        return False

    def get_transmitted_bytes(self):
        return self.tot_bytes_sent + self.tot_bytes_received

    def get_elapsed_time(self):
        return timer() - self._start_time

    def transfer_in_progress(self):
        return self.get_transmitted_bytes() != 0

    def push(self, data):
        self._start_sending(_BytesProducer(data))

    def push_with_producer(self, producer):
        self._start_sending(producer)

    def close_when_done(self):
        self._close_when_done = True
        self._pump()

    def enable_receiving(self, type, cmd):
        self.receive = True
        self.cmd = cmd
        self._start_time = timer()
        if type == "a" and os.linesep != "\r\n":
            self._data_wrapper = self._posix_ascii_data_wrapper
        elif type not in ("a", "i"):
            raise TypeError("unsupported type")
        for ch in self.channels:
            ch.set_interest(self.ioloop.READ)

    def close(self):
        """Close the set without replying (e.g. ABOR, REIN, QUIT)."""
        self._finish(None, self.transfer_finished)

    # --- sending

    def _start_sending(self, producer):
        self.receive = False
        self._source = producer
        self._start_time = timer()
        self._pump()

    def _pump(self):
        """Move data from the source into the connections' buffers,
        stripe by stripe, as long as the next stripe's connection has
        room for it.
        """
        if self._closed or self._source is None:
            return
        write = self.ioloop.WRITE
        try:
            while True:
                ch = self.channels[self._index % self.n]
                room = self.buffer_limit - len(ch.outbuf)
                if room <= 0:
                    break
                if not self._pending:
                    if self._source_done:
                        break
                    data = self._source.more()
                    if not data:
                        self._source_done = True
                        break
                    self._pending += data
                take = min(len(self._pending), self.stripe - self._pos, room)
                ch.outbuf += self._pending[:take]
                del self._pending[:take]
                ch.set_interest(write)
                self._pos += take
                if self._pos == self.stripe:
                    self._index += 1
                    self._pos = 0
        except _FileReadWriteError as err:
            self._fail(f"426 {strerror(err)}; transfer aborted.")
            return
        if self._source_done and not self._pending and self._close_when_done:
            for ch in self.channels:
                if not ch.out_eof:
                    ch.out_eof = True
                    ch.set_interest(write)

    def on_channel_drained(self):
        self._pump()

    def on_channel_finished(self):
        if all(ch.finished for ch in self.channels):
            self.transfer_finished = True
            self._finish("226 Transfer complete.", True)

    # --- receiving

    def _write(self, data):
        """Store every octet before advancing to subsequent stream data."""
        pos = 0
        while pos < len(data):
            written = self.file_obj.write(data[pos:])
            if written is None or not 0 < written <= len(data) - pos:
                raise OSError(errno.EIO, "Incomplete file write")
            pos += written

    def _posix_ascii_data_wrapper(self, chunk):
        if self._had_cr:
            chunk = b"\r" + chunk
        if chunk.endswith(b"\r"):
            self._had_cr = True
            chunk = chunk[:-1]
        else:
            self._had_cr = False
        return chunk.replace(b"\r\n", bytes(os.linesep, "ascii"))

    def on_channel_input(self):
        """Reassemble the data stream (draft-ftpmc Section 6.2) from
        what the connections have buffered so far, writing it in order.
        """
        if self._closed or not self.receive:
            return
        read = self.ioloop.READ
        chunks = []
        while not self._ended:
            ch = self.channels[self._index % self.n]
            if ch.inbuf:
                take = min(len(ch.inbuf), self.stripe - self._pos)
                chunks.append(ch.inbuf[:take])
                del ch.inbuf[:take]
                if not ch.eof:
                    ch.set_interest(read)
                self._pos += take
                if self._pos == self.stripe:
                    self._index += 1
                    self._pos = 0
            elif ch.eof:
                # end-of-data before completing the stripe
                self._ended = True
            else:
                break
        if chunks:
            data = b"".join(chunks)
            if self._data_wrapper is not None:
                data = self._data_wrapper(data)
            try:
                self._write(data)
            except OSError as err:
                self._fail(f"426 {strerror(err)}; transfer aborted.")
                return
        if self._ended:
            # every other connection must be at end-of-data
            for ch in self.channels:
                if ch.inbuf:
                    self._fail(
                        "426 Data after end of stream on connection"
                        f" {ch.index}; transfer aborted."
                    )
                    return
            if all(ch.eof for ch in self.channels):
                # A CR held back for a possible CRLF is itself data at EOF.
                if self._had_cr:
                    try:
                        self._write(b"\r")
                    except OSError as err:
                        self._fail(f"426 {strerror(err)}; transfer aborted.")
                        return
                    self._had_cr = False
                self.transfer_finished = True
                self._finish("226 Transfer complete.", True)

    # --- errors and termination

    def channel_failed(self, channel, err):
        if self._closed:
            return
        why = strerror(err) if err is not None else "connection closed"
        self._fail(
            f"426 Data connection {channel.index} failed ({why});"
            " transfer aborted."
        )

    def channel_error(self, channel):
        if self._closed:
            return
        self.cmd_channel.log_exception(channel)
        self._fail("426 Internal error; transfer aborted.")

    def handle_error(self):
        self.cmd_channel.log_exception(self)
        self._fail("426 Internal error; transfer aborted.")

    def handle_timeout(self):
        if self.get_transmitted_bytes() > self._lastdata:
            self._lastdata = self.get_transmitted_bytes()
        else:
            self._finish("421 Data connection timed out.", False, logger.info)
            self.cmd_channel.close_when_done()

    def _fail(self, resp):
        self._finish(resp, False, logger.warning)

    def _finish(self, resp, completed, logfun=logger.debug):
        if self._closed:
            return
        debug("call: _finish()", inst=self)
        self._closed = True
        self.transfer_finished = completed
        # RFC-959 says we must close the connection before replying
        for ch in self.channels:
            if ch is not None:
                ch.close()
        if self._idler is not None and not self._idler.cancelled:
            self._idler.cancel()
        # close the file before replying, so the client sees it complete
        if self.file_obj is not None and not self.file_obj.closed:
            self.file_obj.close()
        cmd = self.cmd_channel
        if resp:
            cmd.respond(resp, logfun=logfun)
        if self.file_obj is not None:
            filename = self.file_obj.name
            cmd.log_transfer(
                cmd=self.cmd,
                filename=filename,
                receive=self.receive,
                completed=completed,
                elapsed=round(self.get_elapsed_time(), 3),
                bytes=self.get_transmitted_bytes(),
            )
            if completed:
                if self.receive:
                    cmd.on_file_received(filename)
                else:
                    cmd.on_file_sent(filename)
            elif self.receive:
                cmd.on_incomplete_file_received(filename)
            else:
                cmd.on_incomplete_file_sent(filename)
        cmd._on_dtp_close()


class _MCAcceptor(PassiveDTP):
    """Listening socket for one connection index of an MPSV."""

    timeout = 0  # the MCPassive owning it handles the timeout

    def __init__(self, owner, index):
        self.owner = owner
        self.index = index
        self.cmd_channel = owner.cmd_channel
        self.log = self.cmd_channel.log
        self.log_exception = self.cmd_channel.log_exception
        Acceptor.__init__(self, ioloop=self.cmd_channel.ioloop)
        self._listen()
        self.port = self.socket.getsockname()[1]

    def handle_accepted(self, sock, addr):
        cmd = self.cmd_channel
        if not cmd.connected:
            return self.close()
        if cmd.remote_ip != addr[0] and not cmd.permit_foreign_addresses:
            try:
                sock.close()
            except OSError:
                pass
            cmd.log(
                "Rejected data connection from foreign address"
                f" {addr[0]}:{addr[1]}.",
                logfun=logger.warning,
            )
            # keep listening: it may not be the client's fault
            return
        # one connection per port
        self.close()
        self.owner.accepted(self.index, sock)


class MCPassive:
    """Handles MPSV: listens on N ports and builds the connection set.

    - (int) timeout: maximum time for the client to open all N
      connections (defaults 30).
    """

    timeout = 30

    def __init__(self, cmd_channel, n, stripe):
        self.cmd_channel = cmd_channel
        self.mcset = MCDataSet(cmd_channel, n, stripe)
        self.acceptors = []
        self._timer = None
        self._done = False
        try:
            for index in range(n):
                self.acceptors.append(_MCAcceptor(self, index))
        except Exception:
            self.close()
            raise
        ports = ",".join(str(a.port) for a in self.acceptors)
        cmd_channel.respond(f"224 Entering Multi-Passive Mode (|||{ports}|)")
        if self.timeout:
            self._timer = cmd_channel.ioloop.call_later(
                self.timeout, self.handle_timeout, _errback=self.handle_error
            )

    def accepted(self, index, sock):
        cmd = self.cmd_channel
        if not self.mcset.add_socket(index, sock):
            self.close()
            cmd._dtp_acceptor = None
            cmd._mc_data_connections_failed()
            return
        if self.mcset.complete:
            self._done = True
            self._cancel_timer()
            cmd.data_channel = self.mcset
            cmd._on_dtp_connection()

    def handle_timeout(self):
        cmd = self.cmd_channel
        self.close()
        if cmd._dtp_acceptor is self:
            cmd._dtp_acceptor = None
        if cmd.connected:
            cmd._mc_data_connections_failed(timed_out=True)

    def handle_error(self):
        self.cmd_channel.log_exception(self)
        self.close()

    def _cancel_timer(self):
        if self._timer is not None and not self._timer.cancelled:
            self._timer.cancel()

    def close(self):
        self._cancel_timer()
        for acceptor in self.acceptors:
            acceptor.close()
        if not self._done:
            self.mcset.discard()


class _MCConnector(ActiveDTP):
    """Active connection for one connection index of an MPRT."""

    def __init__(self, owner, index, ip, port):
        self.owner = owner
        self.index = index
        self._handed_over = False
        ActiveDTP.__init__(self, ip, port, owner.cmd_channel)

    def handle_connect(self):
        self.del_channel()
        if self._idler is not None and not self._idler.cancelled:
            self._idler.cancel()
        if not self.cmd_channel.connected:
            return self.close()
        err = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            raise OSError(err)
        # the socket now belongs to the connection set
        self._handed_over = True
        self.owner.connected(self.index, self.socket)

    def handle_write(self):
        # asyncore calls this right after handle_connect(); by then the
        # socket belongs to the connection set
        pass

    def handle_timeout(self):
        self.close()
        self.owner.failed()

    def handle_close(self):
        if not self._closed:
            self.close()
            self.owner.failed()

    def close(self):
        if self._handed_over:
            # do not close (or unregister) a socket we no longer own
            self._closed = True
            if self._idler is not None and not self._idler.cancelled:
                self._idler.cancel()
            return
        ActiveDTP.close(self)


class MCActive:
    """Handles MPRT: connects to the N client ports and builds the
    connection set.
    """

    def __init__(self, cmd_channel, n, stripe, ip, ports):
        self.cmd_channel = cmd_channel
        self.mcset = MCDataSet(cmd_channel, n, stripe)
        self.connectors = []
        self._failed = False
        self._done = False
        for index, port in enumerate(ports):
            if self._failed:
                break
            self.connectors.append(_MCConnector(self, index, ip, port))

    def connected(self, index, sock):
        cmd = self.cmd_channel
        if self._failed:
            return
        if not self.mcset.add_socket(index, sock):
            self.failed()
            return
        if self.mcset.complete:
            self._done = True
            if cmd._dtp_connector is self:
                cmd._dtp_connector = None
            n = self.mcset.n
            cmd.respond(
                f"200 MPRT command successful; {n} data connections"
                " established."
            )
            cmd.data_channel = self.mcset
            cmd._on_dtp_connection()

    def failed(self):
        if self._failed or self._done:
            return
        self._failed = True
        cmd = self.cmd_channel
        self.close()
        if cmd._dtp_connector is self:
            cmd._dtp_connector = None
        if cmd.connected:
            cmd._mc_data_connections_failed(active=True)

    def close(self):
        for connector in self.connectors:
            connector.close()
        if not self._done:
            self.mcset.discard()
