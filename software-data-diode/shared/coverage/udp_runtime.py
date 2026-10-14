"""Local UDP service adapters. Sender API deliberately exposes no receive method."""
import asyncio
from collections import Counter
from contextlib import suppress
import json
import os
import socket
import sys
import time

import httpx
from shared.models import ObservabilitySnapshot
from .transport import PartAssembler

SOCKET_AUDIT = {"installed": False, "udp_send_calls": 0, "last_destinations": []}


def install_socket_audit():
    if SOCKET_AUDIT["installed"]:
        return
    def audit(event, arguments):
        if event == "socket.sendto" and arguments[0].type & socket.SOCK_DGRAM:
            SOCKET_AUDIT["udp_send_calls"] += 1
            SOCKET_AUDIT["last_destinations"] = (SOCKET_AUDIT["last_destinations"]+[list(arguments[1])])[-8:]
    sys.addaudithook(audit)
    SOCKET_AUDIT["installed"] = True


if os.getenv("COVERAGE_SOCKET_AUDIT", "false").lower() == "true":
    install_socket_audit()


class SendOnlyUDP:
    def __init__(self, host, port, datagram_bytes=1200):
        if host not in {"data-diode", "fog-receiver", "127.0.0.1"} or not 1 <= int(port) <= 65535:
            raise ValueError("research destination must be a local project service")
        self.host, self.port, self.limit = host, int(port), datagram_bytes
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setblocking(False)
        self.address, self.counts = None, Counter()
        self.task = asyncio.create_task(self._resolve())

    async def _resolve(self):
        while True:
            try:
                rows = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(self.host, self.port,
                    family=socket.AF_INET, type=socket.SOCK_DGRAM), 1)
                self.address = rows[0][4]
            except (OSError, asyncio.TimeoutError):
                self.address = None
            await asyncio.sleep(2)

    def attempt(self, frame):
        if not 1 <= len(frame) <= self.limit:
            raise ValueError("datagram payload bound")
        self.counts["attempts"] += 1
        self.counts["attempted_payload_bytes"] += len(frame)
        try:
            if self.address is None:
                raise OSError("local destination unresolved")
            if self.socket.sendto(frame, self.address) != len(frame):
                raise OSError("partial local UDP send")
            self.counts["local_send_calls_succeeded"] += 1
        except OSError:
            self.counts["local_send_errors"] += 1
        # The caller advances its charged grant regardless of local send outcome.

    async def close(self):
        self.task.cancel()
        with suppress(asyncio.CancelledError):
            await self.task
        self.socket.close()


class ReceiveOnlyUDP(asyncio.DatagramProtocol):
    def __init__(self, queue, limit, counts, authorized):
        self.queue, self.limit, self.counts, self.authorized = queue, limit, counts, authorized

    def datagram_received(self, data, address):
        self.counts["datagrams_received"] += 1
        self.counts["received_payload_bytes"] += len(data)
        if len(data) > self.limit or not data or address[0] not in self.authorized:
            self.counts["size_or_source_drops"] += 1
            return
        try:
            self.queue.put_nowait(data)
        except asyncio.QueueFull:
            self.counts["queue_overflow_drops"] += 1


class IngressRuntime:
    def __init__(self, config, allowed_host):
        self.config, self.allowed_host = config, allowed_host
        self.counts, self.authorized = Counter(), set()
        self.queue = asyncio.Queue(maxsize=config.queue_frames)
        self.endpoint = None
        self.tasks = []

    async def start(self, port):
        self.tasks.append(asyncio.create_task(self._authorize()))
        self.endpoint, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: ReceiveOnlyUDP(self.queue, self.config.datagram_bytes, self.counts, self.authorized),
            local_addr=("0.0.0.0", int(port)), family=socket.AF_INET)
        self.tasks.append(asyncio.create_task(self._process()))

    async def _authorize(self):
        while True:
            try:
                rows = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(self.allowed_host, 0,
                    family=socket.AF_INET, type=socket.SOCK_DGRAM), 1)
                self.authorized.clear()
                self.authorized.update(row[4][0] for row in rows)
            except (OSError, asyncio.TimeoutError):
                self.authorized.clear()
            await asyncio.sleep(2)

    async def _process(self):
        raise NotImplementedError

    def status(self):
        return {**dict(self.counts), "queue_frames": self.queue.qsize(), "max_queue_frames": self.config.queue_frames,
                "application_replies_sent": 0, "socket_audit": dict(SOCKET_AUDIT),
                "live": self.endpoint is not None and all(not task.done() for task in self.tasks)}

    async def close(self):
        if self.endpoint:
            self.endpoint.close()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


class PassiveDiode(IngressRuntime):
    def __init__(self, config, *, link_capacity, host="fog-receiver", port=9002):
        if type(link_capacity) is not int or not 1 <= link_capacity <= 10**9:
            raise ValueError("invalid locally configured forwarding capacity")
        super().__init__(config, "edge-gateway")
        self.sender, self.capacity = SendOnlyUDP(host, port, config.datagram_bytes), link_capacity

    async def _process(self):
        while True:
            frame = await self.queue.get()
            self.sender.attempt(frame)
            self.counts["forward_attempts"] += 1
            self.queue.task_done()
            await asyncio.sleep((len(frame)+28)/self.capacity)

    def status(self):
        return {**super().status(), "sender": dict(self.sender.counts), "forwarding": "PASSIVE_FIFO_LOCAL_ATTEMPTS"}

    async def close(self):
        await super().close()
        await self.sender.close()


class GatewayUDP:
    def __init__(self, controller, config):
        self.controller, self.config = controller, config
        self.sender = SendOnlyUDP("data-diode", 9001, config.datagram_bytes)
        controller.retire_uncertain_lease()
        self.task = asyncio.create_task(self._run())

    async def _run(self):
        next_state = 0
        while True:
            now = time.monotonic()
            if now >= next_state:
                await asyncio.to_thread(self.controller.publish_forward_state)
                next_state = now+self.config.state_interval_seconds
            lease = await asyncio.to_thread(self.controller.lease_frame)
            if lease:
                self.sender.attempt(lease.payload)
                await asyncio.to_thread(self.controller.complete_local_attempt, lease.lease_id)
            await asyncio.sleep(.01)

    async def close(self):
        self.task.cancel()
        with suppress(asyncio.CancelledError):
            await self.task
        await self.sender.close()

    def status(self):
        return {"live": not self.task.done(), "sender": dict(self.sender.counts), "socket_audit": dict(SOCKET_AUDIT),
                "confirmed_receipt": "NOT_OBSERVED"}


class FogUDP(IngressRuntime):
    def __init__(self, framer, store, repository, processor_url):
        super().__init__(framer.config, "data-diode")
        self.framer, self.store, self.repository, self.processor_url = framer, store, repository, processor_url
        self.assembler = PartAssembler(framer)

    async def start(self, port=9002):
        await super().start(port)
        self.tasks.append(asyncio.create_task(self._internal_processing()))

    async def _process(self):
        while True:
            try:
                frame = await asyncio.wait_for(self.queue.get(), .5)
            except asyncio.TimeoutError:
                self.assembler.expire()
                continue
            try:
                artifact = self.assembler.add(frame)
                if artifact is not None:
                    accepted = await asyncio.to_thread(self.store.accept, artifact)
                    self.counts["verified_artifacts" if accepted else "duplicate_artifacts"] += 1
            except Exception as exc:
                self.counts["rejections"] += 1
                self.counts[type(exc).__name__] += 1
            finally:
                self.queue.task_done()

    async def _internal_processing(self):
        while True:
            row = await asyncio.to_thread(self.store.pending)
            try:
                if row:
                    body = json.loads(row["body"])
                    if row["kind"] == "RAW":
                        if not self.processor_url:
                            raise RuntimeError("Fog processor not configured")
                        async with httpx.AsyncClient(timeout=2) as client:
                            response = await client.post(self.processor_url, json=body)
                            response.raise_for_status()
                    else:
                        from datetime import datetime, timedelta, timezone
                        snapshot = ObservabilitySnapshot(timestamp=datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(microseconds=body["timestamp_us"]),
                            service="edge-gateway", metrics=body["metrics"], labels={"scope": "accepted_gateway_ingress", "assurance": "AUTHENTICATED_FORWARD_STATE"})
                        await asyncio.to_thread(self.repository.save_observability_snapshot, snapshot)
                    await asyncio.to_thread(self.store.completed, row["kind"], row["id"])
            except Exception:
                self.counts["internal_fog_processing_errors"] += 1
            await asyncio.sleep(.05 if row else .2)

    def status(self):
        return {**super().status(), "partial_artifacts": len(self.assembler.pending), "partial_bytes": self.assembler.bytes,
                "expired_partial_artifacts": self.assembler.expired, **self.store.status()}
