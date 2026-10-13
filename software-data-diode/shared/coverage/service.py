"""Paced byte grants with owned shares and bounded idle borrowing, no transport."""
from dataclasses import dataclass, field

from .budget import LANES


@dataclass
class ByteService:
    cycle: int = -1
    spent: dict = field(default_factory=lambda: {lane: 0 for lane in LANES})
    owned: dict = field(default_factory=lambda: {lane: 0 for lane in LANES})
    next_us: int = 0
    next_scaled: int = 0
    cursor: int = 0
    total_bytes: int = 0

    def validate(self, config):
        scalars = (self.cycle, self.next_us, self.next_scaled, self.cursor, self.total_bytes)
        if (any(type(value) is not int for value in scalars) or self.cycle < -1
                or min(self.next_us, self.next_scaled, self.total_bytes) < 0 or not 0 <= self.cursor < 3
                or self.next_us != (self.next_scaled+config.link_bytes_per_second-1)//config.link_bytes_per_second
                or set(self.spent) != set(LANES) or set(self.owned) != set(LANES)):
            raise ValueError("invalid local byte-service checkpoint")
        if (any(type(self.spent[lane]) is not int or type(self.owned[lane]) is not int
                or not 0 <= self.owned[lane] <= min(self.spent[lane], config.quotas[lane]) for lane in LANES)
                or sum(self.spent.values()) > min(config.cycle_bytes, self.total_bytes)):
            raise ValueError("invalid byte-service accounting")

    def choose(self, now_us, heads, config):
        if (type(now_us) is not int or now_us < 0 or not set(heads) <= set(LANES)
                or any(type(cost) is not int or not 1 <= cost <= config.max_wire_frame for cost in heads.values())):
            raise ValueError("invalid local byte-service request")
        if now_us < self.next_us:
            return None
        cycle = now_us//(config.service_cycle_seconds*1000000)
        if cycle < self.cycle:
            raise ValueError("local service clock moved backward")
        if cycle != self.cycle:
            self.cycle = cycle
            self.spent = {lane: 0 for lane in LANES}
            self.owned = {lane: 0 for lane in LANES}
        remaining = config.cycle_bytes-sum(self.spent.values())
        owned = {lane for lane, cost in heads.items()
                 if cost <= remaining and self.owned[lane]+cost <= config.quotas[lane]}
        allowed = owned
        if not owned and len(heads) < len(LANES):
            idle_budget = sum(max(0, config.quotas[lane]-self.owned[lane])
                              for lane in LANES if lane not in heads)
            allowed = {lane for lane, cost in heads.items() if cost <= min(remaining, idle_budget)}
        for offset in range(len(LANES)):
            lane = LANES[(self.cursor+offset)%len(LANES)]
            if lane in allowed:
                cost = heads[lane]
                self.spent[lane] += cost
                if lane in owned:
                    self.owned[lane] += cost
                self.total_bytes += cost
                # Carry sub-microsecond fractions when polled at the advertised deadline.
                # Late polling earns no extra service credit or unbounded catch-up burst.
                start = self.next_scaled if now_us == self.next_us else now_us*config.link_bytes_per_second
                self.next_scaled = start+cost*1000000
                self.next_us = (self.next_scaled+config.link_bytes_per_second-1)//config.link_bytes_per_second
                self.cursor = (LANES.index(lane)+1)%len(LANES)
                return lane
        return None

    @staticmethod
    def conditional_wait_bound(pending_wire_bytes, lane, config):
        useful = config.quotas[lane]-2*config.max_wire_frame
        cycles = (pending_wire_bytes+useful-1)//useful
        return (cycles+1)*config.service_cycle_seconds + 2*config.max_wire_frame/config.link_bytes_per_second
