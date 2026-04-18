
from __future__ import annotations
import random
import simpy
from .models import StatusList, RevocationEvent


class Issuer:
    def __init__(
        self,
        env: simpy.Environment,
        revocation_rate: float,
        ttl: float,
        num_credentials: int,
        rng: random.Random,
    ):
        self.env = env
        self.revocation_rate = revocation_rate  # notikumu skaits sekundē
        self.ttl = ttl
        self.rng = rng

        self._revoked: set[int] = set()
        self._version = 0
        self._current_list: StatusList = self._publish()

        self.revocation_log: list[RevocationEvent] = []
        self.credentials = list(range(num_credentials))

        env.process(self._revoke_process())

    def _publish(self) -> StatusList:
        self._version += 1
        return StatusList(
            version=self._version,
            revoked_ids=frozenset(self._revoked),
            issued_at=self.env.now,
            ttl=self.ttl,
        )

    def _revoke_process(self):
        while True:
            # laiks starp diviem notikumiem, ja notikumi notiek ar noteiktu vidējo ātrumu, seko eksponenciālai sadalījumam.
            delay = self.rng.expovariate(self.revocation_rate)
            yield self.env.timeout(delay)
            self._do_revoke()

    def _do_revoke(self):
        active = [c for c in self.credentials if c not in self._revoked]
        if not active:
            return
        cred = self.rng.choice(active)
        self._revoked.add(cred)
        self._current_list = self._publish()
        self.revocation_log.append(
            RevocationEvent(credential_id=cred, revoked_at=self.env.now)
        )

    @property
    def current_list(self) -> StatusList:
        return self._current_list

    def is_revoked(self, credential_id: int) -> bool:
        return credential_id in self._revoked

