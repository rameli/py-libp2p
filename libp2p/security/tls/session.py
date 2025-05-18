from typing import (
    Optional,
)

from libp2p.crypto.keys import (
    PrivateKey,
    PublicKey,
)
from libp2p.io.abc import (
    ReadWriteCloser,
)
from libp2p.peer.id import (
    ID,
)
from libp2p.security.base_session import (
    BaseSession,
)


class TlsSession(BaseSession):
    def __init__(
        self,
        *,
        local_peer: ID,
        local_private_key: PrivateKey,
        remote_peer: ID,
        remote_permanent_pubkey: PublicKey,
        is_initiator: bool,
        conn: ReadWriteCloser,
    ) -> None:
        super().__init__(
            local_peer=local_peer,
            local_private_key=local_private_key,
            remote_peer=remote_peer,
            remote_permanent_pubkey=remote_permanent_pubkey,
            is_initiator=is_initiator,
        )
        self.conn = conn
        # Cache the remote address to avoid repeated lookups
        # through the delegation chain
        try:
            self.remote_peer_addr = conn.get_remote_address()
        except AttributeError:
            self.remote_peer_addr = None

    async def write(self, data: bytes) -> None:
        await self.conn.write(data)

    async def read(self, n: int = None) -> bytes:
        return await self.conn.read(n)

    async def close(self) -> None:
        await self.conn.close()

    def get_remote_address(self) -> Optional[tuple[str, int]]:
        """
        Delegate to the underlying connection's get_remote_address method.
        """
        return self.conn.get_remote_address()
