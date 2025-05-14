import multiaddr
import trio

from libp2p import (
    new_host,
)
from libp2p.crypto.secp256k1 import (
    create_new_key_pair,
)
from libp2p.peer.peerinfo import (
    info_from_p2p_addr,
)
from libp2p.security.tls.transport import (
    TLS_PROTOCOL_ID,
    TlsTransport,
)


async def main():
    key_pair_responder = create_new_key_pair(b"rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr")
    tls_transport_responder = TlsTransport(
        local_key_pair=key_pair_responder,
        secure_bytes_provider=None,
    )

    key_pair_initiator = create_new_key_pair(b"iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii")
    tls_transport_initiator = TlsTransport(
        local_key_pair=key_pair_initiator,
        secure_bytes_provider=None,
    )

    host = new_host(
        key_pair=key_pair_responder,
        sec_opt={TLS_PROTOCOL_ID: tls_transport_responder},
    )
    initor = new_host(
        key_pair=key_pair_initiator,
        sec_opt={TLS_PROTOCOL_ID: tls_transport_initiator},
    )

    remote_multiaddr = (
        "/ip4/0.0.0.0/tcp/8000/p2p/"
        "16Uiu2HAmR3zsWcFxeBgTz7oMYboa2DcZbChA2M5e4jE7S2ZNegu9"
    )

    async with host.run(listen_addrs=[multiaddr.Multiaddr("/ip4/0.0.0.0/tcp/8000")]):
        async with initor.run(
            listen_addrs=[multiaddr.Multiaddr("/ip4/0.0.0.0/tcp/9000")]
        ):
            try:
                peer_info = info_from_p2p_addr(multiaddr.Multiaddr(host.get_addrs()[0]))
                await initor.connect(peer_info)
                print(f"Connected to {peer_info.peer_id.to_string()}")
            except Exception as e:
                print(f"FAILED to connect to {remote_multiaddr}: {e}")

            await trio.sleep_forever()


trio.run(main)
