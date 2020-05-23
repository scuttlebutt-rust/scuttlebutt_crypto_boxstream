using System;
using System.Net.Sockets;

namespace Scuttlebutt.Crypto.BoxStream
{
    static class TestCode
    {
        void Test(byte[] derived_secret, byte[] foreign_pubkey, byte[] self_pubkey, byte[] network_key, byte[] a, byte[] b)
        {
            var inbound_conn = new Socket(SocketType.Dgram, ProtocolType.Udp);
            var inbound_conn = new Socket(SocketType.Dgram, ProtocolType.Udp);

            var (sender, receiver) = BoxStreamBuilder.Build(
                derived_secret,
                foreign_pubkey,
                self_pubkey,
                network_key,
                a,
                b
            );

            var cleartext = new byte[32];
            var wiretext = sender.Box(cleartext);

        }
    }
}