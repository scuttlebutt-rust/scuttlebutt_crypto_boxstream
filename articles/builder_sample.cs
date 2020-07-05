using System;
using System.Net.Sockets;

namespace Scuttlebutt.Crypto.BoxStream
{
    static class TestCode
    {
        static async void Test(byte[] derived_secret, byte[] foreign_pubkey, byte[] self_pubkey, byte[] network_key, byte[] a, byte[] b)
        {
            // Properly initialize a pair of connections
            var inbound_conn = new Socket(SocketType.Dgram, ProtocolType.Tcp);
            var outbound_conn = new Socket(SocketType.Dgram, ProtocolType.Tcp);

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

            outbound_conn.Send(wiretext);

            var netstream = NetworkStream(inbound_conn, true);

            var reply = await receiver.Unbox(netstream);
            Console.WriteLine(reply);
        }
    }
}
