// Copyright © 2020 Pedro Gómez Martín <zentauro@riseup.net>
//
// This file is part of the library Scuttlebutt.Crypto which
// is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this library. If not, see <http://www.gnu.org/licenses/>.

using System;
using Sodium;

namespace Scuttlebutt.Crypto.BoxStream
{
    /// <summary>
    ///   Provides the utilities to generate boxer/unboxer pairs
    /// </summary>
    public static class BoxStreamBuilder
    {
        /// <summary>
        ///   Given the keys obtained during the handshake generates a pair of
        ///   Boxer/Unboxer.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///     TODO: Write about the process detailed in the spec
        ///   </para>
        /// </remarks>
        /// <param name="derived_secret">
        ///   The secret derived from the client long term key and the server's
        ///   ephemeral key (Ab).
        /// </param>
        /// <param name="foreing_pubkey">
        ///   The public key that identifies the other peer, that is, the server
        ///   public key if this is called from the client and vice versa.
        /// </param>
        /// <param name="self_pubkey">
        ///   The public key that identifies the entity calling this.
        /// </param>
        /// <param name="network_key">
        ///   The key that identifies the network, in the case of scuttlebutt is
        ///   the one posted in the scuttlebutt protocol
        ///   <see href="https://ssbc.github.io/scuttlebutt-protocol-guide/">
        ///     guide
        ///   </see>.
        /// </param>
        /// <param name="a">
        ///   The client's ephemeral public key used during the handshake.
        /// </param>
        /// <param name="b">
        ///   The server's ephemeral public key used during the handshake.
        /// </param>
        /// <returns>
        ///   The Boxer/Unboxer pair that a client or server can use to
        ///   communicate with the other.
        /// </returns>
        public static (Boxer, Unboxer) Build(
            byte[] derived_secret,
            byte[] foreing_pubkey,
            byte[] self_pubkey,
            byte[] network_key,
            byte[] a,
            byte[] b
        )
        {
            var common = CryptoHash.Sha256(CryptoHash.Sha256(derived_secret));

            var send_key = CryptoHash.Sha256(Utils.Concat(common, foreing_pubkey));
            var recv_key = CryptoHash.Sha256(Utils.Concat(common, self_pubkey));

            var send_nonce = new byte[24];
            var recv_nonce = new byte[24];

            var bhmac = SecretKeyAuth.Sign(b, network_key);
            var ahmac = SecretKeyAuth.Sign(a, network_key);

            Buffer.BlockCopy(send_nonce, 0, bhmac, 0, 24);
            Buffer.BlockCopy(recv_nonce, 0, ahmac, 0, 24);

            var boxer = new Boxer(send_key, send_nonce);
            var unboxer = new Unboxer(recv_key, recv_nonce);

            return (boxer, unboxer);
        }
    }
}
