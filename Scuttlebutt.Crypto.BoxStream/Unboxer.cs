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
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Sodium;

namespace Scuttlebutt.Crypto.BoxStream
{
    /// <summary>
    ///   This reads messages form an incoming box stream
    /// </summary>
    public class Unboxer : BoxStream
    {
        /// <summary>
        ///   Creates an unboxer instance that automatically increments the nonce
        ///   with every message sent
        /// </summary>
        /// <param name="key">The key derived from the shared secrets</param>
        /// <param name="nonce">The nonce derived from the shared secrets</param>
        public Unboxer(byte[] key, byte[] nonce)
        {
            this.key = key;
            this.nonce = nonce;
        }

        /// <summary>
        ///   Asynchronously reads a message from the stream.
        /// </summary>
        /// <returns>An array with the decrypted message</returns>
        /// <param name="msg">A stream with incoming messages</param>
        public async Task<byte[]> Unbox(Stream msg)
        {
            var enc_header = new byte[HEAD_LEN];
            await msg.ReadAsync(enc_header, 0, HEAD_LEN);

            var header = SecretBox.Open(enc_header, nonce, key);
            var length_buf = header.Take(2).ToArray();
            if (BitConverter.IsLittleEndian)
                Array.Reverse(length_buf);
            var length = BitConverter.ToUInt16(length_buf, 0);

            var boxed_body = new byte[length];
            await msg.ReadAsync(boxed_body, 0, length);

            var to_unbox = Utils.Concat(header.Skip(2).ToArray(), boxed_body);

            return SecretBox.Open(to_unbox, nonce, key);
        }
    }
}
