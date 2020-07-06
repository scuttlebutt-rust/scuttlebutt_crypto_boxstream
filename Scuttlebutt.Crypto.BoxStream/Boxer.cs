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
using System.Threading.Tasks;
using Sodium;

namespace Scuttlebutt.Crypto.BoxStream
{
    /// <summary>
    ///   This class sends messages to the destination
    /// </summary>
    public class Boxer : BoxStream
    {
        /// <summary>
        ///   Creates a boxer instance that automatically increments the nonce
        ///   with every message sent
        /// </summary>
        /// <param name="key">The key derived from the shared secrets</param>
        /// <param name="nonce">The nonce derived from the shared secrets</param>
        public Boxer(byte[] key, byte[] nonce)
        {
            this.key = key;
            this.nonce = nonce;
        }

        /// <summary>
        ///   Encrypts and boxes a given message
        /// </summary>
        /// <returns>An array with the message ready to be sent</returns>
        /// <param name="msg">The message to be encrypted</param>
        /// <exception cref="OverflowException">
        ///   Thrown when the message excedes the 4096 bytes maximum capacity
        /// </exception>
        public byte[] Box(byte[] msg)
        {
            if (msg.Length > 4096)
            {
                throw new OverflowException(
                    $"Message is {msg.Length}, max message size is 4096 bytes"
                );
            }

            var box = new byte[HEAD_LEN + msg.Length];
            var tag = new byte[TAG_SIZE + LEN_SIZE];

            var body = SecretBox.Create(msg, nonce, key);
            Buffer.BlockCopy(body, 0, tag, LEN_SIZE, TAG_SIZE);

            // Represent size as 16 bit unsigned integer
            var size = BitConverter.GetBytes((UInt16)(int)msg.Length);
            // Put the size in bigendian
            if (BitConverter.IsLittleEndian)
                Array.Reverse(size);

            Buffer.BlockCopy(size, 0, tag, 0, LEN_SIZE);

            var header = SecretBox.Create(tag, nonce, key);

            // Fill the box with the contents of the body and header
            Buffer.BlockCopy(header, 0, box, 0, HEAD_LEN);
            Buffer.BlockCopy(body, TAG_SIZE, box, HEAD_LEN, msg.Length);

            Utilities.Increment(nonce);

            return box;
        }
    }
}
