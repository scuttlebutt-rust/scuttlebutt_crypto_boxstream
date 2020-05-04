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
    public class Boxer : BoxStream
    {
        public Boxer(byte[] key, byte[] nonce)
        {
            this.key = key;
            this.nonce = nonce;
        }

        byte[] Box(byte[] msg)
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

            // TODO: Manage endian-ness
            var size = BitConverter.GetBytes(body.Length);
            Buffer.BlockCopy(size, 0, tag, 0, LEN_SIZE);

            var header = SecretBox.Create(tag, nonce, key);
            Buffer.BlockCopy(box, 0, header, 0, HEAD_LEN);
            Buffer.BlockCopy(box, HEAD_LEN, body, TAG_SIZE, msg.Length);

            Utilities.Increment(nonce);

            return box;
        }
    }
}
