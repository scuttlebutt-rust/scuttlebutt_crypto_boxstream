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
    public class Unboxer : BoxStream
    {
        public Unboxer(byte[] key, byte[] nonce)
        {
            this.key = key;
            this.nonce = nonce;
        }

        async Task<byte[]> Unbox(Stream msg)
        {
            var enc_header = new byte[HEAD_LEN];
            await msg.ReadAsync(enc_header, 0, HEAD_LEN);

            var header = SecretBox.Open(enc_header, nonce, key);

            return header;
        }
    }
}
