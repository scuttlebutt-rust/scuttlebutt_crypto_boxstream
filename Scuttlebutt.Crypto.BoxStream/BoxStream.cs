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

namespace Scuttlebutt.Crypto.BoxStream
{
    /// <summary>
    ///   Base class with common attributes for boxing and unboxing
    /// </summary>
    public abstract class BoxStream
    {
        /// <summary>
        ///   Derived key used for encryption at sender point and decryption
        ///   at the receiver point, every pair of <see cref="Boxer" /> and
        ///   <see cref="Unboxer" /> has two different keys, one for sending
        ///   and another for receiving.
        /// </summary>
        protected byte[] key;
        /// <summary>
        ///   The nonce derived from the shared secrets, it is incremented
        ///   with every message sent or received.
        /// </summary>
        protected byte[] nonce;

        /// <summary>
        ///   The size of the body authentication tag that is stored with every
        ///   secret box to detect tampering.
        /// </summary>
        protected const int TAG_SIZE = 16;
        /// <summary>
        ///   The size of the field that stores the length of the message.
        /// </summary>
        protected const int LEN_SIZE = 2;
        /// <summary>
        ///   The size of the header.
        /// </summary>
        protected const int HEAD_LEN = LEN_SIZE + TAG_SIZE + TAG_SIZE;
        /// <summary>
        ///   The maximum size of the body.
        /// </summary>
        protected const int MAX_SIZE = 4 * 1024;
    }
}
