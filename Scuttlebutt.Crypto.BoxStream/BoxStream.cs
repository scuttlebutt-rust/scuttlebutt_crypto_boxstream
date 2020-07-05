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
    public abstract class BoxStream
    {
        protected byte[] key;
        protected byte[] nonce;

        protected const int TAG_SIZE = 16;
        protected const int LEN_SIZE = 2;
        protected const int HEAD_LEN = 2 + 16 + 16;
        protected const int MAX_SIZE = 4 * 1024;
    }
}
