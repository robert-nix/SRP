using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Numerics;
using System.Security.Cryptography;

namespace SRP
{
    public class SRP
    {
        /// <summary>
        /// A generator modulo N
        /// </summary>
        public BigInteger g { get; protected set; }

        /// <summary>
        /// The modulus (a safe prime) to perform exponentiation within.
        /// </summary>
        public BigInteger N { get; protected set; }

        public HashAlgorithm Hasher { get; protected set; }

        public virtual byte[] CalculateM(byte[] I, BigInteger s, BigInteger A, BigInteger B, byte[] K)
        {
            var H_N = Hasher.ComputeHash(N.ToBEByteArray(0x100));
            var H_g = Hasher.ComputeHash(g.ToBEByteArray(0x100));
            var H_I = Hasher.ComputeHash(I);
            var H_xor = new byte[H_N.Length];
            for (var i = 0; i < H_N.Length; i++)
            {
                H_xor[i] = (byte)(H_N[i] ^ H_g[i]);
            }

            return Hasher.ComputeHash(
                H_xor
                .Concat(H_I)
                .Concat(s.ToBEByteArray(0x100))
                .Concat(A.ToBEByteArray(0x100))
                .Concat(B.ToBEByteArray(0x100))
                .Concat(K));
        }

        public virtual byte[] CalculateHAMK(BigInteger A, byte[] M, byte[] SessionKey)
        {
            return Hasher.ComputeHash(
                A.ToBEByteArray()
                .Concat(M)
                .Concat(SessionKey));
        }
    }
}
