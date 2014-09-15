using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SRP
{
    public class Verifier
    {
        SRP srp;
        string username;
        BigInteger A;
        BigInteger b;
        public BigInteger B { get; private set; }
        public byte[] SessionKey { get; private set; }
        byte[] M;
        public byte[] HAMK { get; private set; }
        public bool Authenticated { get; private set; }

        RandomNumberGenerator random = new RNGCryptoServiceProvider();

        public Verifier(SRP srp, VerificationKey key, string username, BigInteger A)
        {
            this.srp = srp;
            this.username = username;
            this.A = A;

            var hasher = srp.Hasher;

            var bBuf = new byte[256 / 8];
            random.GetBytes(bBuf);
            b = bBuf.ToBigIntegerBE();

            var NBuf = srp.N.ToBEByteArray();
            var NBufLen = NBuf.Length;
            var gBuf = srp.g.ToBEByteArray();
            var kBuf = hasher.ComputeHash(NBuf.Concat(gBuf));
            var k = kBuf.ToBigIntegerBE();

            B = k * key.Key + BigInteger.ModPow(srp.g, b, srp.N);

            var BBuf = B.ToBEByteArray();
            var ABuf = A.ToBEByteArray();
            var uBuf = hasher.ComputeHash(ABuf.Concat(BBuf));
            var u = uBuf.ToBigIntegerBE();

            var S = BigInteger.ModPow(A * BigInteger.ModPow(key.Key, u, srp.N), b, srp.N);
            SessionKey = hasher.ComputeHash(S.ToBEByteArray());

            M = srp.CalculateM(Encoding.UTF8.GetBytes(username), key.Salt, A, B, SessionKey);
            HAMK = srp.CalculateHAMK(A, M, SessionKey);
        }

        public byte[] VerifySession(byte[] m)
        {
            Authenticated = m.SequenceEqual(M);
            if (Authenticated)
            {
                return HAMK;
            }
            else
            {
                return null;
            }
        }
    }
}
