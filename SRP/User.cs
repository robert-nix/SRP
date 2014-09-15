using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Numerics;
using System.Text;

namespace SRP
{
    public class User
    {
        SRP srp;
        string username;
        public string Password { get; set; }
        public byte[] SessionKey { get; private set; }

        RandomNumberGenerator random = new RNGCryptoServiceProvider();
        public BigInteger a;
        public BigInteger A { get; set; }
        public BigInteger S { get; private set; }
        public byte[] M { get; private set; }
        public byte[] HAMK { get; private set; }
        public bool Authenticated { get; private set; }

        public User(SRP srp, string username)
        {
            this.srp = srp;
            this.username = username;

            var aBuf = new byte[256];
            random.GetBytes(aBuf);
            a = aBuf.ToBigIntegerBE();

            A = BigInteger.ModPow(srp.g, a, srp.N);
        }

        public void ProcessChallenge(BigInteger B, BigInteger salt)
        {
            var hasher = srp.Hasher;
            var uBuf = hasher.ComputeHash(
                A.ToBEByteArray(0x100)
                .Concat(B.ToBEByteArray(0x100)));
            var u = uBuf.ToBigIntegerBE();

            var key = new VerificationKey(srp, username, Password, salt.ToBEByteArray().ToHex());

            var kBuf = hasher.ComputeHash(
                srp.N.ToBEByteArray(0x100)
                .Concat(srp.g.ToBEByteArray(0x100)));
            var k = kBuf.ToBigIntegerBE();

            // S = (B - k*(g^x)) ^ (a + ux)
            S = BigInteger.ModPow(
                B - k * BigInteger.ModPow(srp.g, key.x, srp.N),
                a + u * key.x,
                srp.N);
            if (S < 0)
                S += srp.N;
            SessionKey = hasher.ComputeHash(S.ToBEByteArray(0x100));

            M = srp.CalculateM(Encoding.UTF8.GetBytes(username), salt, A, B, SessionKey);
            HAMK = srp.CalculateHAMK(A, M, SessionKey);
        }
    
        public void VerifySession(byte[] hamk)
        {
            Authenticated = hamk.SequenceEqual(HAMK);
        }
    }
}
