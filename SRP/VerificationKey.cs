using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Numerics;

namespace SRP
{
    public class VerificationKey
    {
        public BigInteger Salt { get; private set; }
        public BigInteger Key { get; private set; }

        public BigInteger x { get; private set; }

        public string SaltHex
        {
            get
            {
                return Salt.ToBEByteArray().ToHex();
            }
        }

        public string KeyHex
        {
            get
            {
                return Key.ToBEByteArray().ToHex();
            }
        }

        /// <summary>
        /// Creates a VerificationKey from a username/password pair.  Intended
        /// for use by the client on each login and by the server on account
        /// creation only (after which the server should store the generated
        /// VerificationKey)
        /// </summary>
        /// <param name="srp"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        public VerificationKey(SRP srp, string username, string password, string salt = null)
        {
            if (salt == null)
            {
                var random = new RNGCryptoServiceProvider();
                // This is beyond overkill; for consistency with Strife.
                var saltBuf = new byte[256];
                random.GetBytes(saltBuf);
                Salt = saltBuf.ToBigIntegerBE();
            }
            else
            {
                Salt = salt.ToBytes().ToBigIntegerBE();
            }

            var hasher = srp.Hasher;
            var ucpHash = hasher.ComputeHash(
                Encoding.UTF8.GetBytes(String.Format("{0}:{1}", username, password)));
            var ucpLen = ucpHash.Length;
            var _salt = Salt.ToBEByteArray();
            x = hasher.ComputeHash(_salt.Concat(ucpHash)).ToBigIntegerBE();
            Key = BigInteger.ModPow(srp.g, x, srp.N);
        }

        /// <summary>
        /// Creates a VerificationKey from an existing salt/key pair given in
        /// the big-endian hexadecimal encoding of its bytes (a la OpenSSL's
        /// BN_bn2hex/hex2bn).
        /// </summary>
        /// <param name="saltHex"></param>
        /// <param name="keyHex"></param>
        public VerificationKey(string saltHex, string keyHex)
        {
            Salt = saltHex.ToBytes().ToBigIntegerBE();
            Key = keyHex.ToBytes().ToBigIntegerBE();
        }
    }
}
