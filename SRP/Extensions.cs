using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace SRP
{
    public static class Extensions
    {
        static char NibbleToHex(int n)
        {
            if (n > 15 || n < 0)
            {
                throw new InvalidOperationException();
            }
            if (n < 10)
            {
                return (char)('0' + n);
            }
            else
            {
                return (char)('a' + n - 10);
            }
        }

        static int HexToNibble(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }
            if (c >= 'A' && c <= 'F')
            {
                return c - 'A' + 10;
            }
            if (c >= 'a' && c <= 'f')
            {
                return c - 'a' + 10;
            }
            throw new InvalidOperationException();
        }

        public static string ToHex(this byte[] buf)
        {
            char[] result = new char[buf.Length * 2];
            for (var i = 0; i < buf.Length; i++)
            {
                result[2 * i + 0] = NibbleToHex(0xf & (buf[i] >> 4));
                result[2 * i + 1] = NibbleToHex(0xf & buf[i]);
            }
            return new string(result);
        }

        public static byte[] ToBytes(this string s)
        {
            if ((s.Length & 1) != 0)
            {
                s = ' ' + s;
            }
            byte[] result = new byte[s.Length >> 1];
            if (s.Length == 0)
            {
                return result;
            }
            for (var i = 0; i < result.Length; i++)
            {
                result[i] = (byte)(HexToNibble(s[2 * i + 0]) << 4);
                result[i] |= (byte)HexToNibble(s[2 * i + 1]);
            }
            return result;
        }

        public static byte[] Concat(this byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Array.Copy(a, result, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }

        public static byte[] ToBEByteArray(this BigInteger n, int fixedSize = 0)
        {
            var result = BigInteger.Abs(n).ToByteArray();
            var len = result.Length;
            if (fixedSize > len)
            {
                Array.Resize(ref result, fixedSize);
            }
            Array.Reverse(result);
            if (fixedSize < len && result[0] == 0)
            {
                result = result.Skip(1).ToArray();
            }
            return result;
        }

        public static BigInteger ToBigIntegerBE(this byte[] buf)
        {
            var nBuf = new byte[buf.Length + 1];
            nBuf[0] = 0;
            Array.Copy(buf, 0, nBuf, 1, buf.Length);
            Array.Reverse(nBuf);
            return new BigInteger(nBuf);
        }
    }
}
