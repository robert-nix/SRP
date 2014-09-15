using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SRP
{
    public class StrifeSRP : SRP
    {
        // N and Salt grabbed from the Strife binary:
        static byte[] _N = (
"DA950C6C97918CAE89E4F5ECB32461032A217D740064BC12FC0723CD204BD02A" +
"7AE29B53F3310C13BA998B7910F8B6A14112CBC67BDD2427EDF494CB8BCA6851" +
"0C0AAEE5346BD320845981546873069B337C073B9A9369D500873D647D261CCE" +
"D571826E54C6089E7D5085DC2AF01FD861AE44C8E64BCA3EA4DCE942C5F5B89E" +
"5496C2741A9E7E9F509C261D104D11DD4494577038B33016E28D118AE4FD2E85" +
"D9C3557A2346FAECED3EDBE0F4D694411686BA6E65FEE43A772DC84D394ADAE5" +
"A14AF33817351D29DE074740AA263187AB18E3A25665EACAA8267C16CDE064B1" +
"D5AF0588893C89C1556D6AEF644A3BA6BA3F7DEC2F3D6FDC30AE43FBD6D144BB").ToBytes();

        static string GlobalSalt = "WrAq&paHAc_e7aRu-utE=rePr72h*nUs-!d@BrekaS*ajax!faDAheC?3eceK!?u";

        static StrifeSRP()
        {
        }

        public StrifeSRP()
        {
            Hasher = new SHA256Managed();
            N = _N.ToBigIntegerBE();
            g = new BigInteger(2);
        }

        public void SetPassword(User user, string password, string userSalt)
        {
            user.Password = Hasher.ComputeHash(Encoding.UTF8.GetBytes(
                GlobalSalt + password + userSalt)).ToHex().ToLower();
        }
    }
}
