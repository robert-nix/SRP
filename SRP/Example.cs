using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using SRP;

namespace Example
{
    class Example
    {
        /// <summary>
        /// Returns an authenticated HttpClient for use with S2's internal API. 
        /// Please note that System.Net.HttpClient requires .NET 4.5
        /// </summary>
        /// <param name="username">e-mail address of the account</param>
        /// <param name="password">plaintext password</param>
        /// <returns></returns>
        static async Task<HttpClient> StrifeAuth(string username, string password)
        {
            // Helper function for dealing with PHP's serialization format
            Func<string, string, string> getString = (phpStr, keyName) =>
            {
                keyName = '"' + keyName + '"';
                var index = phpStr.IndexOf(keyName);
                if (index >= 0)
                {
                    var lenI = index + keyName.Length + 3;
                    var lenS = "";
                    for (var i = lenI; i < phpStr.Length; i++)
                    {
                        var c = phpStr[i];
                        if (c >= '0' && c <= '9')
                        {
                            lenS += phpStr[i];
                        }
                        else
                        {
                            break;
                        }
                    }
                    var len = Convert.ToInt32(lenS);
                    var strI = lenI + lenS.Length + 2;
                    return phpStr.Substring(strI, len);
                }
                else
                {
                    return null;
                }
            };

            var client = new HttpClient();
            var baseUrl = "http://prod.s2ogi.strife.com";
            client.DefaultRequestHeaders.TryAddWithoutValidation(
                "User-Agent",
                // Mimick S2's client UA format
                "S2/SRP/0.1/windows/x86");
            
            // Do the SRP exchange
            // There's a bit of fuss (leading to the usage ToBEByteArray()) due
            // to the differences between C#'s BigInteger and PHP's libgmp.
            var srp = new StrifeSRP();
            var user = new User(srp, username);
            var authReqContent = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                {"A", user.A.ToBEByteArray().ToHex()}
            });
            var authReqRes = await client.PostAsync(
                baseUrl + "/c/igames/authenticate/email/" + username, authReqContent);
            var authReqResStr = await authReqRes.Content.ReadAsStringAsync();

            var salt = getString(authReqResStr, "salt").ToBytes().ToBigIntegerBE();
            var salt2 = getString(authReqResStr, "salt2");
            srp.SetPassword(user, password, salt2);

            var B = getString(authReqResStr, "B").ToBytes().ToBigIntegerBE();
            user.ProcessChallenge(B, salt);

            var proofReqContent = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                {"proof", user.M.ToHex()},
                {"identities", "strife"}
            });
            var proofReqRes = await client.PostAsync(
                baseUrl + "/c/igames/session/email/" + username, proofReqContent);
            var proofReqResStr = await proofReqRes.Content.ReadAsStringAsync();

            var serverProof = (getString(proofReqResStr, "serverProof") ?? "").ToBytes().ToBigIntegerBE();
            user.VerifySession(serverProof.ToBEByteArray());

            if (!user.Authenticated)
            {
                // If VerifySession failed, we must bail because the server's
                // identity isn't verified:
                throw new Exception("Authentication failed");
            }

            // Add the authorization header to the client and return it
            var accountId = getString(proofReqResStr, "account_id");

            client.DefaultRequestHeaders.TryAddWithoutValidation(
                "X-S2-Authorization",
                String.Format("c igames {0} {1}", accountId, user.SessionKey.ToHex().ToLower()));
            return client;
        }
    }
}
