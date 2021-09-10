using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace MSAL_Token_Validation
{
    class Program
    {
        public class Key
        {
            public string kid { get; set; }
            public string[] x5c { get; set; }
        }

        static ConsoleColor _originalColor;
        static HttpClient _httpClient;

        static async Task Main(string[] args)
        {
            _originalColor = Console.ForegroundColor;
            _httpClient = new HttpClient();

            var certDictionary = await GetPublicKeys();

            while (true)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("Please enter your access token> ");

                Console.ForegroundColor = _originalColor;

                var token = Console.ReadLine();

                try
                {

                    var userId = await ValidateToken(token, certDictionary);

                    Console.WriteLine();
                    Console.WriteLine();

                    if (userId != null)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("Token signature is valid! - UserId = " + userId);
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("Token signature is valid but there was not preferred_username claim value");
                    }

                }
                catch (GraphTokenException gte)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Cannot validate token signature - this looks like a graph token... can't do that, make a call to Graph to validate this token");

                    if (gte.Name != null)
                    {
                        Console.WriteLine();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("But... we sent this to Graph and it said it was OK! (Display name = " + gte.Name + ")");
                    }

                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Token signature is invalid");
                }

                Console.WriteLine();
                Console.ForegroundColor = _originalColor;
            }
        }

        //This method validates the signature of a given JWT token
        public static async Task<string> ValidateToken(string token, Dictionary<string, X509Certificate2> allCerts)
        {
            if (token == null)
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();

            //This property displays more verbose debugging information
            IdentityModelEventSource.ShowPII = true;

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeyResolver = (s, securityToken, identifier, parameters) => allCerts.Select(x => new X509SecurityKey(x.Value, x.Key)),

                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                
                var userId = jwtToken.Claims.First(x => x.Type == "preferred_username").Value;

                return userId;
            }
            catch // Something went wrong...
            {
                //Find the audience claim from within the token and see if it's for Graph
                //If it is, we cannot verify the signature, but we can make a call to Graph
                //to validate the token

                var invalidToken = tokenHandler.ReadJwtToken(token);

                var audience = invalidToken.Claims.First(x => x.Type == "aud").Value;

                if (audience.Equals("https://graph.microsoft.com", StringComparison.OrdinalIgnoreCase) || audience.Equals("00000003-0000-0000-c000-000000000000", StringComparison.OrdinalIgnoreCase))
                {
                    var name = await CallGraph(token);

                    throw new GraphTokenException(name);
                }

                throw;
            }
        }

        //Try to call graph with the given token to prove its validity
        static async Task<string> CallGraph(string token)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "https://graph.microsoft.com/v1.0/me");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var body = await response.Content.ReadAsStringAsync();

            return JObject.Parse(body)["displayName"].Value<string>();
        }

        //Use the MS hosted well-known endpoint to download the certs used in validation
        //This is specific to microsoft issued tokens but the concept would be similar for
        //other identity providers
        static async Task<Dictionary<string, X509Certificate2>> GetPublicKeys()
        {
            Console.Write("Downloading oidc configuration...");

            var configurationUrl = "https://login.microsoftonline.com/common/.well-known/openid-configuration";

            var oidcConfig = await _httpClient.GetStringAsync(configurationUrl);
            var oidcJson = JObject.Parse(oidcConfig);

            Console.WriteLine(" Done");

            Console.Write("Downloading public keys...");

            var jwksUri = oidcJson["jwks_uri"].Value<string>();
            var keysConfig = await _httpClient.GetStringAsync(jwksUri);
            var keysConfigJson = JObject.Parse(keysConfig);

            var allKeys = keysConfigJson["keys"].ToObject<Key[]>();

            Console.WriteLine(" Done");

            Console.WriteLine();

            var certDictionary = new Dictionary<string, X509Certificate2>();

            foreach (var key in allKeys)
            {
                foreach (var x5c in key.x5c)
                {
                    certDictionary[key.kid] = new X509Certificate2(Encoding.UTF8.GetBytes("-----BEGIN CERTIFICATE-----\n" + x5c + "\n-----END CERTIFICATE-----"));
                }
            }

            return certDictionary;
        }
    }

    public class GraphTokenException : Exception 
    { 
        public GraphTokenException(string name)
        {
            Name = name;
        }

        public string Name { get; }
    }
}
