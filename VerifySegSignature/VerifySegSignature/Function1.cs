using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Security.Cryptography;

namespace VerifySegSignature
{
    public static class Function1
    {
        const string pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJxzXoZ/LFxPXvfJ2MBMjhptT691J\n" +
                           "178zwID1EbO0MeB/fbhL8y3hqRWlIg0wTNq8NjWXlAjzjQ/qUxHq82xTMQ==\n-----END PUBLIC KEY-----\n";
        [FunctionName("VerifySignature")]
        public static async Task<IActionResult> VerifySignature(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string name = req.Query["name"];
            string signatureFromHeader = req.Headers["Request-Signature"];
            log.LogInformation($"Sig = {signatureFromHeader}");
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            log.LogInformation($"Request Body as String: \n{requestBody}");

            MemoryStream ms = new MemoryStream();
            await req.Body.CopyToAsync(ms);

            byte[] requestByteArray = ms.ToArray();

            log.LogInformation($"pem before splitting:{pem}");
            // Separate the public key from the surrounding text
            string publicKey = SplitKeyFromFile(pem);
            log.LogInformation($"publicKey: {publicKey}");
            byte[] keyByteArray = Convert.FromBase64String(publicKey);

            string signatureBase64Encoded = signatureFromHeader.Replace("ecdsa=", "");
            log.LogInformation($"signatureBase64Encoded:{signatureBase64Encoded}");

            //Base 64 Decode
            byte[] sigDecoded = Convert.FromBase64String(signatureBase64Encoded);

            var dsa = ECDsa.Create();
            dsa.ImportSubjectPublicKeyInfo(keyByteArray, out _);

            bool verificationResult = dsa.VerifyData(requestByteArray, sigDecoded, HashAlgorithmName.SHA256);

            log.LogInformation($"Verification Result: {verificationResult}");

            return new OkObjectResult(verificationResult);
        }

        private static string SplitKeyFromFile(string sKey)
        {
            // Only needed if .Net 3.1
            string start = "-----BEGIN PUBLIC KEY-----\n";
            string end = "\n-----END PUBLIC KEY-----";

            int pFrom = sKey.IndexOf(start) + start.Length;
            int pTo = sKey.LastIndexOf(end);

            String result = sKey.Substring(pFrom, pTo - pFrom);
            return result;
        }
    }
}
