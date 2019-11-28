using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using Newtonsoft.Json;

namespace certcheck
{
    internal class Options
    {
        [Option('c', "client-id", Required = true,
            HelpText = "Client ID")]
        public string ClientId { get; set; }

        [Option('s', "client-secret", Required = true,
            HelpText = "Client secret")]
        public string ClientSecret { get; set; }

        private string _authHeaderValue = null;
        public string AuthHeaderValue
        {
            get
            {
                return _authHeaderValue ?? (_authHeaderValue =
                           "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ClientId}:{ClientSecret}")));
            }
        }

        [Option('f', "fi-ref", Required = true,
            HelpText = "FI reference ID")]
        public string FiReferenceId { get; set; }

        [Option('u', "check-url", Required = true,
            HelpText = "Check URL")]
        public string CheckUrl { get; set; }

        [Option('m', "email-to", Required = true,
            HelpText = "Addressee e-mail")]
        public string EmailAddressee { get; set; }

        [Option("email-user", Required = true,
            HelpText = "User name for e-mail server")]
        public string EmailUser { get; set; }

        [Option("email-pass", Required = true,
            HelpText = "User password for e-mail server")]
        public string EmailPassword { get; set; }

        [Option("email-server", Required = true,
            HelpText = "E-mail server address")]
        public string EmailServer { get; set; }

        [Option("email-port", Required = true,
            HelpText = "E-mail server port")]
        public int EmailServerPort { get; set; }

        [Option("no-ssl", Default = false,
            HelpText = "Do not use SSL to e-mail server")]
        public bool EmailNoSsl { get; set; }

        [Option('i', "initial-dir", Required = true,
            HelpText = "Certificates initial directory")]
        public string InitialCertDirectory { get; set; }

        [Option('r', "regular-dir", Required = true,
            HelpText = "Certificates regular directory")]
        public string RegularCertDirectory { get; set; }

        [Option('e', "error-dir", Required = true,
            HelpText = "Invalid certificates directory")]
        public string InvalidCertDirectory { get; set; }

        [Option('x', "keep-failed", Required = false,
            Default = false,
            HelpText = "Keep failed certificates")]
        public bool KeepFailed { get; set; }
    }

    internal class CheckerApiResponse
    {
        public class eIDASClass
        {
            public ValidityClass Validity { get; set; }
        }

        public class ValidityClass
        {
            public bool ValidQTSP { get; set; }
            public bool validSignature { get; set; }
            public bool NotRevoked { get; set; }
            public bool NotExpired { get; set; }
        }

        public eIDASClass eIDAS { get; set; }
    }

    internal class ValidityChecker
    {
        private readonly Options _cfg;

        public ValidityChecker(Options cfg)
        {
            _cfg = cfg;
        }

        public void RunChecks()
        {
            // Regular directory check
            (IEnumerable<(string fileName, string errorReason)> invalidCerts, IEnumerable<(string fileName, Exception exception)> unprocessedCerts) =
                ValidateCertificates(_cfg.RegularCertDirectory);

            invalidCerts.ToList().ForEach(x =>
            {
                var body = string.Format(Properties.Resources.EmailRegularCheckTemplate, x.fileName, x.errorReason, _cfg.InvalidCertDirectory);
                SendEmail(Properties.Resources.EmailRegularCheckSubject, body);
                Console.WriteLine($@"{x.fileName}: {x.errorReason}");
            });
            unprocessedCerts.ToList().ForEach(x => { Console.Error.WriteLine($@"{x.fileName}: {x.exception.Message}"); });

            // Initial directory check
            (invalidCerts, unprocessedCerts) = ValidateCertificates(_cfg.InitialCertDirectory, _cfg.RegularCertDirectory);

            invalidCerts.ToList().ForEach(x =>
            {
                var body = string.Format(Properties.Resources.EmailInitialCheckTemplate, x.fileName, x.errorReason, _cfg.InvalidCertDirectory);
                SendEmail(Properties.Resources.EmailInitialCheckSubject, body);
                Console.WriteLine($@"{x.fileName}: {x.errorReason}");
            });
            unprocessedCerts.ToList().ForEach(x => { Console.Error.WriteLine($@"{x.fileName}: {x.exception.Message}"); });
        }

        private void SendEmail(string subject, string body)
        {
            using (var smtpClient = new SmtpClient(_cfg.EmailServer, _cfg.EmailServerPort))
            {
                smtpClient.EnableSsl = !_cfg.EmailNoSsl;
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(_cfg.EmailUser, _cfg.EmailPassword);

                var message = new MailMessage(_cfg.EmailUser, _cfg.EmailAddressee)
                {
                    BodyEncoding = Encoding.UTF8,
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };

                smtpClient.Send(message);
            }
        }

        private (IEnumerable<(string fileName, string errorReason)> invalidCerts, IEnumerable<(string fileName, Exception)> unprocessedCerts)
            ValidateCertificates(string directory, string moveValidTo = null)
        {
            var invalidCerts = new ConcurrentBag<(string fileName, string errorReason)>();
            var unprocessedCerts = new ConcurrentBag<(string fileName, Exception exception)>();

            Parallel.ForEach(Directory.EnumerateFiles(directory), certFile =>
            {
                string baseCertName = Path.GetFileName(certFile);
                try
                {
                    string cert = ReadCertFile(certFile);

                    if (!IsValidCertificate(cert, out List<string> errors))
                    {
                        if (!_cfg.KeepFailed)
                        {
                            File.Move(certFile, $"{_cfg.InvalidCertDirectory}\\{baseCertName}");
                        }
                        invalidCerts.Add((baseCertName, string.Join(',', errors)));
                    }
                    else if (moveValidTo != null)
                    {
                        File.Move(certFile, $"{moveValidTo}\\{baseCertName}");
                    }
                }
                catch (Exception e)
                {
                    unprocessedCerts.Add((baseCertName, e));
                }
            });

            return (invalidCerts, unprocessedCerts);
        }

        private string ReadCertFile(string fileName)
        {
            X509Certificate x509 = new X509Certificate2(fileName);
            string cert =  Convert.ToBase64String(x509.GetRawCertData());

            return cert;
        }

        private bool IsValidCertificate(string cert, out  List<string> errors)
        {
            HttpWebRequest request = WebRequest.Create(_cfg.CheckUrl) as HttpWebRequest;
            if (request == null)
            {
                throw new ApplicationException("Can't create request to cert check API");
            }

            request.Headers.Add("Authorization", _cfg.AuthHeaderValue);
            request.Headers.Add("fi_reference_id", _cfg.FiReferenceId);
            request.Headers.Add("version","1");
            request.Headers.Add("eidas", cert);

            HttpWebResponse response = (HttpWebResponse)request.GetResponse();

            errors = new List<string>();

            if (response.StatusCode != HttpStatusCode.OK)
            {
                errors.Add(string.Format(Properties.Resources.ErrorReasonInvalideStatusCode, response.StatusCode));
                return false;
            }

            CheckerApiResponse apiResponse;
            using (var reader = new StreamReader(response.GetResponseStream() ?? throw new ApplicationException("API cert check response without body"), Encoding.UTF8))
            {
                string body = reader.ReadToEnd();
                apiResponse = JsonConvert.DeserializeObject<CheckerApiResponse>(body);
            }

            bool valid = true;

            if (!apiResponse.eIDAS.Validity.ValidQTSP)
            {
                errors.Add(Properties.Resources.ErrorReasonInvalidQTSP);
                valid = false;
            }

            if (!apiResponse.eIDAS.Validity.validSignature)
            {
                errors.Add(Properties.Resources.ErrorReasonInvalidSignature);
                valid = false;
            }

            if (!apiResponse.eIDAS.Validity.NotRevoked)
            {
                errors.Add(Properties.Resources.ErrorReasonRevoked);
                valid = false;
            }

            if (!apiResponse.eIDAS.Validity.NotExpired)
            {
                errors.Add(Properties.Resources.ErrorReasonExpired);
                valid = false;
            }

            return valid;
        }
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            try
            {
                Parser.Default.ParseArguments<Options>(args)
                    .WithParsed(opts =>
                    {
                        var vc = new ValidityChecker(opts);
                        vc.RunChecks();
                    });
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(Properties.Resources.FatalErrorHeader, e.Message);
                return -1;
            }

            return 0;
        }
    }
}
