using MailKit.Net.Smtp;
using MimeKit;
using WierszeAuthApi.Models;

namespace WierszeAuthApi.UtilityService
{
    public class EmailService : IEmailService
    {

        private readonly IConfiguration _config;
        public EmailService(IConfiguration configuration)
        {
            _config = configuration;   
        }

        public  void SendEmail(EmailModel emailModel)
        {

            var emaiMessage = new MimeMessage();
            var from = _config["EmailSettings:From"];
            emaiMessage.From.Add(new MailboxAddress("Zee", from));
            emaiMessage.To.Add(new MailboxAddress(emailModel.To , emailModel.To));
            emaiMessage.Subject = emailModel.Subject;
            emaiMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                Text = string.Format(emailModel.Content)
            };

            using(var client = new SmtpClient())
            {
                try
                {
                    client.Connect(_config["EmailSettings:SmtpServer"], 465, true);
                    client.Authenticate(_config["EmailSettings:From"], _config["EmailSettings:Password"]);
                    client.Send(emaiMessage);
                }
                catch (Exception)
                {

                    throw;
                }

                finally
                {
                    client.Disconnect(true);
                    client.Dispose();
                }
            }

        }



    }
}
