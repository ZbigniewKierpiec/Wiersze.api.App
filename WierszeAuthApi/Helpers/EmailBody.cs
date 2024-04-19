namespace WierszeAuthApi.Helpers
{
    public static class EmailBody
    {

        public static string  EmailStringBody(string email,string emailToken)
        {
            return $@"<html>
<head>

</head>
<body style=""font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;"">
  <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""background-color: #f4f4f4;"">
    <tr>
      <td align=""center"">
        <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""600"" style=""margin-top: 30px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);"">
          <tr>
            <td align=""center"" style=""padding: 40px 0 30px 0;"">
              <img src=""https://yourwebsite.com/logo.png"" alt=""Logo"" width=""150"" style=""display: block;"">
            </td>
          </tr>
          <tr>
            <td align=""center"" style=""padding: 0 20px;"">
              <h1 style=""font-size: 24px; color: #333333; margin-bottom: 20px;"">Password Reset</h1>
              <p style=""font-size: 16px; color: #666666; margin-bottom: 20px;"">You are receiving this email because a password reset request has been made for your account. If you did not request this change, please ignore this email.</p>
              <p style=""font-size: 16px; color: #666666; margin-bottom: 20px;"">To reset your password, click the button below:</p>
              <a href=""https://localhost:4200/reset?email={email}&code={emailToken}"" style=""background-color: #007bff; color: #ffffff; text-decoration: none; padding: 12px 20px; border-radius: 5px; display: inline-block; font-size: 16px; margin-bottom: 20px;"">Reset Password</a>
             
            </td>
          </tr>
          <tr>
            <td align=""center"" style=""padding: 20px; background-color: #f9f9f9; border-top: 1px solid #dddddd;"">
              <p style=""font-size: 14px; color: #666666; margin: 0;"">If you have any questions, feel free to contact us at <a href=""mailto:info@yourwebsite.com"" style=""color: #007bff; text-decoration: none;"">info@yourwebsite.com</a>.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>   ";
        }

    }
}
