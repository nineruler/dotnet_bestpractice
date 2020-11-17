using BestPractice.Security;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace BestPractice.JWT
{
    public class JwtHelper
    {
        string _issuer = string.Empty;

        public JwtHelper()
        {
            _issuer = "nineruler";
        }

        public JwtHelper(string issuer)
        {
            _issuer = issuer;
        }

        public string CreateToken(TimeSpan expireTime, string aud, long userNo, long? userDeviceNo = null, string salt = null)
        {
            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor();

            securityTokenDescriptor.Claims = new Dictionary<string, object>();

            DateTime now = DateTime.Now;

            // iss : issuer
            securityTokenDescriptor.Issuer = _issuer;
            // iat : issued at
            securityTokenDescriptor.IssuedAt = now;
            // nbf : Not Before
            securityTokenDescriptor.NotBefore = now;
            // exp : expires
            securityTokenDescriptor.Expires = now.Add(expireTime);
            // aud : audience
            securityTokenDescriptor.Audience = aud.ToString();
            // user_no
            securityTokenDescriptor.Claims = new Dictionary<string, object>();
            securityTokenDescriptor.Claims.Add("user_no", userNo);

            if (userDeviceNo != null)
            {
                securityTokenDescriptor.Claims.Add("user_device_no", userDeviceNo);
            }

            long expireUnixTimestamp = ((DateTimeOffset)securityTokenDescriptor.Expires).ToUnixTimeSeconds();

            if (string.IsNullOrEmpty(salt))
            {
                salt = HashHelper.GetMd5(userNo.ToString() + expireUnixTimestamp.ToString());
            }

            if (salt.Length >= 16)
            {
                // signing credential
                securityTokenDescriptor.SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(salt)), SecurityAlgorithms.HmacSha256Signature);
            }

            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();

            JwtSecurityToken jwtSecurityToken = jwtHandler.CreateJwtSecurityToken(securityTokenDescriptor);

            string token = jwtHandler.WriteToken(jwtSecurityToken);

            return token;
        }

        public static JwtPayload ReadPayload(string token)
        {
            JwtSecurityToken jwtSecurityToken = new JwtSecurityTokenHandler().ReadJwtToken(token);

            return jwtSecurityToken.Payload;
        }

        public bool ValidateSigningCredential(string token, string aud, string salt = null)
        {
            long userNo = 0;
            
            try
            {
                JwtPayload payload = ReadPayload(token);

                if (string.IsNullOrEmpty(salt))
                {
                    Claim claim = payload.Claims.Where(t => t.Type == "user_no").FirstOrDefault();

                    userNo = Convert.ToInt64(claim.Value);

                    salt = HashHelper.GetMd5(userNo.ToString() + payload.Exp.ToString());
                }

                TokenValidationParameters tokenValidationParameters = new TokenValidationParameters();
                tokenValidationParameters.ValidIssuer = _issuer;
                tokenValidationParameters.ValidAudience = aud.ToString();
                tokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(salt));

                ClaimsPrincipal claimsPrincipal = new JwtSecurityTokenHandler().ValidateToken(token, tokenValidationParameters, out SecurityToken outToken);
            }
            catch (ArgumentNullException ex)
            {
                // 매개변수 Null
                return false;
            }
            catch (ArgumentException ex)
            {
                // 매개변수 오류
                return false;
            }
            catch (SecurityTokenDecryptionFailedException ex)
            {
                // 복호화 실패
                return false;
            }
            catch (SecurityTokenExpiredException ex)
            {
                // exp 만료
                return false;
            }
            catch (SecurityTokenInvalidAudienceException ex)
            {
                // aud 불일치
                return false;
            }
            catch (SecurityTokenInvalidLifetimeException ex)
            {
                // notbefore > expire
                return false;
            }
            catch (SecurityTokenInvalidSignatureException ex)
            {
                // 서명오류
                return false;
            }
            catch (Exception ex)
            {
                return false;
            }

            return true;
        }

        public bool ValidateSigningCredential(string token, string iss, string aud, string salt = null)
        {
            try
            {
                TokenValidationParameters tokenValidationParameters = new TokenValidationParameters();
                tokenValidationParameters.ValidIssuer = iss;
                tokenValidationParameters.ValidAudience = aud.ToString();
                tokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(salt));

                ClaimsPrincipal claimsPrincipal = new JwtSecurityTokenHandler().ValidateToken(token, tokenValidationParameters, out SecurityToken outToken);
            }
            catch (ArgumentNullException ex)
            {
                // 매개변수 Null
                return false;
            }
            catch (ArgumentException ex)
            {
                // 매개변수 오류
                return false;
            }
            catch (SecurityTokenDecryptionFailedException ex)
            {
                // 복호화 실패
                return false;
            }
            catch (SecurityTokenExpiredException ex)
            {
                // exp 만료
                return false;
            }
            catch (SecurityTokenInvalidAudienceException ex)
            {
                // aud 불일치
                return false;
            }
            catch (SecurityTokenInvalidLifetimeException ex)
            {
                // notbefore > expire
                return false;
            }
            catch (SecurityTokenInvalidSignatureException ex)
            {
                // 서명오류
                return false;
            }
            catch (Exception ex)
            {
                return false;
            }

            return true;
        }
    }
}
