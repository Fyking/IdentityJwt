using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace IdentityCookie.Controllers
{
    [Route("api/[controller]/[action]")]
    [Authorize]
    [ApiController]
    public class AccountController : ControllerBase
    {
        public IConfiguration _configuration { get; }
        public AccountController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [AllowAnonymous]
        [HttpGet]
        public ActionResult Login(string name, string pwd)
        {
            if (name == "AngelaDaddy" && pwd == "123456")
            {
                // push the user’s name into a claim, so we can identify the user later on.
                var claims = new[]
                {
                   new Claim(ClaimTypes.Name, name),
                   new Claim(ClaimTypes.NameIdentifier, "100001"),//指定实体的名称
                   new Claim(ClaimTypes.Email, "123@qq.com"),//邮箱
                   new Claim(ClaimTypes.Role, "admin"),//权限
                   new Claim(ClaimTypes.Sid, "1001")//唯一ID
                };
                //ClaimTypes所有类型请查阅：
                //https://docs.microsoft.com/zh-cn/dotnet/api/system.security.claims.claimtypes?redirectedfrom=MSDN&view=netframework-4.8
                //sign the token using a secret key.This secret will be shared between your API and anything that needs to check that the token is legit.
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SecurityKey"]));//本地密钥
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);//加密方式HmacSha256
                //.NET Core’s JwtSecurityToken class takes on the heavy lifting and actually creates the token.
                //var jwtPayload = new JwtPayload();
                /* Claims (Payload)=>jwtPayload
                    Claims 部分包含了一些跟这个 token 有关的重要信息。 JWT 标准规定了一些字段，下面节选一些字段:
                    issuer: The issuer of the token，token 是给谁的  发送者
                    audience: 接收的
                    sub:主题
                    expires: Expiration Time。 token 过期时间，Unix 时间戳格式
                    iat: Issued At。 token 创建时间， Unix 时间戳格式
                    jti: JWT ID。针对当前 token 的唯一标识
                    除了规定的字段外，可以包含其他任何 JSON 兼容的字段。
                 */
                var token = new JwtSecurityToken(
                    issuer: "jwttest",
                    audience: "jwttest",
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: creds);
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    token_type = "Bearer"
                });
            }
            return BadRequest("用户名密码错误");
        }
        /// <summary>
        /// 删除指定的cookie
        /// </summary>
        /// <param name="key">键</param>
        [HttpGet]
        public ActionResult Delete(string key)
        {
            HttpContext.SignOutAsync().Wait();
            return Ok();
        }

        /// <summary>
        /// 获取cookies
        /// </summary>
        /// <param name="key">键</param>
        /// <returns>返回对应的值</returns>
        [HttpGet]
        public ActionResult<string> GetCookies(string key)
        {
            /*使用Ajax请求验证身份
             var token="";
             //登录获取Token
             var settings = {
		       "url": "https://localhost:44364/api/account/login?name=admin&pwd=123456",
		       "method": "GET",
		       "timeout": 0,
		     };
             //使用Token请求Authorize接口
             $.ajax(settings).done(function (response) {
              console.log(response);
              token=response.token;//赋值
              var settings = {
                "url": "https://localhost:44364/api/account/GetCookies?key=name",
                "method": "GET",
                "timeout": 0,
                "headers": {
                  "Authorization":"Bearer "+token,
                },
              };
              $.ajax(settings).done(function (response) {
                console.log(response);
              });
            });
            */
            bool IsAuthenticated = false;
            var requestURL = HttpContext.Request.Path;
            var claims = HttpContext.User.Claims;
            //如果HttpContext.User.Identity.IsAuthenticated为true，
            //或者HttpContext.User.Claims.Count()大于0表示用户已经登录
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                IsAuthenticated = true;
            }
            if (IsAuthenticated)
            {
                //这里通过 HttpContext.User.Claims 可以将我们在Login这个Action中存储到cookie中的所有
                //claims键值对都读出来，比如我们刚才定义的UserName的值admin就在这里读取出来了
                var userName = HttpContext.User.FindFirst(ClaimTypes.Name).Value;//名字
                var Role = HttpContext.User.FindFirst(ClaimTypes.Role).Value;//权限码
                var SId = HttpContext.User.FindFirst(ClaimTypes.Sid).Value;//唯一验证码
            }
            return requestURL.Value;
        }
    }
}