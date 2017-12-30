#region Related components
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.Linq;
using System.Xml;
using System.Web;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services.Base.AspNet
{
	public static partial class Global
	{
		/// <summary>
		/// Gets the information of the requested app
		/// </summary>
		/// <param name="header"></param>
		/// <param name="query"></param>
		/// <param name="agentString"></param>
		/// <param name="ipAddress"></param>
		/// <param name="urlReferrer"></param>
		/// <returns></returns>
		public static Tuple<string, string, string> GetAppInfo(NameValueCollection header, NameValueCollection query, string agentString, string ipAddress, Uri urlReferrer)
		{
			var name = UtilityService.GetAppParameter("x-app-name", header, query, "Generic App");

			var platform = UtilityService.GetAppParameter("x-app-platform", header, query);
			if (string.IsNullOrWhiteSpace(platform))
				platform = string.IsNullOrWhiteSpace(agentString)
					? "N/A"
					: agentString.IsContains("iPhone") || agentString.IsContains("iPad") || agentString.IsContains("iPod")
						? "iOS PWA"
						: agentString.IsContains("Android")
							? "Android PWA"
							: agentString.IsContains("Windows Phone")
								? "Windows Phone PWA"
								: agentString.IsContains("BlackBerry") || agentString.IsContains("BB10")
									? "BlackBerry PWA"
									: agentString.IsContains("IEMobile") || agentString.IsContains("Opera Mini") || agentString.IsContains("MDP/")
										? "Mobile PWA"
										: "Desktop PWA";

			var origin = header?["origin"];
			if (string.IsNullOrWhiteSpace(origin))
				origin = urlReferrer?.AbsoluteUri;
			if (string.IsNullOrWhiteSpace(origin) || origin.IsStartsWith("file://") || origin.IsStartsWith("http://localhost"))
				origin = ipAddress;

			return new Tuple<string, string, string>(name, platform, origin);
		}

		/// <summary>
		/// Gets the information of the requested app
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Tuple<string, string, string> GetAppInfo(this HttpContext context)
		{
			return Global.GetAppInfo(context.Request.Headers, context.Request.QueryString, context.Request.UserAgent, context.Request.UserHostAddress, context.Request.UrlReferrer);
		}

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="header"></param>
		/// <param name="query"></param>
		/// <param name="agentString"></param>
		/// <param name="ipAddress"></param>
		/// <param name="urlReferrer"></param>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public static Session GetSession(NameValueCollection header, NameValueCollection query, string agentString, string ipAddress, Uri urlReferrer, string sessionID = null, User user = null)
		{
			var appInfo = Base.AspNet.Global.GetAppInfo(header, query, agentString, ipAddress, urlReferrer);
			return new Session()
			{
				SessionID = sessionID ?? "",
				IP = ipAddress,
				AppAgent = agentString,
				DeviceID = UtilityService.GetAppParameter("x-device-id", header, query, ""),
				AppName = appInfo.Item1,
				AppPlatform = appInfo.Item2,
				AppOrigin = appInfo.Item3,
				User = user ?? new User()
			};
		}

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="context"></param>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public static Session GetSession(this HttpContext context, string sessionID = null, User user = null)
		{
			return Global.GetSession(context.Request.Headers, context.Request.QueryString, context.Request.UserAgent, context.Request.UserHostAddress, context.Request.UrlReferrer, sessionID, user);
		}

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <returns></returns>
		public static Session GetSession()
		{
			return HttpContext.Current != null ? HttpContext.Current.GetSession(null, HttpContext.Current.User.Identity as User) : null;
		}

		static string _AESKey = null, _JWTKey = null, _PublicJWTKey = null, _RSAKey = null, _RSAExponent = null, _RSAModulus = null;

		/// <summary>
		/// Geths the key for working with AES
		/// </summary>
		public static string AESKey
		{
			get
			{
				return Global._AESKey ?? (Global._AESKey = UtilityService.GetAppSetting("Keys:AES", "VIEApps-c98c6942-Default-0ad9-AES-40ed-Encryption-9e53-Key-65c501fcf7b3"));
			}
		}

		/// <summary>
		/// Generates the key for working with AES
		/// </summary>
		/// <param name="additional"></param>
		/// <returns></returns>
		public static byte[] GenerateEncryptionKey(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(false, false, 256);
		}

		/// <summary>
		/// Generates the initialize vector for working with AES
		/// </summary>
		/// <param name="additional"></param>
		/// <returns></returns>
		public static byte[] GenerateEncryptionIV(string additional = null)
		{
			return (Global.AESKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, true, 128);
		}

		/// <summary>
		/// Gets the key for working with JSON Web Token
		/// </summary>
		public static string JWTKey
		{
			get
			{
				return Global._JWTKey ?? (Global._JWTKey = UtilityService.GetAppSetting("Keys:JWT", "VIEApps-49d8bd8c-Default-babc-JWT-43f4-Sign-bc30-Key-355b0891dc0f"));
			}
		}

		/// <summary>
		/// Generates the key for working with JSON Web Token
		/// </summary>
		/// <returns></returns>
		public static string GenerateJWTKey()
		{
			return Global._PublicJWTKey ?? (Global._PublicJWTKey = Global.JWTKey.GetHMACSHA512(Global.AESKey).ToBase64Url(false, true));
		}

		/// <summary>
		/// Gets the key for working with RSA
		/// </summary>
		public static string RSAKey
		{
			get
			{
				return Global._RSAKey ?? (Global._RSAKey = UtilityService.GetAppSetting("Keys:RSA", "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"));
			}
		}

		/// <summary>
		/// Gets the public exponent of RSA key
		/// </summary>
		public static string RSAExponent
		{
			get
			{
				if (Global._RSAExponent == null)
				{
					var xmlDoc = new XmlDocument();
					xmlDoc.LoadXml(Global.RSA.ToXmlString(false));
					Global._RSAExponent = xmlDoc.DocumentElement.ChildNodes[1].InnerText.ToHexa(true);
				}
				return Global._RSAExponent;
			}
		}

		/// <summary>
		/// Gets the public modulus of the RSA key
		/// </summary>
		public static string RSAModulus
		{
			get
			{
				if (Global._RSAModulus == null)
				{
					var xmlDoc = new XmlDocument();
					xmlDoc.LoadXml(Global.RSA.ToXmlString(false));
					Global._RSAModulus = xmlDoc.DocumentElement.ChildNodes[0].InnerText.ToHexa(true);
				}
				return Global._RSAModulus;
			}
		}

		static RSACryptoServiceProvider _RSA = null;

		/// <summary>
		/// Gest the RSA Cryptor
		/// </summary>
		public static RSACryptoServiceProvider RSA
		{
			get
			{
				return Global._RSA ?? (Global._RSA = CryptoService.CreateRSAInstance(Global.RSAKey.Decrypt()));
			}
		}

		static HashSet<string> _HiddenSegments = null, _BypassSegments = null, _StaticSegments = null;

		/// <summary>
		/// Gets the segments need to hide
		/// </summary>
		public static HashSet<string> HiddenSegments
		{
			get
			{
				return Global._HiddenSegments ?? (Global._HiddenSegments = UtilityService.GetAppSetting("Segments:Hidden")?.Trim().ToLower().ToHashSet('|', true) ?? new HashSet<string>());
			}
		}

		/// <summary>
		/// Gets the segments need to by-pass
		/// </summary>
		public static HashSet<string> BypassSegments
		{
			get
			{
				return Global._BypassSegments ?? (Global._BypassSegments = UtilityService.GetAppSetting("Segments:Bypass")?.Trim().ToLower().ToHashSet('|', true) ?? new HashSet<string>());
			}
		}

		/// <summary>
		/// Gets the segments of static files
		/// </summary>
		public static HashSet<string> StaticSegments
		{
			get
			{
				return Global._StaticSegments ?? (Global._StaticSegments = UtilityService.GetAppSetting("Segments:Static")?.Trim().ToLower().ToHashSet('|', true) ?? new HashSet<string>());
			}
		}
	}
}