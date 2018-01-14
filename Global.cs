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
		/// Gets the information of the app's OS
		/// </summary>
		/// <param name="agentString"></param>
		/// <returns></returns>
		public static string GetOSInfo(this string agentString)
		{
			return agentString.IsContains("iPhone") || agentString.IsContains("iPad") || agentString.IsContains("iPod")
				? "iOS"
				: agentString.IsContains("Android")
					? "Android"
					: agentString.IsContains("Windows Phone")
						? "Windows Phone"
						: agentString.IsContains("BlackBerry") || agentString.IsContains("BB10")
							? "BlackBerry" + (agentString.IsContains("BB10") ? "10" : "OS")
							: agentString.IsContains("IEMobile") || agentString.IsContains("Opera Mini") || agentString.IsContains("MDP/")
								? "Mobile OS"
								: agentString.IsContains("Windows")
									? "Windows"
									: agentString.IsContains("Mac OS")
										? "macOS"
										: agentString.IsContains("Linux")
											? "Linux"
											: "Generic OS";
		}

		/// <summary>
		/// Gets the information of the app's OS
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetOSInfo(this HttpContext context)
		{
			return context.Request.UserAgent.GetOSInfo();
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

		static string _EncryptionKey = null, _ValidationKey = null, _JWTKey = null, _RSAKey = null, _RSAExponent = null, _RSAModulus = null;

		/// <summary>
		/// Geths the key for encrypting/decrypting data with AES
		/// </summary>
		public static string EncryptionKey
		{
			get
			{
				return Global._EncryptionKey ?? (Global._EncryptionKey = UtilityService.GetAppSetting("Keys:Encryption", "VIEApps-c98c6942-Default-0ad9-AES-40ed-Encryption-9e53-Key-65c501fcf7b3"));
			}
		}

		/// <summary>
		/// Generates the key for working with AES
		/// </summary>
		/// <param name="additional"></param>
		/// <returns></returns>
		public static byte[] GenerateEncryptionKey(string additional = null)
		{
			return (Global.EncryptionKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(false, false, 256);
		}

		/// <summary>
		/// Generates the initialize vector for working with AES
		/// </summary>
		/// <param name="additional"></param>
		/// <returns></returns>
		public static byte[] GenerateEncryptionIV(string additional = null)
		{
			return (Global.EncryptionKey + (string.IsNullOrWhiteSpace(additional) ? "" : ":" + additional)).GenerateEncryptionKey(true, true, 128);
		}

		/// <summary>
		/// Gets the key for validating
		/// </summary>
		public static string ValidationKey
		{
			get
			{
				return Global._ValidationKey ?? (Global._ValidationKey = UtilityService.GetAppSetting("Keys:Validation", "VIEApps-49d8bd8c-Default-babc-Data-43f4-Validation-bc30-Key-355b0891dc0f"));
			}
		}

		/// <summary>
		/// Gets the key for validating/signing a JSON Web Token
		/// </summary>
		/// <returns></returns>
		public static string JWTKey
		{
			get
			{
				return Global._JWTKey ?? (Global._JWTKey = Global.ValidationKey.GetHMACSHA512(Global.EncryptionKey).ToBase64Url(false, true));
			}
		}

		/// <summary>
		/// Gets the key for encrypting/decrypting data with RSA
		/// </summary>
		public static string RSAKey
		{
			get
			{
				return Global._RSAKey ?? (Global._RSAKey = UtilityService.GetAppSetting("Keys:RSA", "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"));
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