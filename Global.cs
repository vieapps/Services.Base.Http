#region Related components
using System;
using System.Text;
using System.Linq;
using System.Numerics;
using System.Dynamic;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.DependencyInjection;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services
{
	public static partial class Global
	{
		/// <summary>
		/// Gets or sets name of the working service
		/// </summary>
		public static string ServiceName { get; set; }

		/// <summary>
		/// Gets the cancellation token source (global scope)
		/// </summary>
		public static CancellationTokenSource CancellationTokenSource { get; } = new CancellationTokenSource();

		/// <summary>
		/// Gets or sets the service provider
		/// </summary>
		public static IServiceProvider ServiceProvider { get; set; }

		/// <summary>
		/// Adds the accessor of HttpContext into collection of services
		/// </summary>
		/// <param name="services"></param>
		public static void AddHttpContextAccessor(this IServiceCollection services) => services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

		/// <summary>
		/// Gets the current HttpContext object
		/// </summary>
		public static HttpContext CurrentHttpContext => Global.ServiceProvider.GetService<IHttpContextAccessor>().HttpContext;

		/// <summary>
		/// Gets the correlation identity
		/// </summary>
		/// <param name="items"></param>
		/// <returns></returns>
		internal static string GetCorrelationID(this IDictionary<object, object> items)
		{
			return items != null
				? !items.ContainsKey("Correlation-ID")
					? (items["Correlation-ID"] = UtilityService.NewUUID) as string
					: items["Correlation-ID"] as string
				: UtilityService.NewUUID;
		}

		/// <summary>
		/// Gets the correlation identity of this context
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetCorrelationID(this HttpContext context) => Global.GetCorrelationID(context?.Items);

		/// <summary>
		/// Gets the correlation identity of the current context
		/// </summary>
		/// <returns></returns>
		public static string GetCorrelationID() => Global.GetCorrelationID(Global.CurrentHttpContext?.Items);

		/// <summary>
		/// Gets the correlation identity of the current context
		/// </summary>
		/// <returns></returns>
		public static string CorrelationID => Global.GetCorrelationID();

		/// <summary>
		/// Gets related information
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Tuple<NameValueCollection, NameValueCollection, string, string, Uri> GetRequestInfo(this HttpContext context)
		{
			var header = context.Request.Headers.ToNameValueCollection();
			var queryString = context.Request.QueryString.ToNameValueCollection();
			var userAgent = context.Request.Headers["User-Agent"].First();
			var ipAddress = $"{context.Connection.RemoteIpAddress}";
			var urlReferer = !string.IsNullOrWhiteSpace(context.Request.Headers["Referer"].First())
				? new Uri(context.Request.Headers["Referer"].First())
				: null;
			return new Tuple<NameValueCollection, NameValueCollection, string, string, Uri>(header, queryString, userAgent, ipAddress, urlReferer);
		}

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
			var info = context.GetRequestInfo();
			return Global.GetAppInfo(info.Item1, info.Item2, info.Item3, info.Item4, info.Item5);
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
		public static string GetOSInfo(this HttpContext context) => context.Request.Headers["User-Agent"].First().GetOSInfo();

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
		public static Session GetSession(NameValueCollection header, NameValueCollection query, string agentString, string ipAddress, Uri urlReferrer, string sessionID = null, UserIdentity user = null)
		{
			var appInfo = Global.GetAppInfo(header, query, agentString, ipAddress, urlReferrer);
			var session = new Session
			{
				SessionID = sessionID ?? "",
				IP = ipAddress,
				AppAgent = agentString,
				DeviceID = UtilityService.GetAppParameter("x-device-id", header, query, ""),
				AppName = appInfo.Item1,
				AppPlatform = appInfo.Item2,
				AppOrigin = appInfo.Item3,
				User = user ?? new UserIdentity()
			};
			if (session.User != null && session.User.ID == null)
				session.User.ID = "";
			return session;
		}

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="context"></param>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public static Session GetSession(this HttpContext context, string sessionID = null, UserIdentity user = null)
		{
			var info = context.GetRequestInfo();
			return Global.GetSession(info.Item1, info.Item2, info.Item3, info.Item4, info.Item5, sessionID, user);
		}

		/// <summary>
		/// Checks to see the session is existed or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="session"></param>
		/// <returns></returns>
		public static async Task<bool> IsSessionExistAsync(this HttpContext context, Session session)
		{
			if (!string.IsNullOrWhiteSpace(session?.SessionID))
			{
				var result = await context.CallServiceAsync(new RequestInfo(session, "Users", "Session", "EXIST")).ConfigureAwait(false);
				return result?["Existed"] is JValue isExisted && isExisted.Value != null && isExisted.Value.CastAs<bool>() == true;
			}
			return false;
		}

		static string _EncryptionKey = null, _ValidationKey = null, _JWTKey = null, _RSAKey = null, _RSAExponent = null, _RSAModulus = null;
		static byte[] _ECCKey = null;
		static RSA _RSA = null;

		/// <summary>
		/// Geths the key for encrypting/decrypting data with AES
		/// </summary>
		public static string EncryptionKey => Global._EncryptionKey ?? (Global._EncryptionKey = UtilityService.GetAppSetting("Keys:Encryption", "VIEApps-c98c6942-Default-0ad9-AES-40ed-Encryption-9e53-Key-65c501fcf7b3"));

		/// <summary>
		/// Gets the key for validating
		/// </summary>
		public static string ValidationKey => Global._ValidationKey ?? (Global._ValidationKey = UtilityService.GetAppSetting("Keys:Validation", "VIEApps-49d8bd8c-Default-babc-Data-43f4-Validation-bc30-Key-355b0891dc0f"));

		/// <summary>
		/// Gets the key for validating/signing a JSON Web Token
		/// </summary>
		/// <returns></returns>
		public static string JWTKey => Global._JWTKey ?? (Global._JWTKey = Global.ValidationKey.GetHMACBLAKE128(Global.EncryptionKey, false).ToBase64Url(true));

		/// <summary>
		/// Gets the key for encrypting/decrypting data with ECCsecp256k1
		/// </summary>
		public static BigInteger ECCKey => (Global._ECCKey ?? (Global._ECCKey = UtilityService.GetAppSetting("Keys:ECC", "tRZMCCemDIshR6SBnltv/kZvamQfMuMyx+2DG+2Yuw+13xN4A7Kk+nmEM81kx6ISlaxGgJjr/xK9kWznIC3OWlF2yrdMKeeCPM8eVFIfkiGqIPnGPDJaWRbtGswNjMmfQhbQvQ9qa5306RLt9F94vrOQp2M9eojE3cSuTqNg4OTL+9Dddabgzl94F3gOJoPRxzHqyKWRUhQdP+hOsWSS2KTska2ddm/Zh/fGKXwY9lnnrLHY1wjSJqCS3OO7PCRfQtEWSJcvzzgm7bvJ18fOLuJ5CZVThS+XLNwZgkbcICepRCiVbsk6fmh0482BJesG55pVeyv7ZyKNW+RyMXNEyLn5VY/1lPLxz7lLS88Lvqo=").Base64ToBytes().Decrypt())).ToUnsignedBigInteger();

		/// <summary>
		/// Gets the key for encrypting/decrypting data with RSA
		/// </summary>
		public static string RSAKey => Global._RSAKey ?? (Global._RSAKey = UtilityService.GetAppSetting("Keys:RSA", "NihT0EJ2NLRhmGNbZ8A3jUdhZfO4jG4hfkwaHF1o00YoVx9S61TpmMiaZssOZB++UUyNsZZzxSfkh0i5O9Yr9us+/2zXhgR2zQVxOUrZnPpHpspyJzOegBpMMuTWF4WTl7st797BQ0AmUY1nEjfMTKVP+VSrrx0opTgi93MyvRGGa48vd7PosAM8uq+oMkhMZ/jTvasK6n3PKtb9XAm3hh4NFZBf7P2WuACXZ4Vbzd1MGtLHWfrYnWjGI9uhlo2QKueRLmHoqKM5pQFlB9M7/i2D/TXeWZSWNU+vW93xncUght3QtCwRJu7Kp8UGf8nnrFOshHgvMgsdDlvJt9ECN0/2uyUcWzB8cte5C9r6sP6ClUVSkKDvEOJVmuS2Isk72hbooPaAm7lS5NOzb2pHrxTKAZxaUyiZkFXH5rZxQ/5QjQ9PiAzm1AVdBE1tg1BzyGzY2z7RY/iQ5o22hhRSN3l49U4ftfXuL+LrGKnzxtVrQ15Vj9/pF7mz3lFy2ttTxJPccBiffi9LVtuUCo9BRgw7syn07gAqj1WXzuhPALwK6P6M1pPeFg6NEKLNWgRFE8GZ+dPhr2O0YCgDVuhJ+hDUxCDAEkZ0cQBiliHtjldJji1FnFMqg90QvFCuVCydq94Dnxdl9HSVMNC69i6H2GNfBuD9kTQ6gIOepc86YazDto8JljqEVOpkegusPENadLjpwOYCCslN1Y314B2g9vvZRwU3T+PcziBjym1ceagEEAObZ22Z/vhxBZ83Z2E1/RkbJqovIRKuHLCzU/4lBeTseJNlKPSACPuKAX08P4y5c+28WDrHv2+o7x9ISJe0SN1KmFMvv1xYtj/1NwOHQzfVjbpL46E0+Jr/IOOjh2CQhhUMm1GOEQAZ9n+b7a4diUPDG+BewAZvtd5gNX4zD0IKkJFwN+fBMWSHs0gs3jNz4RcYhH5IoHq27jrfM3cUlvBP9JpbZugNIh8ddZsUd4XQuCVZF+qlfRjY6lfEy4nXX48ianvdCqnBpkmRadG8qFLybkVS+s8RHcPwRkkzKQ4oGHdDeyiU8ZXnwvJ3IxDLoJV0xqKSRjhe9MxwdeN7VMSTNRAtQvqVvm6cL8KNbd2Hx1kPDEcqeUfVIeZ+zTIptO5GpjEMV+4gu338WG1RyEMAaiE536E+UR+0MqIe/Q==").Decrypt());

		/// <summary>
		/// Gest the instance of RSA
		/// </summary>
		public static RSA RSA => Global._RSA ?? (Global._RSA = CryptoService.CreateRSAInstance(Global.RSAKey));

		/// <summary>
		/// Gets the exponent of RSA
		/// </summary>
		public static string RSAExponent => Global._RSAExponent ?? (Global._RSAExponent = Global.RSA.ExportParameters(false).Exponent.ToHex());

		/// <summary>
		/// Gets the modulus of the RSA
		/// </summary>
		public static string RSAModulus => Global._RSAModulus ?? (Global._RSAModulus = Global.RSA.ExportParameters(false).Modulus.ToHex());

		static HashSet<string> _BypassSegments = null, _StaticSegments = null;

		/// <summary>
		/// Gets the segments need to by-pass
		/// </summary>
		public static HashSet<string> BypassSegments => Global._BypassSegments ?? (Global._BypassSegments = UtilityService.GetAppSetting("Segments:Bypass")?.Trim().ToLower().ToHashSet('|', true) ?? new HashSet<string>());

		/// <summary>
		/// Gets the segments of static files
		/// </summary>
		public static HashSet<string> StaticSegments => Global._StaticSegments ?? (Global._StaticSegments = (UtilityService.GetAppSetting("Segments:Static", "").Trim().ToLower() + "|statics").ToHashSet('|', true));

		/// <summary>
		/// Prepare the request with information of JSON Web Token
		/// </summary>
		/// <param name="context"></param>
		/// <param name="requestInfo"></param>
		/// <param name="token"></param>
		/// <param name="onPreCompleted"></param>
		public static async Task UpdateRequestWithTokenAsync(this HttpContext context, RequestInfo requestInfo, string token, Action<ExpandoObject> onPreCompleted = null)
		{
			// parse JSON Web Token
			var jwt = (token ?? requestInfo.GetParameter("x-app-token")).ParseJSONWebToken(Global.EncryptionKey, Global.JWTKey, payload =>
			{
				try
				{
					requestInfo.Session.Verification = "true".IsEquals(payload.Get<string>("j2f")?.Decrypt(Global.EncryptionKey).ToArray("|").First());
				}
				catch { }
				onPreCompleted?.Invoke(payload);
			});
			requestInfo.Session.SessionID = jwt.Item2;
			requestInfo.Session.User.ID = jwt.Item1;

			// prepare privileges via access token
			if (!requestInfo.Session.User.Equals(""))
			{
				// get session
				var session = await context.CallServiceAsync(new RequestInfo(requestInfo.Session, "Users", "Session", "GET", null, requestInfo.Header)
				{
					Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
					{
						{ "Signature", token.GetHMACSHA256(Global.ValidationKey) }
					}
				}).ConfigureAwait(false);

				// parse access token and update user
				var accessToken = ((session["AccessToken"] as JValue).Value as string).Base64ToBytes().Decrypt(Global.EncryptionKey.GenerateHashKey(256), Global.EncryptionKey.GenerateHashKey(128)).GetString();
				requestInfo.Session.User = accessToken.ToJson().FromJson<UserIdentity>();
			}
			else
				requestInfo.Session.User.SessionID = requestInfo.Session.SessionID;
		}

		/// <summary>
		/// Writes an error exception
		/// </summary>
		/// <param name="context"></param>
		/// <param name="exception"></param>
		/// <param name="requestInfo"></param>
		/// <param name="writeLogs"></param>
		public static void ShowError(this HttpContext context, WampException exception, RequestInfo requestInfo = null, bool writeLogs = true)
		{
			// prepare
			var details = exception.GetDetails(requestInfo);
			var code = details.Item1;
			var message = details.Item2;
			var type = details.Item3;
			var stack = details.Item4;
			var inner = details.Item5;
			var jsonException = details.Item6;

			JArray jsonStack = null;
			if (Global.IsDebugStacksEnabled & !string.IsNullOrWhiteSpace(stack))
			{
				jsonStack = new JArray
				{
					new JObject
					{
						{ "Message", exception.Message },
						{ "Type", exception.GetType().ToString() },
						{ "Stack", exception.StackTrace }
					}
				};
				while (inner != null)
				{
					jsonStack.Add(new JObject
					{
						{ "Message", inner.Message },
						{ "Type", inner.GetType().ToString() },
						{ "Stack", inner.StackTrace }
					});
					inner = inner.InnerException;
				}
			}

			// write logs
			if (writeLogs)
			{
				var logs = new List<string>() { "[" + type + "]: " + message };

				stack = "";
				if (requestInfo != null)
					stack += "\r\n" + "==> Request:\r\n" + requestInfo.ToJson().ToString(Global.IsDebugStacksEnabled ? Formatting.Indented : Formatting.None);

				if (jsonException != null)
					stack += "\r\n" + "==> Response:\r\n" + jsonException.ToString(Global.IsDebugStacksEnabled ? Formatting.Indented : Formatting.None);

				if (exception != null)
				{
					stack += "\r\n" + "==> Stack:\r\n" + exception.StackTrace;
					var counter = 0;
					var innerException = exception.InnerException;
					while (innerException != null)
					{
						counter++;
						stack += "\r\n" + $"-------- Inner ({counter}) ----------------------------------"
							+ "> Message: " + innerException.Message + "\r\n"
							+ "> Type: " + innerException.GetType().ToString() + "\r\n"
							+ innerException.StackTrace;
						innerException = innerException.InnerException;
					}
				}

				context.WriteLogs(requestInfo?.ObjectName ?? "unknown", logs, exception, requestInfo?.ServiceName ?? Global.ServiceName);
			}

			// show error
			context.WriteHttpError(code, message, type, requestInfo?.CorrelationID ?? context.GetCorrelationID(), jsonStack);
		}

		/// <summary>
		/// Writes an error exception
		/// </summary>
		/// <param name="context"></param>
		/// <param name="exception"></param>
		/// <param name="requestInfo"></param>
		/// <param name="writeLogs"></param>
		public static void WriteError(this HttpContext context, Exception exception, RequestInfo requestInfo = null, bool writeLogs = true)
		{
			if (exception is WampException)
				context.ShowError(exception as WampException, requestInfo, writeLogs);

			else
			{
				if (writeLogs && exception != null)
					context.WriteLogs(requestInfo?.ObjectName ?? "Unknown", new List<string> { $"Error occurred while processing (Request: {requestInfo?.ToJson().ToString(Global.IsDebugStacksEnabled ? Formatting.Indented : Formatting.None) ?? "None"})" }, exception, requestInfo?.ServiceName ?? Global.ServiceName);
				var message = exception != null ? exception.Message : "Unknown error";
				var type = exception != null ? exception.GetType().ToString().ToArray('.').Last() : "Unknown";
				context.WriteHttpError(exception != null ? exception.GetHttpStatusCode() : 500, message, type, requestInfo?.CorrelationID ?? context.GetCorrelationID(), exception, Global.IsDebugStacksEnabled);
			}
		}
	}
}