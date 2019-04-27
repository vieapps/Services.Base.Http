#region Related components
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Linq;
using System.Numerics;
using System.Dynamic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Reactive.Subjects;
using System.Runtime.InteropServices;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Server.IISIntegration;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using WampSharp.V2.Realm;
using WampSharp.V2.Core.Contracts;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services
{
	public static partial class Global
	{

		#region Environment
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
		public static IServiceCollection AddHttpContextAccessor(this IServiceCollection services)
			=> services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

		/// <summary>
		/// Gets the current HttpContext object
		/// </summary>
		public static HttpContext CurrentHttpContext
			=> Global.ServiceProvider.GetService<IHttpContextAccessor>().HttpContext;

		/// <summary>
		/// Gets or sets the root path of the app
		/// </summary>
		public static string RootPath { get; set; }

		/// <summary>
		/// Gets the correlation identity
		/// </summary>
		/// <param name="items"></param>
		/// <returns></returns>
		internal static string GetCorrelationID(IDictionary<object, object> items)
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
		public static string GetCorrelationID(this HttpContext context)
			=> Global.GetCorrelationID(context?.Items);

		/// <summary>
		/// Gets the correlation identity of the current context
		/// </summary>
		/// <returns></returns>
		public static string GetCorrelationID()
			=> Global.GetCorrelationID(Global.CurrentHttpContext?.Items);

		/// <summary>
		/// Gets the execution times of current HTTP pipeline context
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetExecutionTimes(this HttpContext context)
		{
			if (context.Items.ContainsKey("PipelineStopwatch") && context.Items["PipelineStopwatch"] is Stopwatch stopwatch)
			{
				stopwatch.Stop();
				return stopwatch.GetElapsedTimes();
			}
			return "";
		}

		/// <summary>
		/// Gets the execution times of current HTTP pipeline context
		/// </summary>
		/// <returns></returns>
		public static string GetExecutionTimes()
			=> Global.GetExecutionTimes(Global.CurrentHttpContext);

		/// <summary>
		/// Gets the refer url of this request
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetReferUrl(this HttpContext context)
			=> $"{context.GetReferUri() ?? context.GetOriginUri()}";

		/// <summary>
		/// Gets related information of this request
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Tuple<NameValueCollection, NameValueCollection, string, string, Uri> GetRequestInfo(this HttpContext context)
			=> new Tuple<NameValueCollection, NameValueCollection, string, string, Uri>(context.Request.Headers.ToNameValueCollection(), context.Request.QueryString.ToNameValueCollection(), context.GetUserAgent(), $"{context.Connection.RemoteIpAddress}", context.GetReferUri());

		/// <summary>
		/// Gets related information of this request
		/// </summary>
		/// <returns></returns>
		public static Tuple<NameValueCollection, NameValueCollection, string, string, Uri> GetRequestInfo()
			=> Global.GetRequestInfo(Global.CurrentHttpContext);

		/// <summary>
		/// Gets the information of the requested app
		/// </summary>
		/// <param name="header"></param>
		/// <param name="query"></param>
		/// <param name="agentString"></param>
		/// <param name="ipAddress"></param>
		/// <param name="urlReferer"></param>
		/// <returns></returns>
		public static Tuple<string, string, string> GetAppInfo(NameValueCollection header, NameValueCollection query, string agentString, string ipAddress, Uri urlReferer)
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
				origin = urlReferer?.AbsoluteUri;
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
			return Global.GetAppInfo(header: info.Item1, query: info.Item2, agentString: info.Item3, ipAddress: info.Item4, urlReferer: info.Item5);
		}

		/// <summary>
		/// Gets the information of the requested app
		/// </summary>
		/// <returns></returns>
		public static Tuple<string, string, string> GetAppInfo()
			=> Global.GetAppInfo(Global.CurrentHttpContext);

		/// <summary>
		/// Gets the information of the app's OS
		/// </summary>
		/// <param name="agentString"></param>
		/// <returns></returns>
		public static string GetOSInfo(this string agentString)
			=> agentString.IsContains("iPhone") || agentString.IsContains("iPad") || agentString.IsContains("iPod")
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

		/// <summary>
		/// Gets the information of the app's OS
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetOSInfo(this HttpContext context)
			=> context.GetUserAgent().GetOSInfo();

		/// <summary>
		/// Gets the information of the app's OS
		/// </summary>
		/// <returns></returns>
		public static string GetOSInfo()
			=> Global.GetOSInfo(Global.CurrentHttpContext);

		static HashSet<string> _StaticSegments = null;

		/// <summary>
		/// Gets the segments of static files
		/// </summary>
		public static HashSet<string> StaticSegments => Global._StaticSegments ?? (Global._StaticSegments = (UtilityService.GetAppSetting("Segments:Static", "").Trim().ToLower() + "|statics").ToHashSet('|', true));

		/// <summary>
		/// Runs the hosting of ASP.NET Core apps
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="hostBuilder"></param>
		/// <param name="args"></param>
		/// <param name="port"></param>
		public static void Run<T>(this IWebHostBuilder hostBuilder, string[] args = null, int port = 0) where T : class
		{
			// prepare
			hostBuilder
				.CaptureStartupErrors(true)
				.UseStartup<T>()
				.UseKestrel(options =>
				{
					options.AddServerHeader = false;
					options.ListenAnyIP((args?.FirstOrDefault(a => a.IsStartsWith("/port:"))?.Replace("/port:", "") ?? UtilityService.GetAppSetting("Port", $"{(port > 0 ? port : UtilityService.GetRandomNumber(8001, 8999))}")).CastAs<int>());
				});

			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && "true".IsEquals(UtilityService.GetAppSetting("Proxy:UseIISIntegration")))
				hostBuilder.UseIISIntegration();

			// build & run
			hostBuilder.Build().Run();
		}

		/// <summary>
		/// Gets the options of forwarded-headers
		/// </summary>
		/// <returns></returns>
		public static ForwardedHeadersOptions GetForwardedHeadersOptions()
		{
			var forwardedHeadersOptions = new ForwardedHeadersOptions
			{
				ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
			};
			UtilityService.GetAppSetting("Proxy:IPs")?.ToList()?.ForEach(proxyIP =>
			{
				if (proxyIP.Contains("/"))
				{
					var networkInfo = proxyIP.ToList("/");
					if (IPAddress.TryParse(networkInfo[0], out IPAddress prefix) && Int32.TryParse(networkInfo[1], out int prefixLength))
						forwardedHeadersOptions.KnownNetworks.Add(new IPNetwork(prefix, prefixLength));
				}
				else if (IPAddress.TryParse(proxyIP, out IPAddress ipAddress))
					forwardedHeadersOptions.KnownProxies.Add(ipAddress);
			});
			if (forwardedHeadersOptions.KnownNetworks.Count > 0 || forwardedHeadersOptions.KnownProxies.Count > 0)
				forwardedHeadersOptions.ForwardLimit = null;
			return forwardedHeadersOptions;
		}

		public static Task WriteVisitStartingLogAsync(this HttpContext context, ILogger logger = null, string objectName = null)
		{
			var userAgent = context.GetUserAgent();
			var refererUrl = context.GetReferUrl();
			var visitlog = $"Request starting {context.Request.Method} {context.GetRequestUri()} {context.Request.Protocol}\r\n- IP: {context.Connection.RemoteIpAddress}{(string.IsNullOrWhiteSpace(userAgent) ? "" : $"\r\n- Agent: {userAgent}")}{(string.IsNullOrWhiteSpace(refererUrl) ? "" : $"\r\n- Refer: {refererUrl}")}";
			if (Global.IsDebugLogEnabled)
				visitlog += $"\r\n- Headers:\r\n\t{context.Request.Headers.ToString("\r\n\t", kvp => $"{kvp.Key}: {kvp.Value}")}";
			return context.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.Visits", visitlog);
		}

		public static Task WriteVisitFinishingLogAsync(this HttpContext context, ILogger logger = null, string objectName = null)
			=> context.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.Visits", $"Request finished in {context.GetExecutionTimes()}");
		#endregion

		#region Encryption keys
		static string _EncryptionKey = null, _ValidationKey = null, _JWTKey = null;
		static byte[] _ECCKey = null;
		static string _RSAKey = null, _RSAExponent = null, _RSAModulus = null;
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
		public static string JWTKey => Global._JWTKey ?? (Global._JWTKey = Global.ValidationKey.GetHMACHash(Global.EncryptionKey, "BLAKE256").ToBase64Url());

		/// <summary>
		/// Gets the key for encrypting/decrypting data with ECCsecp256k1
		/// </summary>
		public static BigInteger ECCKey => ECCsecp256k1.GetPrivateKey(Global._ECCKey ?? (Global._ECCKey = UtilityService.GetAppSetting("Keys:ECC", "MD9g3THNC0Z1Ulk+5eGpijotaR5gtv/mzMzfMa5Oio3gOCCSbpCZe5SBIsvdzyof3rFVFgBxOXBM0QgyhBgaCSVkUGaLko5YAmX8qJ6ThORAwrOJNGqNx08y3l0b+A3jkWdvqVVnu6oS7QfnAPaOp4QjMC0Uxpl/2E3QpsI+vNZ9HkWx4mTJeW1AegNmmvov+KhzgWXt8HuT6Vys/MWGxoWPq+ooDGPAfmeVZiY+8GyY4zgMisdqUObEejaAj+gQd+nnnpI8YOFimjir8fp5eP/rT1t6urYcHNUGjsHvPZUAC7uczE3M3ZIhPXz4iT5MDBtonUGsTnrKZKh/NGGvaC/DAhptFIsnjOlLbAyiXmY=").Base64ToBytes().Decrypt()));

		/// <summary>
		/// Gets the key for encrypting/decrypting data with ECCsecp256k1
		/// </summary>
		public static ECCsecp256k1.Point ECCPublicKey => ECCsecp256k1.GeneratePublicKey(Global.ECCKey);

		/// <summary>
		/// Gets the key for encrypting/decrypting data with RSA
		/// </summary>
		public static string RSAKey => Global._RSAKey ?? (Global._RSAKey = UtilityService.GetAppSetting("Keys:RSA", "DA90WJt+jHmBfNlAS31qY3OS+3iUfwN7Gg+bKUm5RxqV13y7eh4daubWAHqtbrPS/Qw5F3d3D26yEo5FZroGvhyFGpfqJqeoz9EhsByn8hZZwns09qtITU6Wbqi74mQe9/h7Xp/57sJUDKssiTFKZYC+OS9RFytJDFXZF8zVoMDQmdG8f7lD6t16bIk27+KwX3OzdSoPOtNalSAwWxZVKchL23NXbHR6EAhnqouLWGHXTOBLIuOnJdqFE8IzgwuffFJ53iq47K7ILC2mAm3DEyv+j24VBYE/EcB8GBLGVlo4uv3tNaDIw9isTlxyETtZwR+NbV7JXOl3j/wKjCL2U/nsfPzQhAMC58+0oKeda2fCV4cXtg/EyrQSpjn56S04BybThgJjoYF1Vf1FqmaNLB9GaV73PLQKUPLY3qFws7k6og5A08eNsgUVfcZqO1iqVUJDbJHCuPgygnRMSsamGS8oWBtSb/rDto+jdpx2oC/KhNA2zMkhYiIO7DtK7sdwo0XeDjid7aipP+bsIuAGmRmt1RgklF65DGcvbglEPSziopUH2hfvbKhtxD+9gp4RrO7KZPrcFKaP8YOKAh05bAvNKwH6Bou3TKPXSjxzalAJqdHzjZNOLmNsfgS2+Y0J9BJhrGMTZtKqjtkbM2qYLkD8DONGdmUmud0TYjBLQVwesScjXxZsYyyohnU+vzqVD6AOxkc9FcU2RMEnSrCu7HAKTTo930v3p4S1iQrKDXn0zrIvDuX5m0LzeUJcV1WJUsu+n6lQCwDKWYZkNpGnJfodl2TtCjt82etcZMyU13Tpoo1M7oyFqlKjcUmy3hzmqfTqbG2AM348VTg9O3jgJxe9kBu5/Gf5tJXvNKaG3sXIh5Ym8pJ08tpE2DS3v3hlPCOD8YsqouW4FzBMmBgNykY5XjtgYZgDHPxCSlIQSuu19Iv6fXk5lDWjJ1Lx3RqRiXbRk7Xj6wlwu/WlomRRzwyO9fL5W89Gj1BaeYVGK+tBnGs9DFVBIIqlrpDyMOVRhkFayZ5J96r+guuZqmHiq+e4JYIC7aYHMT78n8F8DbWbV7hcnyLTe+e5zFQ4WmuBcPlP3ne4YT+Rs/G2NWvdHKmMDOj91CfyuCCgIFSA2/N8gmElrwt3t2yofkhC2tbJEwLCbErupxC/ttjQkjnqEy84me1mR3rkjRNrhbWer3OLAFNwaVMpX6XkcDuGn7evG9Km73Sv8f7y3G2jH9pj5D67T6iLywiyL0s/4Hs+m+VdRRDagWc9P/I+D9ub9tdD8zYTe89UVHzBGpAA3rA7xlowSZNpN2RQC/j0x2J32uy7sSBOh4U8OcJaAJCZjGZjobrhOr6jQJgNpzs8Zx9L/zTGHRDHb0DI6WOAG++KYkcNYqPS1/aewNE8wSMMaZVRkV4Lp7zx4jj3G6+hj80ZOtpRVto7sVoTH34wbzhz0M+NpunGN/ozvmumGeHqZVSQCwnOSnZjiDg+NJU24nmAwv0m0Bc2fY57M50M14gdfBa0ezuCyElMdySr6Kt1ftFtR5NHl/jHjzD+PPq5Bgzgu8uK06iJtRwOvG4K5RrVcIpoj1absbc+Lh22Ri887iLTxZf7uQyau13FXUbpk2eAwKy1oi5RVYT8MTiijSFhct8xCFj359WYSWq5On7onMn39cWPFEFOKxw48aWu/pyLFjRdZgFxlNvEUgBIie/kI+bj3vlBAaTD+3MWFnCrkLcd1flp4nuyQj0iL2xX8pE49FlSNhkkcF2eHF48JaHrNbpnoFLlUKPg98225M0LR2Qxz/rz9uH7P+YEkrQgcO1fYnRbuFx2o5BJ5PdB45B9GmmpdIZJlP2gagxiWqDdotASjD3pfr17S8jL02bko9oBpmf1Eh5lQYyjYDnNjHmYv3nLRcCd8BKxyksAfqv8lOhpvLsKnwHhFVG2yefKOdmC/M3SGwxDabUI7Xv0kA8+COvGq6AC+sLXHydfPN901UjcvRJwNk85yTJO94zwLUUFgVFQNJtEVbarpPsDGYcAeuyF+ccN74HlVvdi8h9WyT1en39hWO8elhTrEZTDB/1ZNfi9Q6iTJYHrLCqw8vaABdBpN4bEm/XEV2gQE923YuItiPAznDCEl0En5VzYQSOT+mENq6XZTVdu1peSFvmexDoNwreK0waGtCYgmbxMnhXq").Decrypt());

		/// <summary>
		/// Gest the instance of RSA
		/// </summary>
		public static RSA RSA => Global._RSA ?? (Global._RSA = Global.CreateRSA());

		/// <summary>
		/// Creates the instance of RSA
		/// </summary>
		/// <returns></returns>
		public static RSA CreateRSA()
		{
			Global._RSA = string.IsNullOrWhiteSpace(Global.RSAKey)
				? RSA.Create()
				: CryptoService.CreateRSA(Global.RSAKey);
			if (Global._RSA.KeySize != 2048)
			{
				Global._RSA = RSA.Create();
				Global._RSA.KeySize = 2048;
			}
			Global.Logger.LogInformation($"RSA is initialized [{Global._RSA.GetType()}] - Key size: {Global._RSA.KeySize} bits");
			return Global._RSA;
		}

		/// <summary>
		/// Gets the exponent of RSA
		/// </summary>
		public static string RSAExponent => Global._RSAExponent ?? (Global._RSAExponent = Global.RSA.ExportParameters(false).Exponent.ToHex());

		/// <summary>
		/// Gets the modulus of the RSA
		/// </summary>
		public static string RSAModulus => Global._RSAModulus ?? (Global._RSAModulus = Global.RSA.ExportParameters(false).Modulus.ToHex());
		#endregion

		#region Working with session & authenticate ticket
		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="header"></param>
		/// <param name="query"></param>
		/// <param name="agentString"></param>
		/// <param name="ipAddress"></param>
		/// <param name="urlReferer"></param>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public static Session GetSession(NameValueCollection header, NameValueCollection query, string agentString, string ipAddress, Uri urlReferer, string sessionID = null, IUser user = null)
		{
			var appInfo = Global.GetAppInfo(header, query, agentString, ipAddress, urlReferer);
			return new Session
			{
				SessionID = sessionID ?? "",
				IP = ipAddress,
				AppAgent = agentString,
				DeviceID = UtilityService.GetAppParameter("x-device-id", header, query, ""),
				AppName = appInfo.Item1,
				AppPlatform = appInfo.Item2,
				AppOrigin = appInfo.Item3,
				User = user != null ? new User(user) : new User("", sessionID ?? "", new List<string> { SystemRole.All.ToString() }, new List<Privilege>())
			};
		}

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="query"></param>
		/// <param name="agentString"></param>
		/// <param name="ipAddress"></param>
		/// <param name="urlReferer"></param>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public static Session GetSession(NameValueCollection query, string agentString, string ipAddress, Uri urlReferer, string sessionID = null, IUser user = null)
			=> Global.GetSession(null, query, agentString, ipAddress, urlReferer, sessionID, user);

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="context"></param>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public static Session GetSession(this HttpContext context, string sessionID = null, IUser user = null)
		{
			var session = context?.GetItem<Session>("Session");
			if (session == null)
			{
				var info = context?.GetRequestInfo();
				if (info != null)
					session = Global.GetSession(header: info.Item1, query: info.Item2, agentString: info.Item3, ipAddress: info.Item4, urlReferer: info.Item5, sessionID: sessionID, user: user);
			}
			return session;
		}

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public static Session GetSession(string sessionID = null, IUser user = null)
			=> Global.GetSession(Global.CurrentHttpContext, sessionID, user);

		/// <summary>
		/// Checks to see the session is existed or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="session">The session for checking</param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object to write into log</param>
		/// <returns></returns>
		public static async Task<bool> IsSessionExistAsync(this HttpContext context, Session session, ILogger logger = null, string objectName = null)
		{
			if (!string.IsNullOrWhiteSpace(session?.SessionID))
			{
				var result = await context.CallServiceAsync(new RequestInfo(session, "Users", "Session", "EXIST"), Global.CancellationTokenSource.Token, logger, objectName).ConfigureAwait(false);
				return result?["Existed"] is JValue isExisted && isExisted.Value != null && isExisted.Value.CastAs<bool>() == true;
			}
			return false;
		}

		/// <summary>
		/// Checks to see the session is existed or not
		/// </summary>
		/// <param name="session">The session for checking</param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object to write into log</param>
		/// <returns></returns>
		public static Task<bool> IsSessionExistAsync(Session session, ILogger logger = null, string objectName = null)
			=> Global.IsSessionExistAsync(Global.CurrentHttpContext, session, logger, objectName);

		/// <summary>
		/// Gets the authenticate ticket of this session
		/// </summary>
		/// <param name="session"></param>
		/// <param name="onPreCompleted"></param>
		/// <returns></returns>
		public static string GetAuthenticateToken(this Session session, Action<JObject> onPreCompleted = null)
			=> session.User.GetAuthenticateToken(Global.EncryptionKey, Global.JWTKey, payload =>
			{
				payload["2fa"] = $"{session.Verification}|{UtilityService.NewUUID}".Encrypt(Global.EncryptionKey, true);
				onPreCompleted?.Invoke(payload);
			});

		/// <summary>
		/// Updates this session with information of authenticate token
		/// </summary>
		/// <param name="context"></param>
		/// <param name="session"></param>
		/// <param name="authenticateToken"></param>
		/// <param name="onAuthenticateTokenParsed"></param>
		/// <param name="updateWithAccessTokenAsync"></param>
		/// <param name="onAccessTokenParsed"></param>
		public static async Task UpdateWithAuthenticateTokenAsync(this HttpContext context, Session session, string authenticateToken, Action<JObject, User> onAuthenticateTokenParsed = null, Func<HttpContext, Session, string, Action<JObject, User>, Task> updateWithAccessTokenAsync = null, Action<JObject, User> onAccessTokenParsed = null)
		{
			// get user from authenticate token
			session.User = authenticateToken.ParseAuthenticateToken(Global.EncryptionKey, Global.JWTKey, (payload, user) =>
			{
				if (!user.ID.Equals(""))
					try
					{
						session.Verification = "true".IsEquals(payload.Get<string>("2fa")?.Decrypt(Global.EncryptionKey, true).ToArray("|").First());
					}
					catch { }
				onAuthenticateTokenParsed?.Invoke(payload, user);
			});

			// update session identity
			session.SessionID = session.User.SessionID;

			// get session of authenticated user and verify with access token
			try
			{
				if (!session.User.ID.Equals(""))
				{
					if (updateWithAccessTokenAsync != null)
						await updateWithAccessTokenAsync(context, session, authenticateToken, onAccessTokenParsed).ConfigureAwait(false);
					else
						await context.UpdateWithAccessTokenAsync(session, authenticateToken, onAccessTokenParsed).ConfigureAwait(false);
				}
			}
			catch (Exception ex)
			{
				throw new InvalidSessionException(ex);
			}
		}

		/// <summary>
		/// Updates this session with information of authenticate token
		/// </summary>
		/// <param name="session"></param>
		/// <param name="authenticateToken"></param>
		/// <param name="onAuthenticateTokenParsed"></param>
		/// <param name="updateWithAccessTokenAsync"></param>
		/// <param name="onAccessTokenParsed"></param>
		public static Task UpdateWithAuthenticateTokenAsync(Session session, string authenticateToken, Action<JObject, User> onAuthenticateTokenParsed = null, Func<HttpContext, Session, string, Action<JObject, User>, Task> updateWithAccessTokenAsync = null, Action<JObject, User> onAccessTokenParsed = null)
			=> Global.UpdateWithAuthenticateTokenAsync(Global.CurrentHttpContext, session, authenticateToken, onAuthenticateTokenParsed, updateWithAccessTokenAsync, onAccessTokenParsed);

		/// <summary>
		/// Updates this session with information of access token
		/// </summary>
		/// <param name="context"></param>
		/// <param name="session"></param>
		/// <param name="authenticateToken"></param>
		/// <param name="onAccessTokenParsed"></param>
		public static async Task UpdateWithAccessTokenAsync(this HttpContext context, Session session, string authenticateToken, Action<JObject, User> onAccessTokenParsed = null)
		{
			// get session of authenticated user and verify with access token
			var json = await context.CallServiceAsync(new RequestInfo(session, "Users", "Session", "GET")
			{
				Header = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "x-app-token", authenticateToken }
				},
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Signature", authenticateToken.GetHMACSHA256(Global.ValidationKey) }
				}
			}, Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// check existing
			if (json == null)
				throw new SessionNotFoundException();

			// check expiration
			if (DateTime.Parse(json.Get<string>("ExpiredAt")) < DateTime.Now)
				throw new SessionExpiredException();

			// get user with privileges
			var user = json.Get<string>("AccessToken").ParseAccessToken(Global.ECCKey, onAccessTokenParsed);

			// check identity
			if (!session.User.ID.Equals(user.ID) || !session.User.SessionID.Equals(user.SessionID))
				throw new InvalidSessionException();

			// update user
			session.User = user;
		}

		/// <summary>
		/// Updates this session with information of access token
		/// </summary>
		/// <param name="session"></param>
		/// <param name="authenticateToken"></param>
		/// <param name="onAccessTokenParsed"></param>
		public static Task UpdateWithAccessTokenAsync(Session session, string authenticateToken, Action<JObject, User> onAccessTokenParsed = null)
			=> Global.UpdateWithAccessTokenAsync(Global.CurrentHttpContext, session, authenticateToken, onAccessTokenParsed);

		/// <summary>
		/// Gets the url to validate session with passport
		/// </summary>
		/// <param name="context"></param>
		/// <param name="callbackFunction"></param>
		/// <returns></returns>
		public static string GetPassportSessionValidatorUrl(this HttpContext context, string callbackFunction = null)
		{
			var passportUrl = UtilityService.GetAppSetting("HttpUri:Passports", "https://id.vieapps.net");
			return passportUrl + (!passportUrl.EndsWith("/") ? "/" : "") + "validator"
				+ $"?u={$"{UtilityService.NewUUID.Left(5)}|{context.User.Identity.Name}".Encrypt(Global.EncryptionKey).ToBase64Url(true)}"
				+ $"&s={$"{UtilityService.NewUUID.Left(5)}|{context.User.Identity.IsAuthenticated}".Encrypt(Global.EncryptionKey).ToBase64Url(true)}"
				+ $"&c={$"{UtilityService.NewUUID.Left(5)}|{callbackFunction ?? ""}".Encrypt(Global.EncryptionKey).ToBase64Url(true)}";
		}

		/// <summary>
		/// Gets the url to authenticate session with passport
		/// </summary>
		/// <param name="context"></param>
		/// <param name="redirectUrl"></param>
		/// <returns></returns>
		public static string GetPassportSessionAuthenticatorUrl(this HttpContext context, string redirectUrl = null)
		{
			var passportUrl = UtilityService.GetAppSetting("HttpUri:Passports", "https://id.vieapps.net");
			return passportUrl + (!passportUrl.EndsWith("/") ? "/" : "") + "initializer"
				+ $"?u={$"{UtilityService.NewUUID.Left(5)}|{context.User.Identity.Name}".Encrypt(Global.EncryptionKey).ToBase64Url(true)}"
				+ $"&s={$"{UtilityService.NewUUID.Left(5)}|{context.User.Identity.IsAuthenticated}".Encrypt(Global.EncryptionKey).ToBase64Url(true)}"
				+ $"&r={$"{UtilityService.NewUUID.Left(5)}|{redirectUrl ?? $"{context.GetRequestUri()}"}".Encrypt(Global.EncryptionKey).ToBase64Url(true)}";
		}
		#endregion

		#region Authentication & Authorization
		/// <summary>
		/// Gets the state that determines the user is authenticated or not
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static bool IsAuthenticated(this HttpContext context)
			=> context != null && context.User.Identity.IsAuthenticated;

		/// <summary>
		/// Gets the state that determines the user is authenticated or not
		/// </summary>
		/// <returns></returns>
		public static bool IsAuthenticated()
			=> Global.IsAuthenticated(Global.CurrentHttpContext);

		/// <summary>
		/// Gets the state that determines the user is system administrator or not
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Task<bool> IsSystemAdministratorAsync(this HttpContext context)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).IsSystemAdministratorAsync(context.GetCorrelationID())
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is system administrator or not
		/// </summary>
		/// <returns></returns>
		public static Task<bool> IsSystemAdministratorAsync()
			=> Global.IsSystemAdministratorAsync(Global.CurrentHttpContext);

		/// <summary>
		/// Gets the state that determines the user is service administrator or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> IsServiceAdministratorAsync(this HttpContext context, string serviceName = null, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).IsServiceAdministratorAsync(serviceName, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is service administrator or not
		/// </summary>
		/// <param name="serviceName">The name of service</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> IsServiceAdministratorAsync(string serviceName = null, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.IsServiceAdministratorAsync(Global.CurrentHttpContext, serviceName, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is service administrator or not
		/// </summary>
		/// <param name="context"></param>
		/// /// <param name="serviceName">The name of service</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> IsServiceModeratorAsync(this HttpContext context, string serviceName = null, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).IsServiceModeratorAsync(serviceName, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is service administrator or not
		/// </summary>
		/// /// <param name="serviceName">The name of service</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> IsServiceModeratorAsync(string serviceName = null, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.IsServiceModeratorAsync(Global.CurrentHttpContext, serviceName, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to manage or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanManageAsync(this HttpContext context, string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanManageAsync(serviceName, objectName, objectIdentity, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to manage or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanManageAsync(string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanManageAsync(Global.CurrentHttpContext, serviceName, objectName, objectIdentity, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to manage or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanManageAsync(this HttpContext context, string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanManageAsync(serviceName, systemID, definitionID, objectID, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to manage or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanManageAsync(string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanManageAsync(Global.CurrentHttpContext, serviceName, systemID, definitionID, objectID, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to moderate or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanModerateAsync(this HttpContext context, string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanModerateAsync(serviceName, objectName, objectIdentity, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to moderate or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanModerateAsync(string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanModerateAsync(Global.CurrentHttpContext, serviceName, objectName, objectIdentity, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to moderate or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanModerateAsync(this HttpContext context, string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanModerateAsync(serviceName, systemID, definitionID, objectID, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to moderate or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanModerateAsync(string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanModerateAsync(Global.CurrentHttpContext, serviceName, systemID, definitionID, objectID, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to edit or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanEditAsync(this HttpContext context, string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanEditAsync(serviceName, objectName, objectIdentity, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to edit or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanEditAsync(string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanEditAsync(Global.CurrentHttpContext, serviceName, objectName, objectIdentity, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to edit or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanEditAsync(this HttpContext context, string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanEditAsync(serviceName, systemID, definitionID, objectID, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to edit or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanEditAsync(string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanEditAsync(Global.CurrentHttpContext, serviceName, systemID, definitionID, objectID, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to contribute or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanContributeAsync(this HttpContext context, string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanContributeAsync(serviceName, objectName, objectIdentity, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to contribute or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanContributeAsync(string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanContributeAsync(Global.CurrentHttpContext, serviceName, objectName, objectIdentity, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to contribute or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanContributeAsync(this HttpContext context, string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanContributeAsync(serviceName, systemID, definitionID, objectID, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to contribute or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanContributeAsync(string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanContributeAsync(Global.CurrentHttpContext, serviceName, systemID, definitionID, objectID, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to view or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanViewAsync(this HttpContext context, string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanViewAsync(serviceName, objectName, objectIdentity, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to view or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanViewAsync(string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanViewAsync(Global.CurrentHttpContext, serviceName, objectName, objectIdentity, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to view or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanViewAsync(this HttpContext context, string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanViewAsync(serviceName, systemID, definitionID, objectID, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to view or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanViewAsync(string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanViewAsync(Global.CurrentHttpContext, serviceName, systemID, definitionID, objectID, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to download or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanDownloadAsync(this HttpContext context, string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanDownloadAsync(serviceName, objectName, objectIdentity, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to download or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanDownloadAsync(string serviceName, string objectName, string objectIdentity, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanDownloadAsync(Global.CurrentHttpContext, serviceName, objectName, objectIdentity, getPrivileges, getActions);

		/// <summary>
		/// Gets the state that determines the user is able to download or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanDownloadAsync(this HttpContext context, string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> context != null && context.User.Identity != null && context.User.Identity is UserIdentity
				? (context.User.Identity as IUser).CanDownloadAsync(serviceName, systemID, definitionID, objectID, getPrivileges, getActions, context.GetCorrelationID(), Global.CancellationTokenSource.Token)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to download or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> CanDownloadAsync(string serviceName, string systemID, string definitionID, string objectID, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> Global.CanDownloadAsync(Global.CurrentHttpContext, serviceName, systemID, definitionID, objectID, getPrivileges, getActions);
		#endregion

		#region Error handling
		/// <summary>
		/// Writes an error exception as JSON to output with status code
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger"></param>
		/// <param name="exception"></param>
		/// <param name="requestInfo"></param>
		/// <param name="writeLogs"></param>
		public static void WriteError(this HttpContext context, ILogger logger, WampException exception, RequestInfo requestInfo = null, bool writeLogs = true)
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
			var correlationID = requestInfo?.CorrelationID ?? context.GetCorrelationID();
			if (writeLogs)
			{
				var logs = new List<string> { "[" + type + "]: " + message };

				stack = "";
				if (requestInfo != null)
					stack += "\r\n" + "==> Request: " + requestInfo.ToJson().ToString(Global.IsDebugStacksEnabled ? Formatting.Indented : Formatting.None);

				if (jsonException != null)
					stack += "\r\n" + "==> Response: " + jsonException.ToString(Global.IsDebugStacksEnabled ? Formatting.Indented : Formatting.None);

				if (exception != null)
				{
					stack += "\r\n" + "==> Stack: " + exception.StackTrace;
					var counter = 0;
					var innerException = exception.InnerException;
					while (innerException != null)
					{
						counter++;
						stack += "\r\n" + $"-------- Inner ({counter}) ----------------------------------"
							+ $"> Message: {innerException.Message}\r\n"
							+ $"> Type: {innerException.GetType()}\r\n"
							+ innerException.StackTrace;
						innerException = innerException.InnerException;
					}
				}

				context.WriteLogs(logger, null, logs, exception, Global.ServiceName, LogLevel.Error, correlationID);
			}

			// show error
			context.WriteHttpError(code, message, type, correlationID, jsonStack);
		}

		/// <summary>
		/// Writes an error exception as JSON to output with status code
		/// </summary>
		/// <param name="context"></param>
		/// <param name="exception"></param>
		/// <param name="requestInfo"></param>
		/// <param name="writeLogs"></param>
		public static void WriteError(this HttpContext context, WampException exception, RequestInfo requestInfo = null, bool writeLogs = true)
			=> context.WriteError(Global.Logger, exception, requestInfo, writeLogs);

		/// <summary>
		/// Writes an error exception as JSON to output with status code
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger"></param>
		/// <param name="exception"></param>
		/// <param name="requestInfo"></param>
		/// <param name="message"></param>
		/// <param name="writeLogs"></param>
		public static void WriteError(this HttpContext context, ILogger logger, Exception exception, RequestInfo requestInfo = null, string message = null, bool writeLogs = true)
		{
			if (exception is WampException)
				context.WriteError(logger, exception as WampException, requestInfo, writeLogs);

			else
			{
				message = message ?? exception?.Message ?? "Unexpected error";
				var correlationID = requestInfo?.CorrelationID ?? context.GetCorrelationID();
				if (writeLogs && exception != null)
					context.WriteLogs(logger, null, new List<string>
					{
						message,
						$"Request: {requestInfo?.ToJson().ToString(Global.IsDebugStacksEnabled ? Formatting.Indented : Formatting.None) ?? "None"}"
					}, exception, Global.ServiceName, LogLevel.Error, correlationID);
				context.WriteHttpError(exception != null ? exception.GetHttpStatusCode() : 500, message, exception?.GetTypeName(true) ?? "UnknownException", correlationID, exception, Global.IsDebugStacksEnabled);
			}
		}

		/// <summary>
		/// Writes an error exception as JSON to output with status code
		/// </summary>
		/// <param name="context"></param>
		/// <param name="exception"></param>
		/// <param name="requestInfo"></param>
		/// <param name="message"></param>
		/// <param name="writeLogs"></param>
		public static void WriteError(this HttpContext context, Exception exception, RequestInfo requestInfo = null, string message = null, bool writeLogs = true)
			=> context.WriteError(Global.Logger, exception, requestInfo, message, writeLogs);
		#endregion

		#region Working with static files
		/// <summary>
		/// Gets the content of a static file
		/// </summary>
		/// <param name="fileInfo"></param>
		/// <returns></returns>
		public static async Task<byte[]> GetStaticFileContentAsync(FileInfo fileInfo)
			=> fileInfo == null || !fileInfo.Exists
				? throw new FileNotFoundException()
				: fileInfo.GetMimeType().IsEndsWith("json")
					? JObject.Parse((await UtilityService.ReadTextFileAsync(fileInfo, null, Global.CancellationTokenSource.Token).ConfigureAwait(false)).Replace("\r", "").Replace("\t", "")).ToString(Formatting.Indented).ToBytes()
					: await UtilityService.ReadBinaryFileAsync(fileInfo, Global.CancellationTokenSource.Token).ConfigureAwait(false);

		/// <summary>
		/// Gets the content of a static file
		/// </summary>
		/// <param name="filePath"></param>
		/// <returns></returns>
		public static Task<byte[]> GetStaticFileContentAsync(string filePath)
			=> Global.GetStaticFileContentAsync(new FileInfo(filePath));

		/// <summary>
		/// Gets the full path of a static file
		/// </summary>
		/// <param name="pathSegments"></param>
		/// <returns></returns>
		public static string GetStaticFilePath(string[] pathSegments)
		{
			var filePath = pathSegments.First().IsEquals("statics")
				? UtilityService.GetAppSetting("Path:StaticFiles", Global.RootPath + "/data-files/statics")
				: Global.RootPath;
			filePath += ("/" + string.Join("/", pathSegments)).Replace("//", "/").Replace(@"\", "/").Replace('/', Path.DirectorySeparatorChar);
			return pathSegments.First().IsEquals("statics")
				? filePath.Replace($"{Path.DirectorySeparatorChar}statics{Path.DirectorySeparatorChar}statics{Path.DirectorySeparatorChar}", $"{Path.DirectorySeparatorChar}statics{Path.DirectorySeparatorChar}")
				: filePath;
		}

		/// <summary>
		/// Processes the request of static file
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static async Task ProcessStaticFileRequestAsync(this HttpContext context, FileInfo fileInfo)
		{
			var requestUri = context.GetRequestUri();
			try
			{
				if (fileInfo == null || !fileInfo.Exists)
				{
					if (Global.IsDebugLogEnabled)
						await context.WriteLogsAsync("Http.StaticFiles", $"The requested file is not found ({requestUri} => {fileInfo?.FullName ?? requestUri.GetRequestPathSegments().Join("/")})").ConfigureAwait(false);
					throw new FileNotFoundException($"Not Found [{requestUri}]");
				}
				var eTag = "Static#" + $"{requestUri}".ToLower().GenerateUUID();
				context.SetResponseHeaders((int)HttpStatusCode.OK, new Dictionary<string, string>
				{
					{ "Content-Type", $"{fileInfo.GetMimeType()}; charset=utf-8" },
					{ "ETag", eTag },
					{ "Last-Modified", $"{fileInfo.LastWriteTime.ToHttpString()}" },
					{ "Cache-Control", "public" },
					{ "Expires", $"{DateTime.Now.AddHours(13).ToHttpString()}" },
					{ "X-CorrelationID", context.GetCorrelationID() }
				});
				await Task.WhenAll(
					context.WriteAsync(await Global.GetStaticFileContentAsync(fileInfo).ConfigureAwait(false), Global.CancellationTokenSource.Token),
					!Global.IsDebugLogEnabled ? Task.CompletedTask : context.WriteLogsAsync("Http.StaticFiles", $"Success response ({requestUri} => {fileInfo?.FullName ?? requestUri.GetRequestPathSegments().Join("/")} [{fileInfo.Length:#,##0} bytes] - ETag: {eTag} - Last modified: {fileInfo?.LastWriteTime.ToDTString()})")
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await context.WriteLogsAsync("Http.StaticFiles", $"Failure response [{requestUri}]", ex).ConfigureAwait(false);
				context.ShowHttpError(ex.GetHttpStatusCode(), ex.Message, ex.GetType().GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
			}
		}

		/// <summary>
		/// Processes the request of static file
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static async Task ProcessStaticFileRequestAsync(this HttpContext context)
		{
			// only allow GET method
			if (!context.Request.Method.IsEquals("GET"))
			{
				context.ShowHttpError((int)HttpStatusCode.MethodNotAllowed, $"Method {context.Request.Method} is not allowed", "MethodNotAllowedException", context.GetCorrelationID());
				return;
			}

			// process
			var requestUri = context.GetRequestUri();
			try
			{
				// prepare
				FileInfo fileInfo = null;
				var filePath = Global.GetStaticFilePath(requestUri.GetRequestPathSegments());

				// headers to reduce traffic
				var eTag = "Static#" + $"{requestUri}".ToLower().GenerateUUID();
				if (eTag.IsEquals(context.GetHeaderParameter("If-None-Match")))
				{
					var isNotModified = true;
					var lastModifed = DateTime.Now.ToUnixTimestamp();
					if (context.GetHeaderParameter("If-Modified-Since") != null)
					{
						fileInfo = new FileInfo(filePath);
						if (fileInfo.Exists)
						{
							lastModifed = fileInfo.LastWriteTime.ToUnixTimestamp();
							isNotModified = lastModifed <= context.GetHeaderParameter("If-Modified-Since").FromHttpDateTime().ToUnixTimestamp();
						}
						else
							isNotModified = false;
					}
					if (isNotModified)
					{
						context.SetResponseHeaders((int)HttpStatusCode.NotModified, eTag, lastModifed, "public", context.GetCorrelationID());
						if (Global.IsDebugLogEnabled)
							await context.WriteLogsAsync("Http.StaticFiles", $"Success response with status code 304 to reduce traffic ({requestUri} => {filePath} - ETag: {eTag} - Last modified: {fileInfo?.LastWriteTime.ToDTString()})").ConfigureAwait(false);
						return;
					}
				}

				// no caching header => process the request of file
				await context.ProcessStaticFileRequestAsync(fileInfo ?? new FileInfo(filePath)).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await context.WriteLogsAsync("Http.StaticFiles", $"Failure response [{requestUri}]", ex).ConfigureAwait(false);
				context.ShowHttpError(ex.GetHttpStatusCode(), ex.Message, ex.GetType().GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
			}
		}

		/// <summary>
		/// Processes the request of favourties icon file
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static async Task ProcessFavouritesIconFileRequestAsync(this HttpContext context)
		{
			if (!context.Request.Method.IsEquals("GET"))
				context.ShowHttpError((int)HttpStatusCode.MethodNotAllowed, $"Method {context.Request.Method} is not allowed", "MethodNotAllowedException", context.GetCorrelationID());
			else
			{
				var filePath = UtilityService.GetAppSetting("Path:FAVIcon");
				await context.ProcessStaticFileRequestAsync(string.IsNullOrWhiteSpace(filePath) ? null : new FileInfo(filePath)).ConfigureAwait(false);
			}
		}
		#endregion

		#region Working with WAMP connections
		/// <summary>
		/// Opens the WAMP channels with default settings
		/// </summary>
		/// <param name="onIncommingConnectionEstablished"></param>
		/// <param name="onOutgoingConnectionEstablished"></param>
		/// <param name="watingTimes"></param>
		/// <returns></returns>
		public static void OpenWAMPChannels(Action<object, WampSessionCreatedEventArgs> onIncommingConnectionEstablished = null, Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished = null, int watingTimes = 6789)
		{
			try
			{
				Task.WaitAll(new[]
				{
					WAMPConnections.OpenIncomingChannelAsync(
						onIncommingConnectionEstablished,
						(sender, arguments) =>
						{
							if (WAMPConnections.ChannelsAreClosedBySystem || arguments.CloseType.Equals(SessionCloseType.Goodbye))
								Global.Logger.LogDebug($"The incoming channel to WAMP router is closed - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
							else if (WAMPConnections.IncomingChannel != null)
							{
								Global.Logger.LogInformation($"The incoming channel to WAMP router is broken - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
								WAMPConnections.IncomingChannel.ReOpen(Global.CancellationTokenSource.Token, (msg, ex) => Global.Logger.LogDebug(msg, ex), "Incoming");
							}
						},
						(sender, arguments) => Global.Logger.LogDebug($"The incoming channel to WAMP router got an error: {arguments.Exception.Message}", arguments.Exception)
					),
					WAMPConnections.OpenOutgoingChannelAsync(
						onOutgoingConnectionEstablished,
						(sender, arguments) =>
						{
							if (WAMPConnections.ChannelsAreClosedBySystem || arguments.CloseType.Equals(SessionCloseType.Goodbye))
								Global.Logger.LogDebug($"The outgoging channel to WAMP router is closed - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
							else if (WAMPConnections.OutgoingChannel != null)
							{
								Global.Logger.LogInformation($"The outgoging channel to WAMP router is broken - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
								WAMPConnections.OutgoingChannel.ReOpen(Global.CancellationTokenSource.Token, (msg, ex) => Global.Logger.LogDebug(msg, ex), "Outgoging");
							}
						},
						(sender, arguments) => Global.Logger.LogDebug($"The outgoging channel to WAMP router got an error: {arguments.Exception.Message}", arguments.Exception)
					)
				}, watingTimes > 0 ? watingTimes : 6789, Global.CancellationTokenSource.Token);
			}
			catch (Exception ex)
			{
				Global.Logger.LogError($"Error occurred while connecting to the WAMP router: {ex.Message}", ex);
			}
		}
		#endregion

		#region Working with messages & updaters/communicators
		/// <summary>
		/// Gets or sets publisher (for publishing update messages)
		/// </summary>
		public static ISubject<UpdateMessage> UpdateMessagePublisher { get; set; }

		/// <summary>
		/// Publishs an update message
		/// </summary>
		/// <param name="message"></param>
		/// <param name="logger"></param>
		/// <returns></returns>
		public static async Task PublishAsync(this UpdateMessage message, ILogger logger = null, string objectName = null)
		{
			if (Global.UpdateMessagePublisher == null)
				try
				{
					await WAMPConnections.OpenOutgoingChannelAsync().ConfigureAwait(false);
					Global.UpdateMessagePublisher = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetSubject<UpdateMessage>("net.vieapps.rtu.update.messages");
					Global.UpdateMessagePublisher.OnNext(message);
					if (Global.IsDebugResultsEnabled)
						await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Successfully send an update message {message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Failure send an update message: {ex.Message} => {message.ToJson().ToString(Formatting.Indented)}", ex).ConfigureAwait(false);
				}

			else
				try
				{
					Global.UpdateMessagePublisher.OnNext(message);
					if (Global.IsDebugResultsEnabled)
						await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Successfully send an update message: {message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Failure send an update message: {ex.Message} => {message.ToJson().ToString(Formatting.Indented)}", ex).ConfigureAwait(false);
				}
		}

		/// <summary>
		/// Gets or sets primary updater (for updating inter-communicate messages of a service)
		/// </summary>
		public static IDisposable PrimaryInterCommunicateMessageUpdater { get; set; }

		/// <summary>
		/// Gets or sets secondary updater (for updating inter-communicate messages of a service)
		/// </summary>
		public static IDisposable SecondaryInterCommunicateMessageUpdater { get; set; }

		/// <summary>
		/// Publishs an inter-communicate message
		/// </summary>
		/// <param name="message"></param>
		/// <param name="logger"></param>
		/// <returns></returns>
		public static async Task PublishAsync(this CommunicateMessage message, ILogger logger = null, string objectName = null)
		{
			try
			{
				await Global.RTUService.SendInterCommunicateMessageAsync(message, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				if (Global.IsDebugResultsEnabled)
					await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Successfully send an inter-communicate message: {message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Failure send an inter-communicate message: {ex.Message}", ex).ConfigureAwait(false);
			}
		}
		#endregion

		#region Register/Unregister/Update service
		static Task UpdateServiceInfoAsync(bool available, bool running)
			=> new CommunicateMessage
			{
				ServiceName = "APIGateway",
				Type = "Service#Info",
				Data = new JObject
				{
					{ "Name", $"{Global.ServiceName}.HTTP".ToLower() },
					{ "UniqueName", Extensions.GetUniqueName($"{Global.ServiceName}.HTTP") },
					{ "ControllerID", "http-services" },
					{ "InvokeInfo", $"{Environment.UserName.ToLower()} [Host: {Environment.MachineName.ToLower()} - Platform: {$"{RuntimeInformation.FrameworkDescription} @ {RuntimeInformation.OSDescription}".Trim()} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS") + $" ({RuntimeInformation.OSDescription.Trim()})"}]" },
					{ "Available", available },
					{ "Running", running }
				}
			}.PublishAsync(Global.Logger);

		/// <summary>
		/// Registers the service
		/// </summary>
		/// <returns></returns>
		public static Task RegisterServiceAsync()
			=> Global.UpdateServiceInfoAsync(true, true);

		/// <summary>
		/// Unregisters the service
		/// </summary>
		/// <returns></returns>
		public static void UnregisterService(int waitingTimes = 1234)
			=> Task.WaitAll(new[] { Global.UpdateServiceInfoAsync(false, false) }, waitingTimes > 0 ? waitingTimes : 1234);

		/// <summary>
		/// Sends the information of the service
		/// </summary>
		/// <returns></returns>
		public static Task UpdateServiceInfoAsync()
			=> Global.RegisterServiceAsync();
		#endregion

	}
}