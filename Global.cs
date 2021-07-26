#region Related components
using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Numerics;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Realm;
using WampSharp.V2.Core.Contracts;
using net.vieapps.Components.Security;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services
{
	public static partial class Global
	{

		#region Environment
		/// <summary>
		/// Gets or sets name of the service
		/// </summary>
		public static string ServiceName { get; set; }

		/// <summary>
		/// Gets or sets the caching storage
		/// </summary>
		public static ICache Cache { get; set; }

		/// <summary>
		/// Gets or sets the service provider
		/// </summary>
		public static IServiceProvider ServiceProvider { get; set; }

		/// <summary>
		/// Gets the cancellation token source
		/// </summary>
		public static CancellationTokenSource CancellationTokenSource { get; } = new CancellationTokenSource();

		/// <summary>
		/// Gets the cancellation token
		/// </summary>
		public static CancellationToken CancellationToken => Global.CancellationTokenSource.Token;

#if NETSTANDARD2_0
		/// <summary>
		/// Adds a default implementation for the <see cref="IHttpContextAccessor">IHttpContextAccessor</see> service
		/// </summary>
		/// <param name="services"></param>
		/// <returns>The service collection</returns>
		public static IServiceCollection AddHttpContextAccessor(this IServiceCollection services)
			=> services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
#endif

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
			=> items != null
				? !items.ContainsKey("Correlation-ID")
					? (items["Correlation-ID"] = UtilityService.NewUUID) as string
					: items["Correlation-ID"] as string
				: UtilityService.NewUUID;

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
		/// Gets the information of the requested app
		/// </summary>
		/// <param name="header"></param>
		/// <param name="query"></param>
		/// <param name="ipAddress"></param>
		/// <returns></returns>
		public static Tuple<string, string, string> GetAppInfo(Dictionary<string, string> header, Dictionary<string, string> query, string ipAddress)
		{
			var name = UtilityService.GetAppParameter("x-app-name", header, query, "Generic App");
			var userAgent = UtilityService.GetAppParameter("user-agent", header, query);
			var platform = UtilityService.GetAppParameter("x-app-platform", header, query);
			if (string.IsNullOrWhiteSpace(platform))
				platform = string.IsNullOrWhiteSpace(userAgent)
					? "N/A"
					: userAgent.IsContains("iPhone") || userAgent.IsContains("iPad") || userAgent.IsContains("iPod")
						? "iOS PWA"
						: userAgent.IsContains("Android")
							? "Android PWA"
							: userAgent.IsContains("Windows Phone")
								? "Windows Phone PWA"
								: userAgent.IsContains("BlackBerry") || userAgent.IsContains("BB10") || userAgent.IsContains("RIM Tablet OS")
									? "BlackBerry PWA"
									: userAgent.IsContains("IEMobile") || userAgent.IsContains("Opera Mini") || userAgent.IsContains("MDP/")
										? "Mobile PWA"
										: "Desktop PWA";

			var origin = UtilityService.GetAppParameter("origin", header, query) ?? UtilityService.GetAppParameter("referer", header, query);
			if (string.IsNullOrWhiteSpace(origin) || origin.IsStartsWith("file://") || origin.IsStartsWith("http://local"))
				origin = ipAddress;

			return new Tuple<string, string, string>(name, platform, origin);
		}

		/// <summary>
		/// Gets the information of the requested app
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Tuple<string, string, string> GetAppInfo(this HttpContext context)
			=> Global.GetAppInfo(header: context.Request.Headers.ToDictionary(), query: context.Request.QueryString.ToDictionary(), ipAddress: $"{context.Connection.RemoteIpAddress}");

		/// <summary>
		/// Gets the information of the requested app
		/// </summary>
		/// <returns></returns>
		public static Tuple<string, string, string> GetAppInfo()
			=> Global.GetAppInfo(Global.CurrentHttpContext);

		/// <summary>
		/// Gets the information of the app's OS
		/// </summary>
		/// <param name="userAgent"></param>
		/// <returns></returns>
		public static string GetOSInfo(this string userAgent)
			=> userAgent.IsContains("iPhone") || userAgent.IsContains("iPad") || userAgent.IsContains("iPod")
				? "iOS"
				: userAgent.IsContains("Android")
					? "Android"
					: userAgent.IsContains("Windows Phone")
						? "Windows Phone"
						: userAgent.IsContains("BlackBerry") || userAgent.IsContains("BB10") || userAgent.IsContains("RIM Tablet OS")
							? "BlackBerry" + (userAgent.IsContains("BB10") ? "10" : "OS")
							: userAgent.IsContains("IEMobile") || userAgent.IsContains("Opera Mini") || userAgent.IsContains("MDP/")
								? "Mobile OS"
								: userAgent.IsContains("Windows")
									? "Windows"
									: userAgent.IsContains("Mac OS")
										? "macOS"
										: userAgent.IsContains("Linux")
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
		/// Gets the options of forwarded-headers
		/// </summary>
		/// <param name="onCompleted"></param>
		/// <returns></returns>
		public static ForwardedHeadersOptions GetForwardedHeadersOptions(Action<ForwardedHeadersOptions> onCompleted = null)
		{
			var options = new ForwardedHeadersOptions
			{
				ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
			};

			var forwarded = UtilityService.GetAppSetting("Proxy:X-Forwarded-For");
			if (!string.IsNullOrWhiteSpace(forwarded) && !forwarded.IsEquals("X-Forwarded-For"))
				options.ForwardedForHeaderName = forwarded;

			forwarded = UtilityService.GetAppSetting("Proxy:X-Forwarded-Host");
			if (!string.IsNullOrWhiteSpace(forwarded) && !forwarded.IsEquals("X-Forwarded-Host"))
				options.ForwardedHostHeaderName = forwarded;

			forwarded = UtilityService.GetAppSetting("Proxy:X-Forwarded-Proto");
			if (!string.IsNullOrWhiteSpace(forwarded) && !forwarded.IsEquals("X-Forwarded-Proto"))
				options.ForwardedProtoHeaderName = forwarded;

			var original = UtilityService.GetAppSetting("Proxy:X-Original-For");
			if (!string.IsNullOrWhiteSpace(original) && !original.IsEquals("X-Original-For"))
				options.OriginalForHeaderName = original;

			original = UtilityService.GetAppSetting("Proxy:X-Original-Host");
			if (!string.IsNullOrWhiteSpace(original) && !original.IsEquals("X-Original-Host"))
				options.OriginalHostHeaderName = original;

			original = UtilityService.GetAppSetting("Proxy:X-Original-Proto");
			if (!string.IsNullOrWhiteSpace(original) && !original.IsEquals("X-Original-Proto"))
				options.OriginalProtoHeaderName = original;

			UtilityService.GetAppSetting("Proxy:IPs")?.ToList()?.ForEach(proxyIP =>
			{
				if (proxyIP.Contains("/"))
				{
					var networkInfo = proxyIP.ToList("/");
					if (IPAddress.TryParse(networkInfo[0], out var prefix) && Int32.TryParse(networkInfo[1], out var prefixLength))
						options.KnownNetworks.Add(new IPNetwork(prefix, prefixLength));
				}
				else if (IPAddress.TryParse(proxyIP, out var ipAddress))
					options.KnownProxies.Add(ipAddress);
			});
			if (options.KnownNetworks.Count > 0 || options.KnownProxies.Count > 0)
				options.ForwardLimit = null;

			try
			{
				onCompleted?.Invoke(options);
			}
			catch { }

			return options;
		}

		/// <summary>
		/// Gets the state that determines to integrate with IIS while running on Windows
		/// </summary>
		public static bool UseIISIntegration => RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && "true".IsEquals(UtilityService.GetAppSetting("Proxy:UseIISIntegration"));

		/// <summary>
		/// Gets the state that determines to use InProcess hosting model when integrate with IIS while running on Windows
		/// </summary>
		public static bool UseIISInProcess
		{
			get
			{
#if NETSTANDARD2_0
				return false;
#else
				if (Global.UseIISIntegration)
				{
					var useIISInProcess = UtilityService.GetAppSetting("Proxy:UseIISInProcess");
					if (string.IsNullOrWhiteSpace(useIISInProcess))
					{
						var configFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "web.config");
						if (File.Exists(configFilePath))
						{
							var xml = new System.Xml.XmlDocument();
							xml.LoadXml(UtilityService.ReadTextFile(configFilePath));
							useIISInProcess = xml.SelectSingleNode("/configuration/location/system.webServer/aspNetCore")?.Attributes["hostingModel"]?.Value;
							useIISInProcess = "InProcess".IsEquals(useIISInProcess).ToString();
						}
					}
					return "true".IsEquals(useIISInProcess);
				}
				return false;
#endif
			}
		}

		/// <summary>
		/// Gets the maximum body size of a request in mega-bytes (MB)
		/// </summary>
		public static int MaxRequestBodySize => Int32.TryParse(UtilityService.GetAppSetting("Limits:Body", UtilityService.GetAppSetting("MaxRequestBodySize", "10", null)), out var maxSize) ? maxSize : 10;

		/// <summary>
		/// Prepares the sessions' options
		/// </summary>
		/// <param name="options"></param>
		/// <param name="idleTimeout">The idle time-out (minutes)</param>
		/// <param name="sessionCookieName">The name of the session cookie</param>
		/// <param name="onCompleted"></param>
		public static void PrepareSessionOptions(SessionOptions options, int idleTimeout = 5, string sessionCookieName = null, Action<SessionOptions> onCompleted = null)
		{
			options.IdleTimeout = TimeSpan.FromMinutes(idleTimeout > 0 ? idleTimeout : 5);
			options.Cookie.Name = sessionCookieName ?? UtilityService.GetAppSetting("DataProtection:Name:Session", ".VIEApps-Session");
			options.Cookie.HttpOnly = true;
			options.Cookie.IsEssential = true;
			options.Cookie.SameSite = SameSiteMode.Strict;
			onCompleted?.Invoke(options);
		}

		/// <summary>
		/// Prepares the multi-part forms' options
		/// </summary>
		/// <param name="options"></param>
		/// <param name="onCompleted"></param>
		public static void PrepareFormOptions(FormOptions options, Action<FormOptions> onCompleted = null)
		{
			options.MultipartBodyLengthLimit = 1024 * 1024 * Global.MaxRequestBodySize;
			onCompleted?.Invoke(options);
		}

		/// <summary>
		/// Prepares the authentications' options
		/// </summary>
		/// <param name="options"></param>
		/// <param name="onCompleted"></param>
		public static void PrepareAuthenticationOptions(AuthenticationOptions options, Action<AuthenticationOptions> onCompleted = null)
		{
			options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
			onCompleted?.Invoke(options);
		}

		/// <summary>
		/// Prepares the cookie authentications' options
		/// </summary>
		/// <param name="options"></param>
		/// <param name="expires">The expiration (minutes)</param>
		/// <param name="authenticateCookieName">The name of the authenticate cookie</param>
		/// <param name="onCompleted"></param>
		public static void PrepareCookieAuthenticationOptions(CookieAuthenticationOptions options, int expires = 5, string authenticateCookieName = null, Action<CookieAuthenticationOptions> onCompleted = null)
		{
			options.SlidingExpiration = true;
			options.ExpireTimeSpan = TimeSpan.FromMinutes(expires > 0 ? expires : 5);
			options.Cookie.Name = authenticateCookieName ?? UtilityService.GetAppSetting("DataProtection:Name:Authentication", ".VIEApps-Auth");
			options.Cookie.HttpOnly = true;
			options.Cookie.SameSite = SameSiteMode.Strict;
			onCompleted?.Invoke(options);
		}

		/// <summary>
		/// Prepares the cookie policys' options
		/// </summary>
		/// <param name="options"></param>
		/// <param name="minimumSameSitePolicy"></param>
		/// <param name="onCompleted"></param>
		public static void PrepareCookiePolicyOptions(CookiePolicyOptions options, SameSiteMode minimumSameSitePolicy = SameSiteMode.Strict, Action<CookiePolicyOptions> onCompleted = null)
		{
			options.MinimumSameSitePolicy = minimumSameSitePolicy;
			options.HttpOnly = HttpOnlyPolicy.Always;
			onCompleted?.Invoke(options);
		}

		/// <summary>
		/// Prepares the data protections' options
		/// </summary>
		/// <param name="dataProtection"></param>
		/// <param name="applicationName">The name of the application</param>
		/// <param name="expies">The expiration (days)</param>
		/// <param name="onCompleted">Callback on completed</param>
		public static void PrepareDataProtection(this IDataProtectionBuilder dataProtection, string applicationName = null, int expies = 7, Action<IDataProtectionBuilder> onCompleted = null)
		{
			dataProtection
				.SetApplicationName(applicationName ?? UtilityService.GetAppSetting("DataProtection:Name:Application", "VIEApps-NGX"))
				.SetDefaultKeyLifetime(TimeSpan.FromDays(expies > 0 ? expies : 7))
				.UseCryptographicAlgorithms(new AuthenticatedEncryptorConfiguration
				{
					EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
					ValidationAlgorithm = ValidationAlgorithm.HMACSHA256
				})
				.PersistKeysToDistributedCache(new DistributedXmlRepositoryOptions
				{
					Key = UtilityService.GetAppSetting("DataProtection:Key", "DataProtection-Keys"),
					CacheOptions = new DistributedCacheEntryOptions
					{
						AbsoluteExpiration = new DateTimeOffset(DateTime.Now.AddDays(expies > 0 ? expies : 7))
					}
				});

			if ("true".IsEquals(UtilityService.GetAppSetting("DataProtection:DisableAutomaticKeyGeneration")))
				dataProtection.DisableAutomaticKeyGeneration();

			onCompleted?.Invoke(dataProtection);
		}

#if !NETSTANDARD2_0
		/// <summary>
		/// Prepares the IIS Servers' options
		/// </summary>
		/// <param name="options"></param>
		/// <param name="onCompleted"></param>
		public static void PrepareIISServerOptions(IISServerOptions options, Action<IISServerOptions> onCompleted = null)
		{
			options.AutomaticAuthentication = false;
			onCompleted?.Invoke(options);
		}
#endif

		/// <summary>
		/// Gets the listening port
		/// </summary>
		/// <param name="args"></param>
		/// <returns></returns>
		public static int GetListeningPort(string[] args = null)
			=> Int32.TryParse(args?.FirstOrDefault(a => a.IsStartsWith("/port:"))?.Replace("/port:", "") ?? UtilityService.GetAppSetting("Port"), out var port) && port > IPEndPoint.MinPort && port < IPEndPoint.MaxPort
				? port
				: UtilityService.GetRandomNumber(8001, 8999);

		/// <summary>
		/// Runs the hosting of ASP.NET Core apps
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="hostBuilder"></param>
		/// <param name="args">The arguments for running</param>
		/// <param name="port">The port for listening</param>
		/// <param name="allowSynchronousIO">Allow synchronous I/O</param>
		public static void Run<T>(this IWebHostBuilder hostBuilder, string[] args = null, int port = 0, bool allowSynchronousIO = false) where T : class
		{
			// prepare the startup class
			hostBuilder.CaptureStartupErrors(true).UseStartup<T>();

			// prepare the web host
#if NETSTANDARD2_0
			var useKestrel = true;
#else
			var useKestrel = !Global.UseIISInProcess;
#endif

			if (useKestrel)
			{
				hostBuilder.UseKestrel(options =>
				{
					options.AddServerHeader = false;
					options.AllowSynchronousIO = allowSynchronousIO;
					options.ListenAnyIP(port > IPEndPoint.MinPort && port < IPEndPoint.MaxPort ? port : Global.GetListeningPort(args), opts => opts.Protocols = HttpProtocols.Http1AndHttp2);
					options.Limits.MaxRequestBodySize = 1024 * 1024 * Global.MaxRequestBodySize;
				});
				if (Global.UseIISIntegration)
					hostBuilder.UseIISIntegration();
			}
#if !NETSTANDARD2_0
			else
				hostBuilder.UseIIS();
#endif

			// build & run the web host
			using (var host = hostBuilder.Build())
			{
				Global.Cache = host.Services.GetService<ICache>();
				AspNetCoreUtilityService.ServerName = UtilityService.GetAppSetting("ServerName", "VIEApps NGX");
				host.Run();
			}
			Global.Cache?.Dispose();
		}
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
			Global.Logger.LogInformation($"RSA was initialized [{Global._RSA.GetType()}] - Key size: {Global._RSA.KeySize} bits");
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

		#region Session
		/// <summary>
		/// Sets the session information
		/// </summary>
		/// <param name="context"></param>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <param name="developerID"></param>
		/// <param name="appID"></param>
		/// <returns></returns>
		public static Session SetSession(this HttpContext context, Session session, string sessionID = null, IUser user = null, string developerID = null, string appID = null)
		{
			session = session ?? Global.GetSession(context.Request.Headers.ToDictionary(), context.Request.QueryString.ToDictionary(), $"{context.Connection.RemoteIpAddress}", sessionID, user);
			if (!string.IsNullOrWhiteSpace(developerID) && developerID.IsValidUUID())
				session.DeveloperID = developerID;
			if (!string.IsNullOrWhiteSpace(appID) && appID.IsValidUUID())
				session.AppID = appID;
			context.SetItem("Session", session);
			return session;
		}

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="header"></param>
		/// <param name="query"></param>
		/// <param name="ipAddress"></param>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public static Session GetSession(Dictionary<string, string> header, Dictionary<string, string> query, string ipAddress, string sessionID = null, IUser user = null)
		{
			var appInfo = Global.GetAppInfo(header, query, ipAddress);
			return new Session
			{
				SessionID = sessionID ?? "",
				User = user != null ? new User(user) : User.GetDefault(sessionID),
				DeviceID = UtilityService.GetAppParameter("x-device-id", header, query),
				IP = ipAddress,
				DeveloperID = UtilityService.GetAppParameter("x-developer-id", header, query),
				AppID = UtilityService.GetAppParameter("x-app-id", header, query),
				AppAgent = UtilityService.GetAppParameter("user-agent", header, query, "N/A"),
				AppName = appInfo.Item1,
				AppPlatform = appInfo.Item2,
				AppOrigin = appInfo.Item3
			};
		}

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="context"></param>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public static Session GetSession(this HttpContext context, string sessionID = null, IUser user = null)
			=> context.GetItem<Session>("Session") ?? context.SetSession(null, sessionID, user);

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
		public static async Task<bool> IsSessionExistAsync(this HttpContext context, Session session, ILogger logger = null, string objectName = null, string correlationID = null)
		{
			if (!string.IsNullOrWhiteSpace(session?.SessionID))
				try
				{
					var json = await context.CallServiceAsync(new RequestInfo(session, "Users", "Session", "EXIST")
					{
						CorrelationID = correlationID ?? context.GetCorrelationID()
					}, Global.CancellationToken, logger, objectName).ConfigureAwait(false);
					return session.SessionID.IsEquals(json.Get<string>("ID")) && json?["Existed"] is JValue isExisted && isExisted.Value != null && "true".IsEquals(isExisted.Value.ToString());
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync(logger, objectName, $"Error occurred while checking the existing of a session => {ex.Message}", ex, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false);
				}
			return false;
		}

		/// <summary>
		/// Checks to see the session is existed or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object to write into log</param>
		/// <returns></returns>
		public static Task<bool> IsSessionExistAsync(this HttpContext context, ILogger logger = null, string objectName = null, string correlationID = null)
			=> context.IsSessionExistAsync(context.GetSession(), logger, objectName, correlationID);

		/// <summary>
		/// Checks to see the session is existed or not
		/// </summary>
		/// <param name="session">The session for checking</param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object to write into log</param>
		/// <returns></returns>
		public static Task<bool> IsSessionExistAsync(this Session session, ILogger logger = null, string objectName = null, string correlationID = null)
			=> Global.IsSessionExistAsync(Global.CurrentHttpContext, session, logger, objectName, correlationID);

		/// <summary>
		/// Gets the encrypted identity of this session
		/// </summary>
		/// <param name="session"></param>
		/// <returns></returns>
		public static string GetEncryptedID(this Session session)
			=> session.GetEncryptedID(session.SessionID, Global.EncryptionKey, Global.ValidationKey);

		/// <summary>
		/// Gets the JSON that presents this session for working with client apps
		/// </summary>
		/// <param name="session"></param>
		/// <param name="onGetAuthenticateTokenCompleted"></param>
		/// <returns></returns>
		public static JToken GetSessionJson(this Session session, Action<JObject> onGetAuthenticateTokenCompleted = null)
		{
			var encryptionKey = session.GetEncryptionKey(Global.EncryptionKey);
			var encryptionIV = session.GetEncryptionIV(Global.EncryptionKey);
			return new JObject
			{
				{ "ID", session.GetEncryptedID() },
				{ "DeviceID", session.DeviceID },
				{ "Token", session.GetAuthenticateToken(onGetAuthenticateTokenCompleted) },
				{  "Keys", new JObject
					{
						{
							"RSA",
							new JObject
							{
								{ "Exponent", Global.RSAExponent },
								{ "Modulus", Global.RSAModulus }
							}
						},
						{
							"AES",
							new JObject
							{
								{ "Key", encryptionKey.ToHex() },
								{ "IV", encryptionIV.ToHex() }
							}
						},
						{
							"JWT",
							Global.JWTKey.Encrypt(encryptionKey, encryptionIV)
						}
					}
				}
			};
		}

		/// <summary>
		/// Gets the JSON that presents this session for working with client apps
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <param name="onGetAuthenticateTokenCompleted"></param>
		/// <returns></returns>
		public static JToken GetSessionJson(this RequestInfo requestInfo, Action<JObject> onGetAuthenticateTokenCompleted = null)
			=> requestInfo.Session.GetSessionJson(onGetAuthenticateTokenCompleted);

		/// <summary>
		/// Gets the JSON that presents this session for working with APIs
		/// </summary>
		/// <param name="session"></param>
		/// <param name="isOnline"></param>
		/// <returns></returns>
		public static JToken GetSessionBody(this Session session, bool isOnline = true)
			=> new JObject
			{
				{ "ID", session.SessionID },
				{ "IssuedAt", DateTime.Now },
				{ "RenewedAt", DateTime.Now },
				{ "ExpiredAt", DateTime.Now.AddDays(90) },
				{ "UserID", session.User.ID },
				{ "AccessToken", session.User.GetAccessToken(Global.ECCKey) },
				{ "IP", session.IP },
				{ "DeviceID", session.DeviceID },
				{ "DeveloperID", session.DeveloperID },
				{ "AppID", session.AppID },
				{ "AppInfo", $"{session.AppName} @ {session.AppPlatform}" },
				{ "OSInfo", $"{session.AppAgent.GetOSInfo()} [{session.AppAgent}]" },
				{ "Verified", session.Verified },
				{ "Online", isOnline }
			};

		/// <summary>
		/// Gets the JSON that presents this session for working with APIs
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <param name="isVerified"></param>
		/// <param name="isOnline"></param>
		/// <returns></returns>
		public static JToken GetSessionBody(this RequestInfo requestInfo, bool isVerified = false, bool isOnline = true)
			=> requestInfo.Session.GetSessionBody(isOnline);

		/// <summary>
		/// Updates the JSON that presents this session for working with APIs
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <param name="session"></param>
		/// <param name="isOnline"></param>
		/// <returns></returns>
		public static JToken UpdateSessionBody(this RequestInfo requestInfo, JToken session, bool isOnline = true)
		{
			session = session ?? requestInfo.GetSessionBody(isOnline);
			session["RenewedAt"] = DateTime.Now;
			session["ExpiredAt"] = DateTime.Now.AddDays(90);
			session["IP"] = requestInfo.Session.IP;
			session["DeviceID"] = requestInfo.Session.DeviceID;
			session["DeveloperID"] = requestInfo.Session.DeveloperID;
			session["AppID"] = requestInfo.Session.AppID;
			session["AppInfo"] = requestInfo.Session.AppName + " @ " + requestInfo.Session.AppPlatform;
			session["OSInfo"] = $"{requestInfo.Session.AppAgent.GetOSInfo()} [{requestInfo.Session.AppAgent}]";
			session["Online"] = isOnline;
			return session;
		}
		#endregion

		#region Authenticate token
		/// <summary>
		/// Gets the authenticate ticket of this session
		/// </summary>
		/// <param name="session"></param>
		/// <param name="onCompleted"></param>
		/// <returns></returns>
		public static string GetAuthenticateToken(this Session session, Action<JObject> onCompleted = null)
		{
			session.User.SessionID = session.SessionID;
			return session.User.GetAuthenticateToken(Global.EncryptionKey, Global.JWTKey, payload =>
			{
				payload["2fa"] = $"{session.Verified}|{UtilityService.NewUUID}".Encrypt(Global.EncryptionKey, true);
				payload["dev"] = (session.DeveloperID ?? "").Encrypt(Global.EncryptionKey, true);
				payload["app"] = (session.AppID ?? "").Encrypt(Global.EncryptionKey, true);
				onCompleted?.Invoke(payload);
			});
		}

		/// <summary>
		/// Updates this session with information of authenticate token
		/// </summary>
		/// <param name="context"></param>
		/// <param name="session"></param>
		/// <param name="authenticateToken"></param>
		/// <param name="expiredAfter"></param>
		/// <param name="onAuthenticateTokenParsed"></param>
		/// <param name="updateWithAccessTokenAsync"></param>
		/// <param name="onAccessTokenParsed"></param>
		/// <param name="logger"></param>
		/// <param name="objectName"></param>
		/// <param name="correlationID"></param>
		/// <returns></returns>
		public static async Task UpdateWithAuthenticateTokenAsync(this HttpContext context, Session session, string authenticateToken, int expiredAfter = 0, Action<JObject, User> onAuthenticateTokenParsed = null, Func<HttpContext, Session, string, Action<JObject, User>, Task> updateWithAccessTokenAsync = null, Action<JObject, User> onAccessTokenParsed = null, ILogger logger = null, string objectName = null, string correlationID = null)
		{
			// get user from authenticate token
			session.User = authenticateToken.ParseAuthenticateToken(Global.EncryptionKey, Global.JWTKey, expiredAfter, (payload, user) =>
			{
				try
				{
					if (!user.ID.Equals(""))
						session.Verified = "true".IsEquals(payload.Get("2fa", "").Decrypt(Global.EncryptionKey, true).ToArray("|").First());
					session.DeveloperID = payload.Get("dev", "").Decrypt(Global.EncryptionKey, true);
					session.AppID = payload.Get("app", "").Decrypt(Global.EncryptionKey, true);
				}
				catch { }
				onAuthenticateTokenParsed?.Invoke(payload, user);
			});

			// update identities
			session.SessionID = session.User.SessionID;

			// get session of authenticated user and verify with access token
			try
			{
				if (!session.User.ID.Equals(""))
				{
					// update access token
					if (updateWithAccessTokenAsync != null)
						await updateWithAccessTokenAsync(context, session, authenticateToken, onAccessTokenParsed).ConfigureAwait(false);
					else
						await context.UpdateWithAccessTokenAsync(session, authenticateToken, onAccessTokenParsed, logger, objectName, correlationID).ConfigureAwait(false);

					// re-update session identity
					session.SessionID = session.User.SessionID;
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
		/// <param name="expiredAfter"></param>
		/// <param name="onAuthenticateTokenParsed"></param>
		/// <param name="updateWithAccessTokenAsync"></param>
		/// <param name="onAccessTokenParsed"></param>
		/// <param name="logger"></param>
		/// <param name="objectName"></param>
		/// <param name="correlationID"></param>
		/// <returns></returns>
		public static Task UpdateWithAuthenticateTokenAsync(Session session, string authenticateToken, int expiredAfter = 0, Action<JObject, User> onAuthenticateTokenParsed = null, Func<HttpContext, Session, string, Action<JObject, User>, Task> updateWithAccessTokenAsync = null, Action<JObject, User> onAccessTokenParsed = null, ILogger logger = null, string objectName = null, string correlationID = null)
			=> Global.UpdateWithAuthenticateTokenAsync(Global.CurrentHttpContext, session, authenticateToken, expiredAfter, onAuthenticateTokenParsed, updateWithAccessTokenAsync, onAccessTokenParsed, logger, objectName, correlationID);

		/// <summary>
		/// Updates this session with information of access token
		/// </summary>
		/// <param name="context"></param>
		/// <param name="session"></param>
		/// <param name="authenticateToken"></param>
		/// <param name="onAccessTokenParsed"></param>
		/// <param name="logger"></param>
		/// <param name="objectName"></param>
		/// <param name="correlationID"></param>
		/// <returns></returns>
		public static async Task UpdateWithAccessTokenAsync(this HttpContext context, Session session, string authenticateToken, Action<JObject, User> onAccessTokenParsed = null, ILogger logger = null, string objectName = null, string correlationID = null)
		{
			// get session of authenticated user and verify with access token
			var json = await context.CallServiceAsync(new RequestInfo(session, "Users", "Session", "GET")
			{
				Header = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					["x-app-token"] = authenticateToken
				},
				Extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					["Signature"] = authenticateToken.GetHMACSHA256(Global.ValidationKey)
				},
				CorrelationID = correlationID ?? context.GetCorrelationID()
			}, Global.CancellationToken, logger, objectName).ConfigureAwait(false);

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
		/// <param name="logger"></param>
		/// <param name="objectName"></param>
		/// <param name="correlationID"></param>
		/// <returns></returns>
		public static Task UpdateWithAccessTokenAsync(Session session, string authenticateToken, Action<JObject, User> onAccessTokenParsed = null, ILogger logger = null, string objectName = null, string correlationID = null)
			=> Global.UpdateWithAccessTokenAsync(Global.CurrentHttpContext, session, authenticateToken, onAccessTokenParsed, logger, objectName, correlationID);
		#endregion

		#region Authentication
		/// <summary>
		/// Determines the user of the current context is authenticated or not
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static bool IsAuthenticated(this HttpContext context)
			=> context != null && context.User != null && context.User.Identity != null && context.User.Identity.IsAuthenticated;

		/// <summary>
		/// Determines the user of the current context is authenticated or not
		/// </summary>
		/// <returns></returns>
		public static bool IsAuthenticated()
			=> Global.IsAuthenticated(Global.CurrentHttpContext);

		/// <summary>
		/// Gets the user of the current context
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static User GetUser(this HttpContext context)
			=> context == null || context.User == null || context.User.Identity == null || !(context.User.Identity is UserIdentity)
				? User.GetDefault()
				: new User(context.User.Identity as IUser);

		/// <summary>
		/// Gets the user of the current context
		/// </summary>
		/// <returns></returns>
		public static User GetUser()
			=> Global.GetUser(Global.CurrentHttpContext);
		#endregion

		#region Authorization
		/// <summary>
		/// Gets the state that determines the user is able to manage or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="entityInfo">The identity of a specified business repository entity (means a business content-type at run-time) or type-name of an entity definition</param>
		/// <param name="objectID">The identity of the object</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task<bool> CanManageAsync(this HttpContext context, string serviceName, string objectName, string systemID, string entityInfo, string objectID, CancellationToken cancellationToken = default)
			=> context != null
				? Router.GetService(serviceName).CanManageAsync(context.GetUser(), objectName, systemID, entityInfo, objectID, cancellationToken)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to moderate or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="entityInfo">The identity of a specified business repository entity (means a business content-type at run-time) or type-name of an entity definition</param>
		/// <param name="objectID">The identity of the object</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task<bool> CanModerateAsync(this HttpContext context, string serviceName, string objectName, string systemID, string entityInfo, string objectID, CancellationToken cancellationToken = default)
			=> context != null
				? Router.GetService(serviceName).CanModerateAsync(context.GetUser(), objectName, systemID, entityInfo, objectID, cancellationToken)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to edit or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="entityInfo">The identity of a specified business repository entity (means a business content-type at run-time) or type-name of an entity definition</param>
		/// <param name="objectID">The identity of the object</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task<bool> CanEditAsync(this HttpContext context, string serviceName, string objectName, string systemID, string entityInfo, string objectID, CancellationToken cancellationToken = default)
			=> context != null
				? Router.GetService(serviceName).CanEditAsync(context.GetUser(), objectName, systemID, entityInfo, objectID, cancellationToken)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to contribute or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="entityInfo">The identity of a specified business repository entity (means a business content-type at run-time) or type-name of an entity definition</param>
		/// <param name="objectID">The identity of the object</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task<bool> CanContributeAsync(this HttpContext context, string serviceName, string objectName, string systemID, string entityInfo, string objectID, CancellationToken cancellationToken = default)
			=> context != null
				? Router.GetService(serviceName).CanContributeAsync(context.GetUser(), objectName, systemID, entityInfo, objectID, cancellationToken)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to view or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="entityInfo">The identity of a specified business repository entity (means a business content-type at run-time) or type-name of an entity definition</param>
		/// <param name="objectID">The identity of the object</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task<bool> CanViewAsync(this HttpContext context, string serviceName, string objectName, string systemID, string entityInfo, string objectID, CancellationToken cancellationToken = default)
			=> context != null
				? Router.GetService(serviceName).CanViewAsync(context.GetUser(), objectName, systemID, entityInfo, objectID, cancellationToken)
				: Task.FromResult(false);

		/// <summary>
		/// Gets the state that determines the user is able to download or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="entityInfo">The identity of a specified business repository entity (means a business content-type at run-time) or type-name of an entity definition</param>
		/// <param name="objectID">The identity of the object</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task<bool> CanDownloadAsync(this HttpContext context, string serviceName, string objectName, string systemID, string entityInfo, string objectID, CancellationToken cancellationToken = default)
			=> context != null
				? Router.GetService(serviceName).CanDownloadAsync(context.GetUser(), objectName, systemID, entityInfo, objectID, cancellationToken)
				: Task.FromResult(false);
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
		/// <param name="logsObjectName"></param>
		public static void WriteError(this HttpContext context, ILogger logger, WampException exception, RequestInfo requestInfo = null, bool writeLogs = true, string logsObjectName = null)
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
				var logs = new List<string> { $"[{type}]: {message}" };

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

				context.WriteLogs(logger, logsObjectName ?? requestInfo?.ObjectName, logs, exception, Global.ServiceName, LogLevel.Error, correlationID);
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
		/// <param name="logsObjectName"></param>
		public static void WriteError(this HttpContext context, WampException exception, RequestInfo requestInfo = null, bool writeLogs = true, string logsObjectName = null)
			=> context.WriteError(Global.Logger, exception, requestInfo, writeLogs, logsObjectName);

		/// <summary>
		/// Writes an error exception as JSON to output with status code
		/// </summary>
		/// <param name="context"></param>
		/// <param name="exception"></param>
		/// <param name="requestInfo"></param>
		/// <param name="logsObjectName"></param>
		public static void WriteError(this HttpContext context, WampException exception, RequestInfo requestInfo, string logsObjectName)
			=> context.WriteError(Global.Logger, exception, requestInfo, true, logsObjectName);

		/// <summary>
		/// Writes an error exception as JSON to output with status code
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger"></param>
		/// <param name="exception"></param>
		/// <param name="requestInfo"></param>
		/// <param name="message"></param>
		/// <param name="writeLogs"></param>
		/// <param name="logsObjectName"></param>
		public static void WriteError(this HttpContext context, ILogger logger, Exception exception, RequestInfo requestInfo = null, string message = null, bool writeLogs = true, string logsObjectName = null)
		{
			if (exception is WampException wampException)
				context.WriteError(logger, wampException, requestInfo, writeLogs, logsObjectName);

			else
			{
				message = message ?? exception?.Message ?? "Unexpected error";
				var correlationID = requestInfo?.CorrelationID ?? context.GetCorrelationID();
				if (writeLogs && exception != null)
					context.WriteLogs(logger, logsObjectName ?? requestInfo?.ObjectName, new List<string>
					{
						message,
						$"Request: {requestInfo?.ToString(Global.IsDebugStacksEnabled ? Formatting.Indented : Formatting.None) ?? "None"}"
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
		/// <param name="logsObjectName"></param>
		public static void WriteError(this HttpContext context, Exception exception, RequestInfo requestInfo = null, string message = null, bool writeLogs = true, string logsObjectName = null)
			=> context.WriteError(Global.Logger, exception, requestInfo, message, writeLogs, logsObjectName);

		/// <summary>
		/// Writes an error exception as JSON to output with status code
		/// </summary>
		/// <param name="context"></param>
		/// <param name="exception"></param>
		/// <param name="requestInfo"></param>
		/// <param name="logsObjectName"></param>
		public static void WriteError(this HttpContext context, Exception exception, RequestInfo requestInfo, string logsObjectName)
			=> context.WriteError(Global.Logger, exception, requestInfo, null, true, logsObjectName);

		/// <summary>
		/// Waits on attempt
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static async Task WaitOnAttemptedAsync(this HttpContext context)
		{
			var cacheKey = $"Attempt#{context.Connection.RemoteIpAddress}";
			var attempt = await Global.Cache.ExistsAsync(cacheKey, Global.CancellationToken).ConfigureAwait(false)
				? await Global.Cache.GetAsync<int>(cacheKey, Global.CancellationToken).ConfigureAwait(false) + 1
				: 1;
			await Task.WhenAll
			(
				Task.Delay(567 + ((attempt - 1) * 5678)),
				Global.Cache.SetAsync(cacheKey, attempt, 13, Global.CancellationToken)
			).ConfigureAwait(false);
		}
		#endregion

		#region Static files
		/// <summary>
		/// Gets the content of a static file
		/// </summary>
		/// <param name="fileInfo"></param>
		/// <returns></returns>
		public static async Task<byte[]> GetStaticFileContentAsync(FileInfo fileInfo, CancellationToken cancellationToken = default)
			=> fileInfo == null || !fileInfo.Exists
				? throw new FileNotFoundException()
				: fileInfo.GetMimeType().IsEndsWith("json")
					? JToken.Parse((await UtilityService.ReadTextFileAsync(fileInfo, null, cancellationToken).ConfigureAwait(false)).Replace("\r", "").Replace("\t", "")).ToString(Formatting.Indented).ToBytes()
					: await UtilityService.ReadBinaryFileAsync(fileInfo, cancellationToken).ConfigureAwait(false);

		/// <summary>
		/// Gets the content of a static file
		/// </summary>
		/// <param name="filePath"></param>
		/// <returns></returns>
		public static Task<byte[]> GetStaticFileContentAsync(string filePath, CancellationToken cancellationToken = default)
			=> Global.GetStaticFileContentAsync(new FileInfo(filePath), cancellationToken);

		/// <summary>
		/// Gets the full path of a static file
		/// </summary>
		/// <param name="pathSegments"></param>
		/// <returns></returns>
		public static string GetStaticFilePath(string[] pathSegments)
		{
			var filePath = pathSegments.First().IsEquals("statics")
				? UtilityService.GetAppSetting("Path:Statics", $"{Global.RootPath}/data-files/statics")
				: Global.RootPath;
			filePath += ("/" + pathSegments.Join("/")).Replace("//", "/").Replace(@"\", "/").Replace('/', Path.DirectorySeparatorChar);
			return pathSegments.First().IsEquals("statics")
				? filePath.Replace($"{Path.DirectorySeparatorChar}statics{Path.DirectorySeparatorChar}statics{Path.DirectorySeparatorChar}", $"{Path.DirectorySeparatorChar}statics{Path.DirectorySeparatorChar}")
				: filePath;
		}

		/// <summary>
		/// Processes the request of static file
		/// </summary>
		/// <param name="context"></param>
		/// <param name="fileInfo"></param>
		/// <param name="encoding"></param>
		/// <param name="cache"></param>
		/// <returns></returns>
		public static async Task ProcessStaticFileRequestAsync(this HttpContext context, FileInfo fileInfo, string encoding = null, Cache cache = null)
		{
			var requestUri = context.GetRequestUri();
			try
			{
				// check existed
				if (fileInfo == null || !fileInfo.Exists)
				{
					if (Global.IsDebugLogEnabled)
						await context.WriteLogsAsync("Http.Statics", $"The requested file is not found ({requestUri} => {fileInfo?.FullName ?? requestUri.GetRequestPathSegments().Join("/")})").ConfigureAwait(false);
					throw new FileNotFoundException($"Not Found [{requestUri}]");
				}

				// headers to reduce traffic
				var eTag = context.GenerateETag();
				if (eTag.IsEquals(context.GetHeaderParameter("If-None-Match")))
				{
					var isNotModified = true;
					var lastModifed = DateTime.Now.ToUnixTimestamp();
					if (context.GetHeaderParameter("If-Modified-Since") != null)
					{
						lastModifed = fileInfo.LastWriteTime.ToUnixTimestamp();
						isNotModified = lastModifed <= context.GetHeaderParameter("If-Modified-Since").FromHttpDateTime().ToUnixTimestamp();
					}
					if (isNotModified)
					{
						context.SetResponseHeaders((int)HttpStatusCode.NotModified, eTag, lastModifed, "public", context.GetCorrelationID());
						if (Global.IsDebugLogEnabled)
							await context.WriteLogsAsync("Http.Statics", $"Success response with status code 304 to reduce traffic ({requestUri} => {fileInfo.FullName} - ETag: {eTag} - Last modified: {fileInfo?.LastWriteTime.ToDTString()})").ConfigureAwait(false);
						return;
					}
				}

				// no caching header => process the request of file
				var mimeType = fileInfo.GetMimeType();
				var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					{ "Content-Type", $"{mimeType}; charset=utf-8" },
					{ "ETag", eTag },
					{ "Last-Modified", $"{fileInfo.LastWriteTime.ToHttpString()}" },
					{ "Cache-Control", "public" },
					{ "Expires", $"{DateTime.Now.AddHours(13).ToHttpString()}" },
					{ "X-Correlation-ID", context.GetCorrelationID() }
				};

				// small files (HTML, JSON, CSS)
				if (mimeType.IsStartsWith("text/") || fileInfo.Extension.IsStartsWith(".json") || fileInfo.Extension.IsStartsWith(".js") || fileInfo.Extension.IsStartsWith(".css") || fileInfo.Extension.IsStartsWith(".htm") || fileInfo.Extension.IsStartsWith(".xml"))
					using (var cts = CancellationTokenSource.CreateLinkedTokenSource(Global.CancellationToken, context.RequestAborted))
					{
						var content = await Global.GetStaticFileContentAsync(fileInfo, cts.Token).ConfigureAwait(false);
						if (!string.IsNullOrWhiteSpace(encoding))
						{
							content = content.Compress(encoding);
							headers["Content-Encoding"] = encoding;
							headers["Content-Length"] = content.Length.ToString();
						}
						await context.WriteAsync(content, headers, cts.Token).ConfigureAwait(false);
					}

				// other files
				else
					using (var cts = CancellationTokenSource.CreateLinkedTokenSource(Global.CancellationToken, context.RequestAborted))
					{
						using (var stream = new FileStream(fileInfo.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, AspNetCoreUtilityService.BufferSize, true))
							await context.WriteAsync(stream, headers, cts.Token).ConfigureAwait(false);
					}

				await Task.WhenAll
				(
					cache != null ? cache.SetAsync($"{eTag}:time", fileInfo.LastWriteTime.ToHttpString(), Global.CancellationToken) : Task.CompletedTask,
					Global.IsDebugLogEnabled ? context.WriteLogsAsync("Http.Statics", $"Success response ({requestUri} => {fileInfo?.FullName ?? requestUri.GetRequestPathSegments().Join("/")} [{fileInfo.Length:#,##0} bytes] - ETag: {eTag} - Last modified: {fileInfo?.LastWriteTime.ToDTString()})") : Task.CompletedTask
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await context.WriteLogsAsync("Http.Statics", $"Failure response [{requestUri}]", ex).ConfigureAwait(false);
				context.ShowHttpError(ex.GetHttpStatusCode(), ex.Message, ex.GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
			}
		}

		/// <summary>
		/// Processes the request of static file
		/// </summary>
		/// <param name="context"></param>
		/// <param name="encoding"></param>
		/// <param name="cache"></param>
		/// <returns></returns>
		public static async Task ProcessStaticFileRequestAsync(this HttpContext context, string encoding = null, Cache cache = null)
		{
			if (context.Request.Method.IsEquals("GET"))
				try
				{
					await context.ProcessStaticFileRequestAsync(new FileInfo(Global.GetStaticFilePath(context.GetRequestUri().GetRequestPathSegments())), encoding, cache).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync("Http.Statics", $"Failure response [{context.GetRequestUri()}]", ex).ConfigureAwait(false);
					context.ShowHttpError(ex.GetHttpStatusCode(), ex.Message, ex.GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
				}
			else
				context.ShowHttpError((int)HttpStatusCode.MethodNotAllowed, $"Method {context.Request.Method} is not allowed", "MethodNotAllowedException", context.GetCorrelationID());
		}

		/// <summary>
		/// Processes the request of favourties icon file
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static async Task ProcessFavouritesIconFileRequestAsync(this HttpContext context)
		{
			if (context.Request.Method.IsEquals("GET"))
			{
				var filePath = UtilityService.GetAppSetting("Path:FAVIcon");
				await context.ProcessStaticFileRequestAsync(string.IsNullOrWhiteSpace(filePath) ? null : new FileInfo(filePath)).ConfigureAwait(false);
			}
			else
				context.ShowHttpError((int)HttpStatusCode.MethodNotAllowed, $"Method {context.Request.Method} is not allowed", "MethodNotAllowedException", context.GetCorrelationID());
		}
		#endregion

		#region Update messages
		/// <summary>
		/// Publishs an update message
		/// </summary>
		/// <param name="message"></param>
		/// <param name="logger"></param>
		/// <returns></returns>
		public static async Task PublishAsync(this UpdateMessage message, ILogger logger = null, string objectName = null)
		{
			try
			{
				await message.SendAsync().ConfigureAwait(false);
				if (Global.IsDebugResultsEnabled)
					await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Successfully send an update message {message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Failure send an update message: {ex.Message} => {message.ToJson().ToString(Formatting.Indented)}", ex).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Publishs a collection of update messages
		/// </summary>
		/// <param name="messages"></param>
		/// <param name="logger"></param>
		/// <returns></returns>
		public static async Task PublishAsync(this List<BaseMessage> messages, string deviceID, string excludedDeviceID, ILogger logger = null, string objectName = null)
		{
			try
			{
				await messages.SendAsync(deviceID, excludedDeviceID).ConfigureAwait(false);
				if (Global.IsDebugResultsEnabled)
					await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Successfully send a collection of update messages\r\n\t{messages.Select(message => message.ToJson().ToString(Formatting.None)).Join("\r\n\t")}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Failure send a collection of update messages: {ex.Message}", ex).ConfigureAwait(false);
			}
		}
		#endregion

		#region Communicate messages
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
				await message.SendAsync().ConfigureAwait(false);
				if (Global.IsDebugResultsEnabled)
					await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Successfully send an inter-communicate message: {message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Failure send an inter-communicate message: {ex.Message}", ex).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Publishs a collection of inter-communicate messages
		/// </summary>
		/// <param name="messages"></param>
		/// <param name="logger"></param>
		/// <returns></returns>
		public static async Task PublishAsync(this List<CommunicateMessage> messages, ILogger logger = null, string objectName = null)
		{
			try
			{
				await messages.SendAsync().ConfigureAwait(false);
				if (Global.IsDebugResultsEnabled)
					await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Successfully send a collection of inter-communicate messages\r\n\t{messages.Select(message => message.ToJson().ToString(Formatting.None)).Join("\r\n\t")}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.InternalAPIs", $"Failure send a collection of inter-communicate messages: {ex.Message}", ex).ConfigureAwait(false);
			}
		}
		#endregion

		#region Register/Unregister services
		/// <summary>
		/// Sends service information to API Gateway
		/// </summary>
		/// <param name="available"></param>
		/// <param name="running"></param>
		/// <param name="objectNameForLogging"></param>
		/// <param name="addHttpSuffix"></param>
		/// <returns></returns>
		public static async Task SendServiceInfoAsync(bool available, bool running, string objectNameForLogging = null, bool addHttpSuffix = true)
		{
			try
			{
				await Extensions.SendServiceInfoAsync($"{Global.ServiceName}{(addHttpSuffix ? ".HTTP" : "")}", new[] { $"/controller-id:{Environment.MachineName.ToLower()}.services.http" }, running, available, Global.CancellationToken).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(Global.Logger, objectNameForLogging ?? "Http.InternalAPIs", $"Failure send the service info to API Gateway => {ex.Message}", ex).ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Sends service information to API Gateway
		/// </summary>
		/// <returns></returns>
		public static Task SendServiceInfoAsync(string objectNameForLogging = null, bool addHttpSuffix = true)
			=> Global.SendServiceInfoAsync(true, true, objectNameForLogging, addHttpSuffix);

		/// <summary>
		/// Registers the service with API Gateway
		/// </summary>
		/// <returns></returns>
		public static Task RegisterServiceAsync(string objectNameForLogging = null, bool addHttpSuffix = true)
			=> Global.SendServiceInfoAsync(objectNameForLogging, addHttpSuffix);

		/// <summary>
		/// Registers the service with API Gateway
		/// </summary>
		/// <returns></returns>
		public static void RegisterService(string objectNameForLogging = null, bool addHttpSuffix = true)
			=> Task.Run(async () => await Global.RegisterServiceAsync(objectNameForLogging, addHttpSuffix).ConfigureAwait(false), Global.CancellationToken)
			.ContinueWith(task =>
			{
				if (task.Exception != null)
					Global.Logger.LogError($"Error occurred while registering the service => {task.Exception.Message}", task.Exception);
			}, Global.CancellationToken, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default)
			.ConfigureAwait(false);

		/// <summary>
		/// Unregisters the service with API Gateway
		/// </summary>
		/// <returns></returns>
		public static Task UnregisterServiceAsync(string objectNameForLogging = null, bool addHttpSuffix = true)
			=> Global.SendServiceInfoAsync(false, false, objectNameForLogging, addHttpSuffix);

		/// <summary>
		/// Unregisters the service with API Gateway
		/// </summary>
		/// <returns></returns>
		public static void UnregisterService(string objectNameForLogging = null, int waitingTimes = 567, bool addHttpSuffix = true)
			=> Global.UnregisterServiceAsync(objectNameForLogging, addHttpSuffix).Wait(waitingTimes > 0 ? waitingTimes : 567);
		#endregion

		#region Connect/Disconnect (API Gateway Router)
		/// <summary>
		/// Connects to the API Gateway Router with default settings
		/// </summary>
		/// <param name="onIncomingConnectionEstablished">The action to fire when the incoming connection is established</param>
		/// <param name="onOutgoingConnectionEstablished">The action to fire when the outgogin connection is established</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static async Task ConnectAsync(
			Action<object, WampSessionCreatedEventArgs> onIncomingConnectionEstablished = null,
			Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished = null,
			CancellationToken cancellationToken = default
		)
		{
			using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, Global.CancellationToken))
				await Router.ConnectAsync(
					async (sender, arguments) =>
					{
						await Router.IncomingChannel.UpdateAsync(arguments.SessionId, Global.ServiceName, $"Incoming ({Global.ServiceName} HTTP service)", Global.Logger).ConfigureAwait(false);
						Global.Logger.LogInformation($"The incoming channel to API Gateway Router is established - Session ID: {arguments.SessionId}");
						try
						{
							onIncomingConnectionEstablished?.Invoke(sender, arguments);
						}
						catch (Exception ex)
						{
							Global.Logger.LogError($"Error occurred while invoking \"{nameof(onIncomingConnectionEstablished)}\" => {ex.Message}", ex);
						}
					},
					(sender, arguments) =>
					{
						if (Router.ChannelsAreClosedBySystem || (arguments.CloseType.Equals(SessionCloseType.Goodbye) && "wamp.close.normal".IsEquals(arguments.Reason)))
							Global.Logger.LogDebug($"The incoming channel to API Gateway Router is closed - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
						else if (Router.IncomingChannel != null)
						{
							Global.Logger.LogDebug($"The incoming channel to API Gateway Router is broken - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
							Router.IncomingChannel.ReOpen(Global.CancellationToken, (msg, ex) => Global.Logger.LogInformation(msg, ex), "Incoming");
						}
					},
					(sender, arguments) => Global.Logger.LogError($"Got an unexpected error of the incoming channel to API Gateway Router => {arguments.Exception?.Message}", arguments.Exception),
					async (sender, arguments) =>
					{
						await Router.OutgoingChannel.UpdateAsync(arguments.SessionId, Global.ServiceName, $"Outgoing ({Global.ServiceName} HTTP service)", Global.Logger).ConfigureAwait(false);
						Global.Logger.LogInformation($"The outgoing channel to API Gateway Router is established - Session ID: {arguments.SessionId}");
						try
						{
							onOutgoingConnectionEstablished?.Invoke(sender, arguments);
						}
						catch (Exception ex)
						{
							Global.Logger.LogError($"Error occurred while invoking \"{nameof(onOutgoingConnectionEstablished)}\" => {ex.Message}", ex);
						}
					},
					(sender, arguments) =>
					{
						if (Router.ChannelsAreClosedBySystem || (arguments.CloseType.Equals(SessionCloseType.Goodbye) && "wamp.close.normal".IsEquals(arguments.Reason)))
							Global.Logger.LogDebug($"The outgoing channel to API Gateway Router is closed - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
						else if (Router.OutgoingChannel != null)
						{
							Global.Logger.LogDebug($"The outgoing channel to API Gateway Router is broken - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
							Router.OutgoingChannel.ReOpen(Global.CancellationToken, (msg, ex) => Global.Logger.LogInformation(msg, ex), "Outgoging");
						}
					},
					(sender, arguments) => Global.Logger.LogError($"Got an unexpected error of the outgoing channel to API Gateway Router => {arguments.Exception?.Message}", arguments.Exception),
					cts.Token
				).ConfigureAwait(false);
		}

		/// <summary>
		/// Connects to the API Gateway Router with default settings
		/// </summary>
		/// <param name="onIncomingConnectionEstablished">The action to fire when the incoming connection is established</param>
		/// <param name="onOutgoingConnectionEstablished">The action to fire when the outgogin connection is established</param>
		/// <param name="waitingTimes">The miliseconds for waiting for connected</param>
		/// <param name="onTimeout">The action to fire when time-out</param>
		/// <param name="onError">The action to fire when got any error (except time-out)</param>
		public static void Connect(
			Action<object, WampSessionCreatedEventArgs> onIncomingConnectionEstablished = null,
			Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished = null,
			int waitingTimes = 6789,
			Action<Exception> onTimeout = null,
			Action<Exception> onError = null
		)
			=> Task.Run(async () =>
			{
				using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(waitingTimes > 0 ? waitingTimes : 6789)))
				{
					try
					{
						await Global.ConnectAsync(onIncomingConnectionEstablished, onOutgoingConnectionEstablished, cts.Token).ConfigureAwait(false);
					}
					catch (OperationCanceledException ex)
					{
						Global.Logger.LogDebug($"Canceled => {ex.Message}", ex);
						if (cts.IsCancellationRequested)
							onTimeout?.Invoke(ex);
						else
							onError?.Invoke(ex);
					}
					catch (Exception ex)
					{
						Global.Logger.LogError($"Error => {ex.Message}", ex);
						onError?.Invoke(ex);
					}
				}
			}, Global.CancellationToken)
			.ContinueWith(task =>
			{
				if (task.Exception != null)
					Global.Logger.LogError($"Error occurred while connecting to API Gateway Router => {task.Exception.Message}", task.Exception);
				else
				{
					Router.RunReconnectTimer();
					Global.Logger.LogInformation("Reconnect-timer was initialized");
				}
			}, Global.CancellationToken, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default)
			.ConfigureAwait(false);

		/// <summary>
		/// Disconnects from API Gateway Router (means close all WAMP channels)
		/// </summary>
		/// <param name="message">The message to send to API Gateway Router before closing the channel</param>
		/// <param name="onError">The action to run when got any error</param>
		public static Task DisconnectAsync(string message = null, Action<Exception> onError = null)
			=> Router.DisconnectAsync(message, onError);

		/// <summary>
		/// Disconnects from API Gateway Router (means close all WAMP channels)
		/// </summary>
		/// <param name="waitingTimes">Times (miliseconds) for waiting to disconnect</param>
		/// <param name="message">The message to send to API Gateway Router before closing the channel</param>
		/// <param name="onError">The action to run when got any error</param>
		public static void Disconnect(int waitingTimes = 1234, string message = null, Action<Exception> onError = null)
			=> Router.Disconnect(waitingTimes, message, onError);
		#endregion

	}
}