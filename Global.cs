#region Related components
using System;
using System.Net;
using System.Linq;
using System.IO;
using System.IO.Compression;
using System.Numerics;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Core.Contracts;
using WampSharp.V2.Realm;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Security;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services
{
	public static partial class Global
	{

		#region Properties
		/// <summary>
		/// Gets or sets name of the service
		/// </summary>
		public static string ServiceName { get; set; }

		/// <summary>
		/// Gets or sets identity of the node that runs the service
		/// </summary>
		public static string NodeID
		{
			get => Router.NodeID;
			set => Router.NodeID = value;
		}

		/// <summary>
		/// Gets or sets the caching storage
		/// </summary>
		public static Cache Cache { get; set; }

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
		/// Gets the segments of static files
		/// </summary>
		public static HashSet<string> StaticSegments { get; } = (UtilityService.GetAppSetting("Segments:Static", "").Trim().ToLower() + "|statics").ToHashSet('|', true);

		/// <summary>
		/// Gets or sets primary updater (for updating inter-communicate messages of a service)
		/// </summary>
		public static IDisposable PrimaryInterCommunicateMessageUpdater { get; set; }

		/// <summary>
		/// Gets or sets secondary updater (for updating inter-communicate messages of a service)
		/// </summary>
		public static IDisposable SecondaryInterCommunicateMessageUpdater { get; set; }

		/// <summary>
		/// Gets or sets cache updater (for invalidating a cache item)
		/// </summary>
		public static IDisposable CacheUpdater { get; set; }
		#endregion

		#region Environment
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
		{
			var correlationID = context?.GetParameter("x-original-correlation-id") ?? context?.GetParameter("x-correlation-id");
			if (string.IsNullOrWhiteSpace(correlationID))
				correlationID = Global.GetCorrelationID(context?.Items);
			else
				context?.SetItem("Correlation-ID", correlationID);
			return correlationID;
		}

		/// <summary>
		/// Gets the correlation identity of the current context
		/// </summary>
		/// <returns></returns>
		public static string GetCorrelationID()
			=> Global.GetCorrelationID(Global.CurrentHttpContext?.Items);

		/// <summary>
		/// Gets the stopwatch of current HTTP pipeline context
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static Stopwatch GetStopwatch(this HttpContext context)
			=> context.Items.TryGetValue("PipelineStopwatch", out var value) && value is Stopwatch stopwatch
				? stopwatch
				: null;

		/// <summary>
		/// Gets the execution times of current HTTP pipeline context
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static string GetExecutionTimes(this HttpContext context)
			=> context.GetStopwatch()?.GetElapsedTimes() ?? "";

		/// <summary>
		/// Gets the execution times of current HTTP pipeline context
		/// </summary>
		/// <returns></returns>
		public static string GetExecutionTimes()
			=> Global.GetExecutionTimes(Global.CurrentHttpContext);

		/// <summary>
		/// Updates the 'server-timing' headers
		/// </summary>
		/// <param name="context"></param>
		/// <param name="data">Data to update - format 'metric;dur=;desc='</param>
		public static HttpContext UpdateServerTiming(this HttpContext context, string data, System.Action onCompleted = null)
		{
			if (!string.IsNullOrWhiteSpace(data))
			{
				var serverTiming = context.Items.TryGetValue("Server-Timing", out var srvTiming) && srvTiming is string ? srvTiming as string : "";
				context.SetItem("Server-Timing", serverTiming + (serverTiming != "" ? ", " : "") + data);
			}
			onCompleted?.Invoke();
			return context;
		}

		/// <summary>
		/// Updates the 'server-timing' headers
		/// </summary>
		/// <param name="context"></param>
		/// <param name="metric"></param>
		/// <param name="duration"></param>
		/// <param name="description"></param>
		/// <param name="onCompleted"></param>
		/// <returns></returns>
		public static HttpContext UpdateServerTiming(this HttpContext context, string metric, long duration, string description = null, System.Action onCompleted = null)
			=> context.UpdateServerTiming(metric + (duration > -1 ? $";dur={duration}" : "") + (string.IsNullOrWhiteSpace(description) ? "" : $";desc=\"{description.Replace("\"", "'")}\""), onCompleted);

		/// <summary>
		/// Updates the 'server-timing' headers
		/// </summary>
		/// <param name="context"></param>
		/// <param name="metric"></param>
		/// <param name="duration"></param>
		/// <param name="description"></param>
		/// <param name="onCompleted"></param>
		/// <returns></returns>
		public static HttpContext UpdateServerTiming(this HttpContext context, string metric, int duration, string description = null, System.Action onCompleted = null)
			=> context.UpdateServerTiming(metric, (long)duration, description, onCompleted);

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
		public static (string Name, string Platform, string Origin) GetAppInfo(Dictionary<string, string> header, Dictionary<string, string> query, string ipAddress)
		{
			var name = UtilityService.GetAppParameter("x-app-name", header, query, "Generic App");
			var userAgent = UtilityService.GetAppParameter("user-agent", header, query);
			var platform = UtilityService.GetAppParameter("x-app-platform", header, query);
			if (string.IsNullOrWhiteSpace(platform))
			{
				platform = (userAgent ?? "").GetOSInfo();
				platform = (platform.IsEquals("Windows") || platform.IsEquals("macOS") || platform.IsEquals("Linux") || platform.IsEquals("Generic OS") ? "Desktop" : platform) + " PWA";
			}
			var origin = UtilityService.GetAppParameter("origin", header, query) ?? UtilityService.GetAppParameter("referer", header, query);
			if (string.IsNullOrWhiteSpace(origin) || origin.IsStartsWith("file://") || origin.IsStartsWith("http://local"))
				origin = ipAddress;
			return (name, platform, origin);
		}

		/// <summary>
		/// Gets the information of the requested app
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static (string Name, string Platform, string Origin) GetAppInfo(this HttpContext context)
			=> Global.GetAppInfo(context.Request.Headers.ToDictionary(), context.Request.QueryString.ToDictionary(), $"{context.GetRemoteIPAddress()}");

		/// <summary>
		/// Gets the information of the requested app
		/// </summary>
		/// <returns></returns>
		public static (string Name, string Platform, string Origin) GetAppInfo()
			=> Global.GetAppInfo(Global.CurrentHttpContext);

		/// <summary>
		/// Gets the information of the app's OS
		/// </summary>
		/// <param name="userAgent"></param>
		/// <returns></returns>
		public static string GetOSInfo(this string userAgent)
			=> Extensions.GetOSInfo(userAgent ?? "");

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
				if (proxyIP.Contains('/'))
				{
					var networkInfo = proxyIP.ToList("/");
					if (IPAddress.TryParse(networkInfo[0], out var prefix) && Int32.TryParse(networkInfo[1], out var prefixLength))
#if NETSTANDARD2_0 || NET8_0
						options.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(prefix, prefixLength));
#else
						options.KnownIPNetworks.Add(new System.Net.IPNetwork(prefix, prefixLength));
#endif
				}
				else if (IPAddress.TryParse(proxyIP, out var ipAddress))
					options.KnownProxies.Add(ipAddress);
			});
#if NETSTANDARD2_0 || NET8_0
			if (options.KnownNetworks.Count > 0 || options.KnownProxies.Count > 0)
#else
			if (options.KnownIPNetworks.Count > 0 || options.KnownProxies.Count > 0)
#endif
				options.ForwardLimit = null;

			onCompleted?.Invoke(options);
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
				if (Global.UseIISIntegration)
				{
					var useIISInProcess = UtilityService.GetAppSetting("Proxy:UseIISInProcess");
					if (string.IsNullOrWhiteSpace(useIISInProcess))
					{
						var fileInfo = new FileInfo(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "web.config"));
						if (fileInfo.Exists)
						{
							var xml = fileInfo.ReadAsXml();
							useIISInProcess = xml.SelectSingleNode("/configuration/location/system.webServer/aspNetCore")?.Attributes["hostingModel"]?.Value;
							useIISInProcess = "InProcess".IsEquals(useIISInProcess).ToString();
						}
					}
					return "true".IsEquals(useIISInProcess);
				}
				return false;
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
		/// <param name="sameSite"></param>
		/// <param name="secure"></param>
		/// <param name="httpOnly"></param>
		/// <param name="cookieName"></param>
		/// <param name="onCompleted"></param>
		public static void PrepareSessionOptions(SessionOptions options, int idleTimeout = 5, SameSiteMode sameSite = SameSiteMode.Lax, CookieSecurePolicy secure = CookieSecurePolicy.Always, HttpOnlyPolicy httpOnly = HttpOnlyPolicy.Always, string cookieName = null, Action<SessionOptions> onCompleted = null)
		{
			options.IdleTimeout = TimeSpan.FromMinutes(idleTimeout > 0 ? idleTimeout : 5);
			options.Cookie.Name = cookieName ?? UtilityService.GetAppSetting("DataProtection:Name:Session", ".VIEApps-Session");
			options.Cookie.IsEssential = true;
			options.Cookie.SameSite = sameSite;
			options.Cookie.SecurePolicy = secure;
			options.Cookie.HttpOnly = httpOnly == HttpOnlyPolicy.Always;
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
		/// <param name="sameSite"></param>
		/// <param name="secure"></param>
		/// <param name="httpOnly"></param>
		/// <param name="cookieName"></param>
		/// <param name="onCompleted"></param>
		public static void PrepareCookieAuthenticationOptions(CookieAuthenticationOptions options, int expires = 0, SameSiteMode sameSite = SameSiteMode.Lax, CookieSecurePolicy secure = CookieSecurePolicy.Always, HttpOnlyPolicy httpOnly = HttpOnlyPolicy.Always, string cookieName = null, Action<CookieAuthenticationOptions> onCompleted = null)
		{
			options.SlidingExpiration = true;
			options.ExpireTimeSpan = TimeSpan.FromMinutes(expires > 0 ? expires : 5);
			options.Cookie.Name = cookieName ?? UtilityService.GetAppSetting("DataProtection:Name:Authentication", ".VIEApps-Auth");
			options.Cookie.IsEssential = true;
			options.Cookie.SameSite = sameSite;
			options.Cookie.SecurePolicy = secure;
			options.Cookie.HttpOnly = httpOnly == HttpOnlyPolicy.Always;
			onCompleted?.Invoke(options);
		}

		/// <summary>
		/// Prepares the cookie policys' options
		/// </summary>
		/// <param name="options"></param>
		/// <param name="sameSite"></param>
		/// <param name="secure"></param>
		/// <param name="httpOnly"></param>
		/// <param name="onCompleted"></param>
		public static void PrepareCookiePolicyOptions(CookiePolicyOptions options, SameSiteMode sameSite = SameSiteMode.Lax, CookieSecurePolicy secure = CookieSecurePolicy.Always, HttpOnlyPolicy httpOnly = HttpOnlyPolicy.Always, Action < CookiePolicyOptions> onCompleted = null)
		{
			options.MinimumSameSitePolicy = sameSite;
			options.Secure = secure;
			options.HttpOnly = httpOnly;
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

		/// <summary>
		/// Prepares the response compressions' options
		/// </summary>
		/// <param name="options"></param>
		/// <param name="onCompleted"></param>
		public static void PrepareResponseCompression(ResponseCompressionOptions options, Action<ResponseCompressionOptions> onCompleted = null)
		{
			options.EnableForHttps = true;
			options.Providers.Add<ZstdCompressionProvider>();
#if !NETSTANDARD2_0
			options.Providers.Add<BrotliCompressionProvider>();
#endif
			options.Providers.Add<GzipCompressionProvider>();
			options.Providers.Add<DeflateCompressionProvider>();
			options.MimeTypes = "image/bmp,image/x-icon,image/svg+xml,application/rss+xml,application/atom+xml,application/xhtml+xml,application/ld+json,application/pdf,application/msword,application/vnd.ms-excel,application/vnd.ms-powerpoint,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.openxmlformats-officedocument.presentationml.presentation".ToArray().Concat(ResponseCompressionDefaults.MimeTypes);
			onCompleted?.Invoke(options);
		}

		/// <summary>
		/// Gets the remote IP address
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static IPAddress GetRemoteIPAddress(this HttpContext context)
		{
			try
			{
				var forwardedIP = context.GetHeaderParameter("X-Forwarded-For");
				return string.IsNullOrWhiteSpace(forwardedIP) ? context.Connection.RemoteIpAddress : IPAddress.Parse(forwardedIP);
			}
			catch
			{
				return context.Connection.RemoteIpAddress;
			}
		}

		/// <summary>
		/// Gets the listening port
		/// </summary>
		/// <param name="args"></param>
		/// <returns></returns>
		public static int GetListeningPort(string[] args = null)
			=> Int32.TryParse(args?.FirstOrDefault(a => a.IsStartsWith("/port:"))?.Replace("/port:", "") ?? UtilityService.GetAppSetting("Port"), out var port) && port > IPEndPoint.MinPort && port < IPEndPoint.MaxPort
				? port
				: UtilityService.GetRandomNumber(8001, 8999);
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
			session = session ?? Global.GetSession(context.Request.Headers.ToDictionary(), context.Request.QueryString.ToDictionary(), $"{context.GetRemoteIPAddress()}", sessionID, user);
			if (!string.IsNullOrWhiteSpace(developerID) && developerID.IsValidUUID())
				session.DeveloperID = developerID;
			if (!string.IsNullOrWhiteSpace(appID) && appID.IsValidUUID())
				session.AppID = appID;
			return context.SetItem("Session", session);
		}

		static readonly string[] SessionAttributes = new[] { "SessionID", "DeviceID", "DeveloperID", "AppID", "AppName", "AppPlatform" };

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="header"></param>
		/// <param name="query"></param>
		/// <param name="ipAddress"></param>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <param name="onCompleted"></param>
		/// <returns></returns>
		public static Session GetSession(Dictionary<string, string> header, Dictionary<string, string> query, string ipAddress, string sessionID = null, IUser user = null, Action<Session> onCompleted = null)
		{
			var (appName, appPlatform, appOrigin) = Global.GetAppInfo(header, query, ipAddress);
			var session = new Session
			{
				IP = ipAddress,
				SessionID = sessionID ?? "",
				User = user != null ? new User(user) : User.GetDefault(sessionID),
				DeviceID = UtilityService.GetAppParameter("x-device-id", header, query),
				DeveloperID = UtilityService.GetAppParameter("x-developer-id", header, query),
				AppID = UtilityService.GetAppParameter("x-app-id", header, query),
				AppAgent = UtilityService.GetAppParameter("user-agent", header, query, "N/A"),
				AppMode = UtilityService.GetAppParameter("x-app-mode", header, query, "Client"),
				AppName = appName,
				AppPlatform = appPlatform,
				AppOrigin = appOrigin
			};
			SessionAttributes.ForEach(name =>
			{
				try
				{
					session.SetAttributeValue(name, session.GetAttributeValue(name).ToString().Url64Decode());
				}
				catch { }
			});
			onCompleted?.Invoke(session);
			return session;
		}

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="context"></param>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public static Session GetSession(this HttpContext context, string sessionID = null, IUser user = null)
		{
			var session = context?.GetItem<Session>("Session") ?? context?.SetSession(null, sessionID, user ?? context.User?.Identity as IUser);
			if (session != null && (string.IsNullOrWhiteSpace(session.SessionID) || string.IsNullOrWhiteSpace(session.DeviceID)))
			{
				var cookie = context?.Request.Cookies[$"{UtilityService.GetAppSetting("DataProtection:Name:Session", ".VIEApps-Session")}-Info"];
				if (!string.IsNullOrWhiteSpace(cookie))
					try
					{
						var info = cookie.Base58Decode(true, "BLAKE").Decrypt(Global.EncryptionKey).GetString().ToList("|");
						if (string.IsNullOrWhiteSpace(session.SessionID) && info.Count > 0)
							session.SessionID = session.User.SessionID = info[0];
						if (string.IsNullOrWhiteSpace(session.DeviceID) && info.Count > 1)
							session.DeviceID = info[1];
					}
					catch { }
			}
			return session ?? Global.GetSession(null, null, "127.0.0.1", sessionID, user);
		}

		/// <summary>
		/// Gets the session information
		/// </summary>
		/// <param name="sessionID"></param>
		/// <param name="user"></param>
		/// <returns></returns>
		public static Session GetSession(string sessionID = null, IUser user = null)
			=> Global.GetSession(Global.CurrentHttpContext, sessionID, user);

		internal static Task<JToken> GetSessionAsync(this HttpContext context, Session session, string authenticateToken = null, ILogger logger = null, string objectName = null, string correlationID = null)
		{
			session = session ?? context.GetSession();
			authenticateToken = authenticateToken ?? session.GetAuthenticateToken();
			var requestInfo = new RequestInfo(session, "Users", "Session", "GET")
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
			};
			return context.CallServiceAsync(requestInfo, Global.CancellationToken, logger, objectName);
		}

		/// <summary>
		/// Stores some important information of the session into encrypted cookie
		/// </summary>
		/// <param name="context"></param>
		/// <param name="session"></param>
		/// <returns></returns>
		public static Session StoreSession(this HttpContext context, Session session = null)
		{
			session = session ?? context?.GetSession();
			if (!string.IsNullOrWhiteSpace(session?.SessionID) && !string.IsNullOrWhiteSpace(session?.DeviceID))
				try
				{
					var name = $"{UtilityService.GetAppSetting("DataProtection:Name:Session", ".VIEApps-Session")}-Info";
					var cookie = context.Request.Cookies[name];
					var info = string.IsNullOrWhiteSpace(cookie) ? null : cookie.Decrypt(Global.EncryptionKey, true).ToList("|");
					if (info == null || info.Count < 2 || !info[0].Equals(session.SessionID) || !info[1].Equals(session.DeviceID))
						context.Response.Cookies.Append(name, $"{session.SessionID}|{session.DeviceID}".ToBytes().Encrypt(Global.EncryptionKey).ToBase58(true, "BLAKE"), new CookieOptions { Expires = DateTime.Now.AddDays(366) });
				}
				catch { }
			return session;
		}

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
		/// <param name="onGetSessionJsonCompleted"></param>
		/// <param name="onGetAuthenticateTokenCompleted"></param>
		/// <returns></returns>
		public static JToken GetSessionJson(this Session session, Action<JToken> onGetSessionJsonCompleted = null, Action<JObject> onGetAuthenticateTokenCompleted = null)
		{
			var encryptionKey = session.GetEncryptionKey(Global.EncryptionKey);
			var encryptionIV = session.GetEncryptionIV(Global.EncryptionKey);
			var sessionJson = new JObject
			{
				{ "ID", session.GetEncryptedID() },
				{ "DeviceID", session.DeviceID },
				{ "Token", session.GetAuthenticateToken(onGetAuthenticateTokenCompleted) },
				{ "Keys", new JObject
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
			onGetSessionJsonCompleted?.Invoke(sessionJson);
			return sessionJson;
		}

		/// <summary>
		/// Gets the JSON that presents this session for working with client apps
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <param name="onGetSessionJsonCompleted"></param>
		/// <param name="onGetAuthenticateTokenCompleted"></param>
		/// <returns></returns>
		public static JToken GetSessionJson(this RequestInfo requestInfo, Action<JToken> onGetSessionJsonCompleted = null, Action<JObject> onGetAuthenticateTokenCompleted = null)
			=> requestInfo.Session.GetSessionJson(onGetSessionJsonCompleted, onGetAuthenticateTokenCompleted);

		/// <summary>
		/// Gets the JSON that presents this session for working with APIs
		/// </summary>
		/// <param name="session"></param>
		/// <param name="isOnline"></param>
		/// <param name="onCompleted"></param>
		/// <returns></returns>
		public static JToken GetSessionBody(this Session session, bool isOnline = true, Action<JToken> onCompleted = null)
		{
			var sessionBody = new JObject
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
			onCompleted?.Invoke(sessionBody);
			return sessionBody;
		}

		/// <summary>
		/// Gets the JSON that presents this session for working with APIs
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <param name="isOnline"></param>
		/// <param name="onCompleted"></param>
		/// <returns></returns>
		public static JToken GetSessionBody(this RequestInfo requestInfo, bool isOnline = true, Action<JToken> onCompleted = null)
			=> requestInfo.Session?.GetSessionBody(isOnline, onCompleted);

		/// <summary>
		/// Updates the JSON that presents this session for working with APIs
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <param name="session"></param>
		/// <param name="isOnline"></param>
		/// <param name="onCompleted"></param>
		/// <returns></returns>
		public static JToken UpdateSessionBody(this RequestInfo requestInfo, JToken session, bool isOnline = true, Action<JToken> onCompleted = null)
		{
			session = session ?? requestInfo.GetSessionBody(isOnline);
			session["RenewedAt"] = DateTime.Now;
			session["ExpiredAt"] = DateTime.Now.AddDays(90);
			session["IP"] = requestInfo.Session.IP;
			session["DeviceID"] = requestInfo.Session.DeviceID;
			session["DeveloperID"] = requestInfo.Session.DeveloperID;
			session["AppID"] = requestInfo.Session.AppID;
			session["AppInfo"] = $"{requestInfo.Session.AppName} @ {requestInfo.Session.AppPlatform}";
			session["OSInfo"] = $"{requestInfo.Session.AppAgent.GetOSInfo()} [{requestInfo.Session.AppAgent}]";
			session["Online"] = isOnline;
			onCompleted?.Invoke(session);
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
			if (session == null || session.User == null)
				return null;
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
		/// <param name="logger"></param>
		/// <param name="objectName"></param>
		/// <param name="correlationID"></param>
		/// <returns></returns>
		public static Task UpdateWithAuthenticateTokenAsync(this HttpContext context, Session session, string authenticateToken, int expiredAfter, ILogger logger, string objectName, string correlationID)
			=> context.UpdateWithAuthenticateTokenAsync(session, authenticateToken, expiredAfter, null, null, null, logger, objectName, correlationID);

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
			// step 1: get user
			try
			{
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
				session.SessionID = session.User.SessionID = string.IsNullOrWhiteSpace(session.User.SessionID) ? UtilityService.NewUUID : session.User.SessionID;
			}
			catch (Exception ex)
			{
				if (ex is InvalidTokenSignatureException)
				{
					var parts = authenticateToken.ToArray('.', true);
					await context.WriteLogsAsync("Authentications", $"JWT authenticate token signature is invalid\r\n> Header: {parts[0]}\r\n> Payload: {parts[1]}\r\n> Signature: {parts[2]}\r\n> Sign key: {Global.JWTKey}", null, Global.ServiceName, LogLevel.Error, correlationID).ConfigureAwait(false);
				}
				else
					await context.WriteLogsAsync("Authentications", $"JWT authenticate token is invalid ==> {authenticateToken}", ex, Global.ServiceName, LogLevel.Error).ConfigureAwait(false);
				throw;
			}

			// step 2: get roles/privileges
			try
			{
				if (string.IsNullOrWhiteSpace(session.User.ID))
				{
					session.User.Roles = new List<string> { $"{SystemRole.All}" };
					session.User.Privileges = new List<Privilege>();
				}
				else
				{
					if (updateWithAccessTokenAsync != null)
						await updateWithAccessTokenAsync(context, session, authenticateToken, onAccessTokenParsed).ConfigureAwait(false);
					else
						await context.UpdateWithAccessTokenAsync(session, authenticateToken, onAccessTokenParsed, logger, objectName, correlationID).ConfigureAwait(false);
				}
			}
			catch (Exception ex)
			{
				throw ex is TokenExpiredException || ex is InvalidTokenException || ex is InvalidTokenSignatureException || ex is SessionExpiredException || ex is InvalidSessionException || ex is SessionNotFoundException ? ex : new InvalidSessionException(ex);
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
		public static async Task UpdateWithAccessTokenAsync(this HttpContext context, Session session, string authenticateToken = null, Action<JObject, User> onAccessTokenParsed = null, ILogger logger = null, string objectName = null, string correlationID = null)
		{
			// get session of authenticated user and verify with access token
			var sessionJson = await context.GetSessionAsync(session, authenticateToken, logger, objectName).ConfigureAwait(false) ?? throw new SessionNotFoundException();

			// check expiration
			if (!DateTime.TryParse(sessionJson.Get<string>("ExpiredAt"), out var expiredAt) || expiredAt < DateTime.Now)
			{
				await context.WriteLogsAsync("Authentications", $"Session is expired\r\n> Time: {sessionJson.Get<string>("ExpiredAt")}\r\n> {sessionJson}", null, Global.ServiceName, LogLevel.Error).ConfigureAwait(false);
				throw new SessionExpiredException();
			}

			// get user with privileges
			var accessToken = sessionJson.Get<string>("AccessToken");
			User user;
			try
			{
				user = accessToken.ParseAccessToken(Global.ECCKey, onAccessTokenParsed);
			}
			catch (Exception ex)
			{
				if (ex is InvalidTokenSignatureException)
				{
					var parts = accessToken.ToArray('.', true);
					var key = ECCsecp256k1.GetPublicKey(Global.ECCKey.GenerateECCPublicKey()).ToHex();
					var signature = $"{parts[0]}.{parts[1]}".GetHMAC(key, "BLAKE256", false).ToBase64Url(true);
					await context.WriteLogsAsync("Authentications", $"JWT access token signature is invalid\r\n> Header: {parts[0]}\r\n> Payload: {parts[1]}\r\n> Signature: {parts[2]}\r\n> Sign key: {key}\r\n> Compute signature: {signature}", null, Global.ServiceName, LogLevel.Error).ConfigureAwait(false);
				}
				else
					await context.WriteLogsAsync("Authentications", $"JWT access token is invalid ==> {accessToken}", ex, Global.ServiceName, LogLevel.Error).ConfigureAwait(false);
				throw;
			}

			// check identity
			var isUserIDMatched = session.User.ID.Equals(user.ID);
			var isSessionIDMatched = session.User.SessionID.Equals(user.SessionID);
			if (!isUserIDMatched || !isSessionIDMatched)
				throw new InvalidSessionException($"Session is invalid [{isUserIDMatched}/{isSessionIDMatched}]");

			// update
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
			=> context != null && context.User != null && context.User.Identity != null && context.User.Identity is UserIdentity userIdentity
				? new User(userIdentity)
				: User.GetDefault();

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
		/// <param name="message"></param>
		/// <param name="writeLogs"></param>
		/// <param name="logsObjectName"></param>
		public static void WriteError(this HttpContext context, ILogger logger, Exception exception, RequestInfo requestInfo = null, string message = null, bool writeLogs = true, string logsObjectName = null)
		{
			// prepare
			var code = exception != null ? exception.GetHttpStatusCode() : 500;
			message = message ?? exception?.Message ?? "Unknown error";
			var type = exception?.GetTypeName(true) ?? "UnknownException";
			var correlationID = requestInfo?.CorrelationID ?? context.GetCorrelationID();
			JArray stacks = null;

			if (exception is WampException wampException)
			{
				var details = wampException.GetDetails(requestInfo);
				code = details.Code;
				message = details.Message;
				type = details.Type;
				var stack = details.Stack;
				var inner = details.InnerException;

				if (Global.IsDebugStacksEnabled & !string.IsNullOrWhiteSpace(stack))
				{
					stacks = new JArray { stack, $"{exception.Message} [{exception.GetType()}] {exception.StackTrace}" };
					while (inner != null)
					{
						stacks.Add($"{inner.Message} [{inner.GetType()}] {inner.StackTrace}");
						inner = inner.InnerException;
					}
				}

				if (writeLogs)
				{
					var logs = new List<string> { $"[{type}]: {message}" };
					stack = "";
					if (requestInfo != null)
						stack += "\r\n" + "==> Request: " + requestInfo.ToJson().ToString(Global.IsDebugStacksEnabled ? Formatting.Indented : Formatting.None);

					var jsonException = details.InnerJSON;
					if (jsonException != null)
						stack += "\r\n" + "==> Response: " + jsonException.ToString(Global.IsDebugStacksEnabled ? Formatting.Indented : Formatting.None);

					if (exception != null)
					{
						stack += "\r\n" + "==> StackTrace: " + exception.StackTrace;
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
			}

			else
			{
				stacks = Global.IsDebugStacksEnabled ? exception?.GetStacks() : null;
				if (writeLogs && exception != null)
					context.WriteLogs(logger, logsObjectName ?? requestInfo?.ObjectName, new List<string>
					{
						message,
						$"Request: {requestInfo?.ToString(Global.IsDebugStacksEnabled ? Formatting.Indented : Formatting.None) ?? "None"}"
					}, exception, Global.ServiceName, LogLevel.Error, correlationID);
			}

			// show error
			context.WriteError(code, message, type, correlationID, stacks);
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
			var cacheKey = $"Attempt#{context.GetRemoteIPAddress()}";
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
		public static async Task<byte[]> GetStaticFileContentAsync(this FileInfo fileInfo, CancellationToken cancellationToken = default)
			=> fileInfo == null || !fileInfo.Exists
				? throw new FileNotFoundException()
				: fileInfo.GetMimeType().IsEndsWith("json")
					? JToken.Parse((await fileInfo.ReadAsTextAsync(cancellationToken).ConfigureAwait(false)).Replace("\r", "").Replace("\t", "")).ToString(Formatting.Indented).ToBytes()
					: await fileInfo.ReadAsBinaryAsync(cancellationToken).ConfigureAwait(false);

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
		/// <returns></returns>
		public static async Task ProcessStaticFileRequestAsync(this HttpContext context, FileInfo fileInfo)
		{
			var requestURI = context.GetRequestUri();
			try
			{
				// check existed
				if (fileInfo == null || !fileInfo.Exists)
				{
					if (Global.IsDebugLogEnabled)
						await context.WriteLogsAsync("Http.Statics", $"The requested file is not found ({requestURI} => {fileInfo?.FullName ?? requestURI.GetRequestPathSegments().Join("/")})").ConfigureAwait(false);
					throw new FileNotFoundException($"Not Found [{requestURI}]");
				}

				// headers to reduce traffic
				var eTag = context.GenerateETag("vieapps");
				if (eTag.IsEquals(context.GetHeaderParameter("If-None-Match")) && context.GetHeaderParameter("If-Modified-Since") != null && fileInfo.LastWriteTimeUtc <= context.GetHeaderParameter("If-Modified-Since").FromHttpDateTime())
				{
					context.SetResponseHeaders((int)HttpStatusCode.NotModified, eTag, fileInfo.LastWriteTimeUtc.ToUnixTimestamp(), "public", context.GetCorrelationID());
					if (Global.IsDebugLogEnabled)
						await context.WriteLogsAsync("Http.Statics", $"Success response with status code 304 to reduce traffic ({requestURI} => {fileInfo.FullName} - ETag: {eTag} - Last modified: {fileInfo?.LastWriteTime.ToDTString()})").ConfigureAwait(false);
					return;
				}

				// no caching header => process the request of file
				var contentType = fileInfo.GetMimeType();
				var isText = contentType.IsStartsWith("text/") || contentType.IsEndsWith("/javascript") || contentType.IsEndsWith("/json") || contentType.IsEndsWith("+xml");
				var isReadable = isText || contentType.IsStartsWith("image/") || contentType.IsStartsWith("video/") || contentType.IsStartsWith("audio/");				
				var maxAge = 12 * 60 * 60;
				var headers = new Dictionary<string, string>
				{
					["ETag"] = eTag,
					["Content-Type"] = contentType + (isText ? "; charset=utf-8" : ""),
					["Content-Disposition"] = isReadable ? null : "attachment; filename=\"" + fileInfo.Name.UrlEncode() + "\"",
					["Cache-Control"] = context.GetHttpCacheControl(false, maxAge, maxAge, false),
					["Expires"] = DateTime.Now.AddSeconds(maxAge).ToHttpString(),
					["Last-Modified"] = fileInfo.LastWriteTime.ToHttpString(),
					["X-Cache"] = "SEND-FILE",
					["X-Node"] = Global.NodeID,
					["X-Correlation-ID"] = context.GetCorrelationID()
				};
				await context.SendFileAsync(fileInfo, headers, context.RequestAborted).ConfigureAwait(false);
				if (Global.IsDebugLogEnabled)
					await context.WriteLogsAsync("Http.Statics", $"Success response ({requestURI} => {fileInfo.FullName ?? requestURI.GetRequestPathSegments().Join("/")} [{fileInfo.Length:#,##0} bytes] - ETag: {eTag} - Last modified: {fileInfo.LastWriteTime.ToDTString()})").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await context.WriteLogsAsync("Http.Statics", $"Failure response [{requestURI}]", ex).ConfigureAwait(false);
				context.ShowError(ex.GetHttpStatusCode(), ex.Message, ex.GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
			}
		}

		/// <summary>
		/// Processes the request of static file
		/// </summary>
		/// <param name="context"></param>
		/// <param name="cache"></param>
		/// <returns></returns>
		public static async Task ProcessStaticFileRequestAsync(this HttpContext context, Cache cache = null)
		{
			if (context.Request.Method.IsEquals("GET"))
				try
				{
					await context.ProcessStaticFileRequestAsync(new FileInfo(Global.GetStaticFilePath(context.GetRequestUri().GetRequestPathSegments()))).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync("Http.Statics", $"Failure response [{context.GetRequestUri()}]", ex).ConfigureAwait(false);
					context.ShowError(ex.GetHttpStatusCode(), ex.Message, ex.GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
				}
			else
				context.ShowError((int)HttpStatusCode.MethodNotAllowed, $"Method {context.Request.Method} is not allowed", "MethodNotAllowedException", context.GetCorrelationID());
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
				context.ShowError((int)HttpStatusCode.MethodNotAllowed, $"Method {context.Request.Method} is not allowed", "MethodNotAllowedException", context.GetCorrelationID());
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
					await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.APIs", $"Successfully send an update message {message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.APIs", $"Failure send an update message: {ex.Message} => {message.ToJson().ToString(Formatting.Indented)}", ex).ConfigureAwait(false);
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
					await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.APIs", $"Successfully send a collection of update messages\r\n\t{messages.Select(message => message.ToJson().ToString(Formatting.None)).Join("\r\n\t")}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.APIs", $"Failure send a collection of update messages: {ex.Message}", ex).ConfigureAwait(false);
			}
		}
		#endregion

		#region Push communicate messages
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
					await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.APIs", $"Successfully send an inter-communicate message: {message.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.APIs", $"Failure send an inter-communicate message: {ex.Message}", ex).ConfigureAwait(false);
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
					await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.APIs", $"Successfully send a collection of inter-communicate messages\r\n\t{messages.Select(message => message.ToJson().ToString(Formatting.None)).Join("\r\n\t")}").ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await Global.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.APIs", $"Failure send a collection of inter-communicate messages: {ex.Message}", ex).ConfigureAwait(false);
			}
		}
		#endregion

		#region Event Stream
		/// <summary>
		/// Gets a value indicating whether the request is an Event Stream (Server Sent Event) establishment request.
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static bool IsEventStreamRequest(this HttpContext context)
		{
			var accept = context.GetHeaderParameter("Accept");
			return accept != null && accept.IsContains("text/event-stream");
		}

		/// <summary>
		/// Initializes the response as Event Stream (Server Sent Event)
		/// </summary>
		/// <param name="context"></param>
		/// <param name="headers"></param>
		/// <returns></returns>
		public static Task InitializeEventStreamAsync(this HttpContext context, Dictionary<string, string> headers = null)
		{
			context.SetResponseHeaders((int)HttpStatusCode.OK, new Dictionary<string, string>(headers ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
			{
				["Content-Type"] = "text/event-stream",
				["Access-Control-Allow-Origin"] = "*",
				["X-Node"] = Global.NodeID,
				["X-Correlation-ID"] = context.GetCorrelationID()
			});
			return context.FlushAsync(Global.CancellationToken);
		}

		/// <summary>
		/// Pushs a event message to connected stream
		/// </summary>
		/// <param name="context"></param>
		/// <param name="data">The string that presents data of the event message</param>
		/// <param name="id">The string that presents identity of the event message</param>
		/// <param name="name">The string that presents type of the event message</param>
		/// <param name="retry">The number that presents time (in miniseconds) that the connected client will be waited before retrying</param>
		/// <returns></returns>
		public static async Task PushEventMessageAsync(this HttpContext context, string data, string id = null, string name = null, int retry = 0)
		{
			var message = $"{(string.IsNullOrWhiteSpace(id) ? "" : $"id: {id}\n")}{(string.IsNullOrWhiteSpace(name) ? "" : $"event: {name}\n")}{(retry < 1 ? "" : $"retry: {retry}\n")}data: {data}\n\n";
			using (var cts = CancellationTokenSource.CreateLinkedTokenSource(Global.CancellationToken, context.RequestAborted))
			{
				await context.WritesAsync(message, cts.Token).ConfigureAwait(false);
				await context.FlushAsync(cts.Token).ConfigureAwait(false);
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
				await Global.WriteLogsAsync(Global.Logger, objectNameForLogging ?? "Http.APIs", $"Failure send the service info to API Gateway => {ex.Message}", ex).ConfigureAwait(false);
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
		{
			Global.NodeID = Extensions.GetNodeID();
			return Global.SendServiceInfoAsync(objectNameForLogging, addHttpSuffix);
		}

		/// <summary>
		/// Registers the service with API Gateway
		/// </summary>
		/// <returns></returns>
		public static void RegisterService(string objectNameForLogging = null, bool addHttpSuffix = true)
			=> Global.RegisterServiceAsync(objectNameForLogging, addHttpSuffix).Execute(ex => Global.Logger.LogError($"Error occurred while registering the service => {ex.Message}", ex));

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
		public static void UnregisterService(string objectNameForLogging = null, bool addHttpSuffix = true)
			=> Global.UnregisterServiceAsync(objectNameForLogging, addHttpSuffix).Execute(true);
		#endregion

		#region Connect/Disconnect (API Gateway Router)
		/// <summary>
		/// Connects to the API Gateway with default settings
		/// </summary>
		/// <param name="onIncomingConnectionEstablished">The action to fire when the incoming connection is established</param>
		/// <param name="onOutgoingConnectionEstablished">The action to fire when the outgoing connection is established</param>
		/// <param name="onBackupConnectionEstablished">The action to fire when the backup connection is established</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static async Task ConnectAsync(Action<object, WampSessionCreatedEventArgs> onIncomingConnectionEstablished, Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished, Action<object, WampSessionCreatedEventArgs> onBackupConnectionEstablished, CancellationToken cancellationToken)
		{
			Global.NodeID = Extensions.GetNodeID();
			using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, Global.CancellationToken))
				await Router.ConnectAsync(
					// incoming - on connection established
					(sender, arguments) =>
					{
						Global.WriteLogs(UtilityService.NewUUID, $"The API Gateway incoming channel was established - Session ID: {arguments.SessionId}");
						Router.IncomingChannel.Update(arguments.SessionId, Global.ServiceName, $"Incoming: services.{Global.ServiceName.ToLower()}.http @ {Global.NodeID}", Global.Logger);
						if (!Router.GotBackupRouter())
						{
							Global.CacheUpdater?.Dispose();
							Global.CacheUpdater = Router.IncomingChannel.AssignProcessL1CacheRequest(Global.Cache, $"{Global.ServiceName}.HTTP", Global.NodeID);
							Global.Cache.AssignSendL1CacheRequest($"{Global.ServiceName}.HTTP", Global.NodeID);
						}
						onIncomingConnectionEstablished?.Invoke(sender, arguments);
					},
					// incoming - on connection broken
					(sender, arguments) =>
					{
						var mode = Router.ChannelsAreClosedBySystem || (arguments.CloseType.Equals(SessionCloseType.Goodbye) && "wamp.close.normal".IsEquals(arguments.Reason)) ? "closed" : "broken";
						Global.WriteLogs(UtilityService.NewUUID, $"The API Gateway incoming channel was {mode} - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
					},
					// incoming - on connection error
					(sender, arguments) => Global.WriteLogs(UtilityService.NewUUID, $"Got an unexpected error of the API Gateway incoming channel => {arguments.Exception.Message}", arguments.Exception),
					// outgoing - on connection established
					(sender, arguments) =>
					{
						Global.WriteLogs(UtilityService.NewUUID, $"The API Gateway outgoing channel was established - Session ID: {arguments.SessionId}");
						Router.OutgoingChannel.Update(arguments.SessionId, Global.ServiceName, $"Outgoing: services.{Global.ServiceName.ToLower()}.http @ {Global.NodeID}", Global.Logger);
						onOutgoingConnectionEstablished?.Invoke(sender, arguments);
					},
					// outgoing - on connection broken
					(sender, arguments) =>
					{
						var mode = Router.ChannelsAreClosedBySystem || (arguments.CloseType.Equals(SessionCloseType.Goodbye) && "wamp.close.normal".IsEquals(arguments.Reason)) ? "closed" : "broken";
						Global.WriteLogs(UtilityService.NewUUID, $"The API Gateway outgoing channel was {mode} - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
					},
					// outgoing - on connection error
					(sender, arguments) => Global.WriteLogs(UtilityService.NewUUID, $"Got an unexpected error of the API Gateway outgoing channel => {arguments.Exception.Message}", arguments.Exception),
					// backup - on connection established
					(sender, arguments) =>
					{
						Global.WriteLogs(UtilityService.NewUUID, $"The API Gateway backup channel was established - Session ID: {arguments.SessionId}");
						Router.BackupChannel.Update(arguments.SessionId, Global.ServiceName, $"Backup: services.{Global.ServiceName.ToLower()}.http @ {Global.NodeID}", Global.Logger, true);
						Global.CacheUpdater?.Dispose();
						Global.CacheUpdater = Router.BackupChannel.AssignProcessL1CacheRequest(Global.Cache, $"{Global.ServiceName}.HTTP", Global.NodeID);
						Global.Cache.AssignSendL1CacheRequest($"{Global.ServiceName}.HTTP", Global.NodeID, true);
						onBackupConnectionEstablished?.Invoke(sender, arguments);
					},
					// backup - on connection broken
					(sender, arguments) =>
					{
						var mode = Router.ChannelsAreClosedBySystem || (arguments.CloseType.Equals(SessionCloseType.Goodbye) && "wamp.close.normal".IsEquals(arguments.Reason)) ? "closed" : "broken";
						Global.WriteLogs(UtilityService.NewUUID, $"The API Gateway backup channel was {mode} - {arguments.CloseType} ({(string.IsNullOrWhiteSpace(arguments.Reason) ? "Unknown" : arguments.Reason)})");
					},
					// backup - on connection error
					(sender, arguments) => Global.WriteLogs(UtilityService.NewUUID, $"Got an unexpected error of the API Gateway backup channel => {arguments.Exception.Message}", arguments.Exception),
					cts.Token,
					exception => Global.WriteLogs(UtilityService.NewUUID, $"Error occurred while connecting to API Gateway Router => {exception.Message}", exception)
				).ConfigureAwait(false);
		}
		/// <summary>
		/// Connects to the API Gateway with default settings
		/// </summary>
		/// <param name="onIncomingConnectionEstablished">The action to fire when the incoming connection is established</param>
		/// <param name="onOutgoingConnectionEstablished">The action to fire when the outgoing connection is established</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public static Task ConnectAsync(Action<object, WampSessionCreatedEventArgs> onIncomingConnectionEstablished = null, Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished = null, CancellationToken cancellationToken = default)
			=> Global.ConnectAsync(onIncomingConnectionEstablished, onOutgoingConnectionEstablished, null, cancellationToken);

		static async Task ConnectAsync(Action<object, WampSessionCreatedEventArgs> onIncomingConnectionEstablished, Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished, Action<object, WampSessionCreatedEventArgs> onBackupConnectionEstablished, int waitingTimes, Action<Exception> onTimeout, Action<Exception> onError)
		{
			using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(waitingTimes > 0 ? waitingTimes : 6789)))
				try
				{
					await Global.ConnectAsync(onIncomingConnectionEstablished, onOutgoingConnectionEstablished, onBackupConnectionEstablished, cts.Token).ConfigureAwait(false);
				}
				catch (OperationCanceledException ex)
				{
					Global.WriteLogs(UtilityService.NewUUID, $"Canceled => {ex.Message}", ex);
					if (cts.IsCancellationRequested)
						onTimeout?.Invoke(ex);
					else
						onError?.Invoke(ex);
				}
				catch (Exception ex)
				{
					Global.WriteLogs(UtilityService.NewUUID, $"Error => {ex.Message}", ex);
					onError?.Invoke(ex);
				}
		}

		/// <summary>
		/// Connects to the API Gateway with default settings
		/// </summary>
		/// <param name="onIncomingConnectionEstablished">The action to fire when the incoming connection is established</param>
		/// <param name="onOutgoingConnectionEstablished">The action to fire when the outgoing connection is established</param>
		/// <param name="onBackupConnectionEstablished">The action to fire when the backup connection is established</param>
		/// <param name="waitingTimes">The miliseconds for waiting for connected</param>
		/// <param name="onTimeout">The action to fire when time-out</param>
		/// <param name="onError">The action to fire when got any error (except time-out)</param>
		public static void Connect(Action<object, WampSessionCreatedEventArgs> onIncomingConnectionEstablished, Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished, Action<object, WampSessionCreatedEventArgs> onBackupConnectionEstablished, int waitingTimes = 6789, Action<Exception> onTimeout = null, Action<Exception> onError = null)
			=> Global.ConnectAsync(onIncomingConnectionEstablished, onOutgoingConnectionEstablished, onBackupConnectionEstablished, waitingTimes, onTimeout, onError).Execute();

		/// <summary>
		/// Connects to the API Gateway with default settings
		/// </summary>
		/// <param name="onIncomingConnectionEstablished">The action to fire when the incoming connection is established</param>
		/// <param name="onOutgoingConnectionEstablished">The action to fire when the outgoing connection is established</param>
		/// <param name="waitingTimes">The miliseconds for waiting for connected</param>
		/// <param name="onTimeout">The action to fire when time-out</param>
		/// <param name="onError">The action to fire when got any error (except time-out)</param>
		public static void Connect(Action<object, WampSessionCreatedEventArgs> onIncomingConnectionEstablished = null, Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished = null, int waitingTimes = 6789, Action<Exception> onTimeout = null, Action<Exception> onError = null)
			=> Global.Connect(onIncomingConnectionEstablished, onOutgoingConnectionEstablished, null, waitingTimes, onTimeout, onError);

		/// <summary>
		/// Disconnects from API Gateway (means close all WAMP channels)
		/// </summary>
		/// <param name="message">The message to send to API Gateway Router before closing the channel</param>
		/// <param name="onError">The action to run when got any error</param>
		public static Task DisconnectAsync(string message = null, Action<Exception> onError = null)
		{
			Global.CancellationTokenSource.Cancel();
			Global.PrimaryInterCommunicateMessageUpdater?.Dispose();
			Global.PrimaryInterCommunicateMessageUpdater = null;
			Global.SecondaryInterCommunicateMessageUpdater?.Dispose();
			Global.SecondaryInterCommunicateMessageUpdater = null;
			Global.CacheUpdater?.Dispose();
			Global.CacheUpdater = null;
			Global.CancellationTokenSource.Dispose();
			return Router.DisconnectAsync(message, onError);
		}

		/// <summary>
		/// Disconnects from API Gateway Router (means close all WAMP channels)
		/// </summary>
		/// <param name="message">The message to send to API Gateway Router before closing the channel</param>
		/// <param name="onError">The action to run when got any error</param>
		public static void Disconnect(string message = null, Action<Exception> onError = null)
			=> Global.DisconnectAsync(message, onError).Execute(true);
		#endregion

		#region Crawlerbot
		static List<string> Crawlerbots { get; } = new List<string>
		{
			@" YLT",
			@"^Aether",
			@"^Amazon Simple Notification Service Agent$",
			@"^Amazon-Route53-Health-Check-Service",
			@"^Amazon CloudFront",
			@"^b0t$",
			@"^bluefish ",
			@"^Calypso v\/",
			@"^COMODO DCV",
			@"^Corax",
			@"^DangDang",
			@"^DavClnt",
			@"^DHSH",
			@"^docker\/[0-9]",
			@"^Expanse",
			@"^FDM ",
			@"^git\/",
			@"^Goose\/",
			@"^Grabber",
			@"^Gradle\/",
			@"^HTTPClient\/",
			@"^HTTPing",
			@"^Java\/",
			@"^Jeode\/",
			@"^Jetty\/",
			@"^Mail\/",
			@"^Mget",
			@"^Microsoft URL Control",
			@"^Mikrotik\/",
			@"^Netlab360",
			@"^NG\/[0-9\.]",
			@"^NING\/",
			@"^npm\/",
			@"^Nuclei",
			@"^PHP-AYMAPI\/",
			@"^PHP\/",
			@"^pip\/",
			@"^pnpm\/",
			@"^RMA\/",
			@"^Ruby|Ruby\/[0-9]",
			@"^symbolicator\\/",
			@"^Swurl ",
			@"^TLS tester ",
			@"^twine\/",
			@"^ureq",
			@"^VSE\/[0-9]",
			@"^WordPress\.com",
			@"^XRL\/[0-9]",
			@"^ZmEu",
			@"008\/",
			@"13TABS",
			@"192\.comAgent",
			@"2GDPR\/",
			@"2ip\.ru",
			@"404enemy",
			@"7Siters",
			@"80legs",
			@"a3logics\.in",
			@"A6-Indexer",
			@"Abonti",
			@"Aboundex",
			@"aboutthedomain",
			@"Accoona-AI-Agent",
			@"acoon",
			@"acrylicapps\.com\/pulp",
			@"Acunetix",
			@"AdAuth\/",
			@"adbeat",
			@"AddThis",
			@"ADmantX",
			@"AdminLabs",
			@"adressendeutschland",
			@"adreview\/",
			@"adscanner",
			@"adstxt-worker",
			@"Adstxtaggregator",
			@"adstxt\.com",
			@"Adyen HttpClient",
			@"AffiliateLabz\/",
			@"affilimate-puppeteer",
			@"agentslug",
			@"AHC",
			@"aihit",
			@"aiohttp\/",
			@"Airmail",
			@"akka-http\/",
			@"akula\/",
			@"alertra",
			@"alexa site audit",
			@"Alibaba\.Security\.Heimdall",
			@"Alligator",
			@"allloadin",
			@"AllSubmitter",
			@"alyze\.info",
			@"amagit",
			@"Anarchie",
			@"AndroidDownloadManager",
			@"Anemone",
			@"AngleSharp",
			@"annotate_google",
			@"Anthill",
			@"Anturis Agent",
			@"Ant\.com",
			@"AnyEvent-HTTP\/",
			@"Apache Ant\/",
			@"Apache Droid",
			@"Apache OpenOffice",
			@"Apache-HttpAsyncClient",
			@"Apache-HttpClient",
			@"ApacheBench",
			@"Apexoo",
			@"apimon\.de",
			@"APIs-Google",
			@"AportWorm\/",
			@"AppBeat\/",
			@"AppEngine-Google",
			@"AppleSyndication",
			@"Aprc\/[0-9]",
			@"Arachmo",
			@"arachnode",
			@"Arachnophilia",
			@"Ahrefs",
			@"aria2",
			@"Arukereso",
			@"asafaweb",
			@"Asana\/",
			@"Ask Jeeves",
			@"AskQuickly",
			@"ASPSeek",
			@"Asterias",
			@"Astute",
			@"asynchttp",
			@"Attach",
			@"attohttpc",
			@"autocite",
			@"AutomaticWPTester",
			@"Autonomy",
			@"awin\.com",
			@"AWS Security Scanner",
			@"axios\/",
			@"a\.pr-cy\.ru",
			@"B-l-i-t-z-B-O-T",
			@"Backlink-Ceck",
			@"BacklinkHttpStatus",
			@"BackStreet",
			@"BackupLand",
			@"BackWeb",
			@"Bad-Neighborhood",
			@"Badass",
			@"baidu\.com",
			@"Bandit",
			@"Barracuda Sentinel \(EE\)",
			@"basicstate",
			@"BatchFTP",
			@"Battleztar Bazinga",
			@"baypup\/",
			@"BazQux",
			@"BBBike",
			@"BCKLINKS",
			@"BDFetch",
			@"BegunAdvertising",
			@"Bewica-security-scan",
			@"Bidtellect",
			@"BigBozz",
			@"Bigfoot",
			@"biglotron",
			@"bingbot",
			@"BingLocalSearch",
			@"BingPreview",
			@"binlar",
			@"biNu image cacher",
			@"Bitacle",
			@"Bitrix link preview",
			@"biz_Directory",
			@"BKCTwitterUnshortener\/",
			@"Black Hole",
			@"Blackboard Safeassign",
			@"BlackWidow",
			@"BlockNote\.Net",
			@"BlogBridge",
			@"Bloglines",
			@"Bloglovin",
			@"BlogPulseLive",
			@"BlogSearch",
			@"Blogtrottr",
			@"BlowFish",
			@"boitho\.com-dc",
			@"Boost\.Beast",
			@"BPImageWalker",
			@"Braintree-Webhooks",
			@"Branch Metrics API",
			@"Branch-Passthrough",
			@"Brandprotect",
			@"Brandwatch",
			@"Brodie\/",
			@"Browsershots",
			@"BUbiNG",
			@"Buck\/",
			@"Buddy",
			@"BuiltWith",
			@"Bullseye",
			@"BunnySlippers",
			@"Burf Search",
			@"Butterfly\/",
			@"BuzzSumo",
			@"CAAM\/[0-9]",
			@"caam dot crwlr at gmail dot com",
			@"CakePHP",
			@"Calculon",
			@"Canary%20Mail",
			@"CaretNail",
			@"catexplorador",
			@"CC Metadata Scaper",
			@"Cegbfeieh",
			@"censys",
			@"centuryb.o.t9[at]gmail.com",
			@"Cerberian Drtrs",
			@"CERT\.at-Statistics-Survey",
			@"cf-facebook",
			@"cg-eye",
			@"changedetection",
			@"ChangesMeter",
			@"Charlotte",
			@"chatterino-api-cache",
			@"CheckHost",
			@"checkprivacy",
			@"CherryPicker",
			@"ChinaClaw",
			@"Chirp\/",
			@"chkme\.com",
			@"Chlooe",
			@"Chromaxa",
			@"CirrusExplorer",
			@"CISPA Vulnerability Notification",
			@"CISPA Web Analyser",
			@"Citoid",
			@"CJNetworkQuality",
			@"Clarsentia",
			@"clips\.ua\.ac\.be",
			@"Cloud mapping",
			@"CloudEndure",
			@"CloudFlare-AlwaysOnline",
			@"Cloudflare-Healthchecks",
			@"Cloudinary",
			@"cmcm\.com",
			@"coccoc",
			@"cognitiveseo",
			@"ColdFusion",
			@"colly -",
			@"CommaFeed",
			@"Commons-HttpClient",
			@"commonscan",
			@"contactbigdatafr",
			@"contentkingapp",
			@"Contextual Code Sites Explorer",
			@"convera",
			@"CookieReports",
			@"copyright sheriff",
			@"CopyRightCheck",
			@"Copyscape",
			@"cortex\/",
			@"Cosmos4j\.feedback",
			@"Covario-IDS",
			@"Craw\/",
			@"Crescent",
			@"Criteo",
			@"Crowsnest",
			@"CSHttp",
			@"CSSCheck",
			@"Cula\/",
			@"curb",
			@"Curious George",
			@"curl",
			@"cuwhois\/",
			@"cybo\.com",
			@"DAP\/NetHTTP",
			@"DareBoost",
			@"DatabaseDriverMysqli",
			@"DataCha0s",
			@"DatadogSynthetics",
			@"Datafeedwatch",
			@"Datanyze",
			@"DataparkSearch",
			@"dataprovider",
			@"DataXu",
			@"Daum(oa)?[ \/][0-9]",
			@"dBpoweramp",
			@"ddline",
			@"deeris",
			@"delve\.ai",
			@"Demon",
			@"DeuSu",
			@"developers\.google\.com\/\+\/web\/snippet\/",
			@"Devil",
			@"Digg",
			@"Digincore",
			@"DigitalPebble",
			@"Dirbuster",
			@"Discourse Forum Onebox",
			@"Dispatch\/",
			@"Disqus\/",
			@"DittoSpyder",
			@"dlvr",
			@"DMBrowser",
			@"DNSPod-reporting",
			@"docoloc",
			@"Dolphin http client",
			@"DomainAppender",
			@"DomainLabz",
			@"Domains Project\/",
			@"Donuts Content Explorer",
			@"dotMailer content retrieval",
			@"dotSemantic",
			@"downforeveryoneorjustme",
			@"Download Wonder",
			@"downnotifier",
			@"DowntimeDetector",
			@"Drip",
			@"drupact",
			@"Drupal \(\+http:\/\/drupal\.org\/\)",
			@"DTS Agent",
			@"dubaiindex",
			@"DuplexWeb-Google",
			@"DynatraceSynthetic",
			@"EARTHCOM",
			@"Easy-Thumb",
			@"EasyDL",
			@"Ebingbong",
			@"ec2linkfinder",
			@"eCairn-Grabber",
			@"eCatch",
			@"ECCP",
			@"eContext\/",
			@"Ecxi",
			@"EirGrabber",
			@"ElectricMonk",
			@"elefent",
			@"EMail Exractor",
			@"EMail Wolf",
			@"EmailWolf",
			@"Embarcadero",
			@"Embed PHP Library",
			@"Embedly",
			@"endo\/",
			@"europarchive\.org",
			@"evc-batch",
			@"EventMachine HttpClient",
			@"Everwall Link Expander",
			@"Evidon",
			@"Evrinid",
			@"ExactSearch",
			@"ExaleadCloudview",
			@"Excel\/",
			@"exif",
			@"ExoRank",
			@"Exploratodo",
			@"Express WebPictures",
			@"Extreme Picture Finder",
			@"EyeNetIE",
			@"ezooms",
			@"facebookcatalog",
			@"facebookexternalagent",
			@"facebookexternalhit",
			@"facebookexternalua",
			@"facebookplatform",
			@"meta-catalog",
			@"meta-externalagent",
			@"meta-externalhit",
			@"meta-externalua",
			@"meta-platform",
			@"fairshare",
			@"Faraday v",
			@"fasthttp",
			@"Faveeo",
			@"Favicon downloader",
			@"faviconarchive",
			@"faviconkit",
			@"FavOrg",
			@"Feed Wrangler",
			@"Feedable\/",
			@"Feedbin",
			@"FeedBooster",
			@"FeedBucket",
			@"FeedBunch\/",
			@"FeedBurner",
			@"feeder",
			@"Feedly",
			@"FeedshowOnline",
			@"Feedshow\/",
			@"Feedspot",
			@"FeedViewer\/",
			@"Feedwind\/",
			@"FeedZcollector",
			@"feeltiptop",
			@"Fetch API",
			@"Fetch\/[0-9]",
			@"Fever\/[0-9]",
			@"FHscan",
			@"Fiery%20Feeds",
			@"Filestack",
			@"Fimap",
			@"findlink",
			@"findthatfile",
			@"FlashGet",
			@"FlipboardBrowserProxy",
			@"FlipboardProxy",
			@"FlipboardRSS",
			@"Flock\/",
			@"Florienzh\/",
			@"fluffy",
			@"Flunky",
			@"flynxapp",
			@"forensiq",
			@"ForusP",
			@"FoundSeoTool",
			@"fragFINN\.de",
			@"free thumbnails",
			@"Freeuploader",
			@"FreshRSS",
			@"frontman",
			@"Funnelback",
			@"Fuzz Faster U Fool",
			@"G-i-g-a-b-o-t",
			@"g00g1e\.net",
			@"ganarvisitas",
			@"gdnplus\.com",
			@"GeedoProductSearch",
			@"geek-tools",
			@"Genieo",
			@"GentleSource",
			@"GetCode",
			@"Getintent",
			@"GetLinkInfo",
			@"getprismatic",
			@"GetRight",
			@"getroot",
			@"GetURLInfo\/",
			@"GetWeb",
			@"Geziyor",
			@"Ghost Inspector",
			@"GigablastOpenSource",
			@"GIS-LABS",
			@"github-camo",
			@"GitHub-Hookshot",
			@"github\.com",
			@"Go http package",
			@"Go [\d\.]* package http",
			@"Go!Zilla",
			@"Go-Ahead-Got-It",
			@"Go-http-client",
			@"go-mtasts\/",
			@"gobuster",
			@"gobyus",
			@"Gofeed",
			@"gofetch",
			@"Goldfire Server",
			@"GomezAgent",
			@"gooblog",
			@"Goodzer\/",
			@"Google AppsViewer",
			@"Google Desktop",
			@"Google favicon",
			@"Google Keyword Suggestion",
			@"Google Keyword Tool",
			@"Google Page Speed Insights",
			@"Google PP Default",
			@"Google Search Console",
			@"Google Web Preview",
			@"Google-Ads",
			@"Google-Adwords",
			@"Google-Apps-Script",
			@"Google-Calendar-Importer",
			@"Google-HotelAdsVerifier",
			@"Google-HTTP-Java-Client",
			@"Google-InspectionTool",
			@"Google-Podcast",
			@"Google-Publisher-Plugin",
			@"Google-Read-Aloud",
			@"Google-SearchByImage",
			@"Google-Site-Verification",
			@"Google-SMTP-STS",
			@"Google-speakr",
			@"Google-Structured-Data-Testing-Tool",
			@"Google-Transparency-Report",
			@"google-xrawler",
			@"Google-Youtube-Links",
			@"Googlebot",
			@"GoogleDocs",
			@"GoogleHC\/",
			@"GoogleOther",
			@"GoogleProber",
			@"GoogleProducer",
			@"GoogleSites",
			@"Gookey",
			@"GoSpotCheck",
			@"gosquared-thumbnailer",
			@"Gotit",
			@"GoZilla",
			@"grabify",
			@"GrabNet",
			@"Grafula",
			@"Grammarly",
			@"GrapeFX",
			@"GreatNews",
			@"Gregarius",
			@"GRequests",
			@"grokkit",
			@"grouphigh",
			@"grub-client",
			@"gSOAP\/",
			@"GT::WWW",
			@"GTmetrix",
			@"GuzzleHttp",
			@"gvfs\/",
			@"HAA(A)?RTLAND http client",
			@"Haansoft",
			@"hackney\/",
			@"Hadi Agent",
			@"HappyApps-WebCheck",
			@"Hardenize",
			@"Hatena",
			@"Havij",
			@"HaxerMen",
			@"HEADMasterSEO",
			@"HeartRails_Capture",
			@"help@dataminr\.com",
			@"heritrix",
			@"Hexometer",
			@"historious",
			@"hkedcity",
			@"hledejLevne\.cz",
			@"Hloader",
			@"HMView",
			@"Holmes",
			@"HonesoSearchEngine",
			@"HootSuite Image proxy",
			@"Hootsuite-WebFeed",
			@"hosterstats",
			@"HostTracker",
			@"ht:\/\/check",
			@"htdig",
			@"HTMLparser",
			@"htmlyse",
			@"HTTP Banner Detection",
			@"http-get",
			@"HTTP-Header-Abfrage",
			@"http-kit",
			@"http-request\/",
			@"HTTP-Tiny",
			@"HTTP::Lite",
			@"http:\/\/www.neomo.de\/",
      @"HttpComponents",
			@"httphr",
			@"HTTPie",
			@"HTTPMon",
			@"httpRequest",
			@"httpscheck",
			@"httpssites_power",
			@"httpunit",
			@"HttpUrlConnection",
			@"http\.rb\/",
			@"HTTP_Compression_Test",
			@"http_get",
			@"http_request2",
			@"http_requester",
			@"httrack",
			@"huaweisymantec",
			@"HubSpot ",
			@"HubSpot-Link-Resolver",
			@"Humanlinks",
			@"i2kconnect\/",
			@"Iblog",
			@"ichiro",
			@"Id-search",
			@"IdeelaborPlagiaat",
			@"IDG Twitter Links Resolver",
			@"IDwhois\/",
			@"Iframely",
			@"igdeSpyder",
			@"iGooglePortal",
			@"IlTrovatore",
			@"Image Fetch",
			@"Image Sucker",
			@"ImageEngine\/",
			@"ImageVisu\/",
			@"Imagga",
			@"imagineeasy",
			@"imgsizer",
			@"InAGist",
			@"inbound\.li parser",
			@"InDesign%20CC",
			@"Indy Library",
			@"InetURL",
			@"infegy",
			@"infohelfer",
			@"InfoTekies",
			@"InfoWizards Reciprocal Link",
			@"inpwrd\.com",
			@"instabid",
			@"Instapaper",
			@"Integrity",
			@"integromedb",
			@"Intelliseek",
			@"InterGET",
			@"Internet Ninja",
			@"InternetSeer",
			@"internetVista monitor",
			@"internetwache",
			@"internet_archive",
			@"intraVnews",
			@"IODC",
			@"IOI",
			@"Inboxb0t",
			@"iplabel",
			@"ips-agent",
			@"IPS\/[0-9]",
			@"IPWorks HTTP\/S Component",
			@"iqdb\/",
			@"Iria",
			@"Irokez",
			@"isitup\.org",
			@"iskanie",
			@"isUp\.li",
			@"iThemes Sync\/",
			@"IZaBEE",
			@"iZSearch",
			@"JAHHO",
			@"janforman",
			@"Jaunt\/",
			@"Java.*outbrain",
			@"javelin\.io",
			@"Jbrofuzz",
			@"Jersey\/",
			@"JetCar",
			@"Jigsaw",
			@"Jobboerse",
			@"JobFeed discovery",
			@"Jobg8 URL Monitor",
			@"jobo",
			@"Jobrapido",
			@"Jobsearch1\.5",
			@"JoinVision Generic",
			@"JolokiaPwn",
			@"Joomla",
			@"Jorgee",
			@"JS-Kit",
			@"JungleKeyThumbnail",
			@"JustView",
			@"Kaspersky Lab CFR link resolver",
			@"Kelny\/",
			@"Kerrigan\/",
			@"KeyCDN",
			@"Keyword Density",
			@"Keywords Research",
			@"khttp\/",
			@"KickFire",
			@"KimonoLabs\/",
			@"Kml-Google",
			@"knows\.is",
			@"KOCMOHABT",
			@"kouio",
			@"krawler\.dk",
			@"kube-probe",
			@"kubectl",
			@"kulturarw3",
			@"KumKie",
			@"Larbin",
			@"Lavf\/",
			@"leakix\.net",
			@"LeechFTP",
			@"LeechGet",
			@"letsencrypt",
			@"Lftp",
			@"LibVLC",
			@"LibWeb",
			@"Libwhisker",
			@"libwww",
			@"Licorne",
			@"Liferea\/",
			@"Lighthouse",
			@"Lightspeedsystems",
			@"Likse",
			@"limber\.io",
			@"Link Valet",
			@"LinkAlarm\/",
			@"LinkAnalyser",
			@"link-check",
			@"linkCheck",
			@"linkdex",
			@"LinkExaminer",
			@"linkfluence",
			@"linkpeek",
			@"LinkPreview",
			@"LinkScan",
			@"LinksManager",
			@"LinkTiger",
			@"LinkWalker",
			@"link_thumbnailer",
			@"Lipperhey",
			@"Litemage_walker",
			@"livedoor ScreenShot",
			@"LoadImpactRload",
			@"localsearch-web",
			@"LongURL API",
			@"longurl-r-package",
			@"looid\.com",
			@"looksystems\.net",
			@"lscache_runner",
			@"ltx71",
			@"lua-resty-http",
			@"Lucee \(CFML Engine\)",
			@"Lush Http Client",
			@"lwp-request",
			@"lwp-trivial",
			@"LWP::Simple",
			@"lycos",
			@"LYT\.SR",
			@"L\.webis",
			@"mabontland",
			@"MacOutlook\/",
			@"MagentaNews\/",
			@"Mag-Net",
			@"MagpieRSS",
			@"Mail::STS",
			@"MailChimp",
			@"Mail\.Ru",
			@"Majestic12",
			@"makecontact\/",
			@"Mandrill",
			@"MapperCmd",
			@"marketinggrader",
			@"MarkMonitor",
			@"MarkWatch",
			@"Mass Downloader",
			@"masscan\/",
			@"Mata Hari",
			@"mattermost",
			@"MatchorySearch\/",
			@"Mediametric",
			@"Mediapartners-Google",
			@"mediawords",
			@"MegaIndex\.ru",
			@"MeltwaterNews",
			@"Melvil Rawi",
			@"MemGator",
			@"Metaspinner",
			@"MetaURI",
			@"MFC_Tear_Sample",
			@"Microsearch",
			@"Microsoft Data Access",
			@"Microsoft Office",
			@"Microsoft Outlook",
			@"Microsoft Windows Network Diagnostics",
			@"Microsoft-WebDAV-MiniRedir",
			@"Microsoft\.Data\.Mashup",
			@"MicrosoftPreview",
			@"MIDown tool",
			@"MIIxpc",
			@"Mindjet",
			@"Miniature\.io",
			@"Miniflux",
			@"mio_httpc",
			@"Miro-HttpClient",
			@"Mister PiX",
			@"mixdata dot com",
			@"mixed-content-scan",
			@"mixnode",
			@"Mnogosearch",
			@"mogimogi",
			@"Mojeek",
			@"Mojolicious \(Perl\)",
			@"Mollie",
			@"monitis",
			@"Monitority\/",
			@"Monit\/",
			@"montastic",
			@"MonSpark",
			@"MonTools",
			@"Moreover",
			@"Morfeus Fucking Scanner",
			@"Morning Paper",
			@"MovableType",
			@"mowser",
			@"Mrcgiguy",
			@"Mr\.4x3 Powered",
			@"MS Web Services Client Protocol",
			@"MSFrontPage",
			@"mShots",
			@"MuckRack\/",
			@"muhstik-scan",
			@"MVAClient",
			@"MxToolbox\/",
			@"myseosnapshot",
			@"nagios",
			@"Najdi\.si",
			@"Name Intelligence",
			@"NameFo\.com",
			@"Nameprotect",
			@"nationalarchives",
			@"Navroad",
			@"nbertaupete95",
			@"NearSite",
			@"Needle",
			@"Nessus",
			@"Net Vampire",
			@"NetAnts",
			@"NETCRAFT",
			@"NetLyzer",
			@"NetMechanic",
			@"NetNewsWire",
			@"Netpursual",
			@"netresearch",
			@"NetShelter ContentScan",
			@"Netsparker",
			@"NetSystemsResearch",
			@"nettle",
			@"NetTrack",
			@"Netvibes",
			@"NetZIP",
			@"Neustar WPM",
			@"NeutrinoAPI",
			@"NewRelicPinger",
			@"NewsBlur .*Finder",
			@"NewsGator",
			@"newsme",
			@"newspaper\/",
			@"Nexgate Ruby Client",
			@"NG-Search",
			@"nghttp2",
			@"Nibbler",
			@"NICErsPRO",
			@"NihilScio",
			@"Nikto",
			@"nineconnections",
			@"NLNZ_IAHarvester",
			@"Nmap Scripting Engine",
			@"node-fetch",
			@"node-superagent",
			@"node-urllib",
			@"Nodemeter",
			@"NodePing",
			@"node\.io",
			@"nominet\.org\.uk",
			@"nominet\.uk",
			@"Norton-Safeweb",
			@"Notifixious",
			@"notifyninja",
			@"NotionEmbedder",
			@"nuhk",
			@"nutch",
			@"Nuzzel",
			@"nWormFeedFinder",
			@"nyawc\/",
			@"Nymesis",
			@"NYU",
			@"Observatory\/",
			@"Ocelli\/",
			@"Octopus",
			@"oegp",
			@"Offline Explorer",
			@"Offline Navigator",
			@"OgScrper",
			@"okhttp",
			@"omgili",
			@"OMSC",
			@"Online Domain Tools",
			@"Open Source RSS",
			@"OpenCalaisSemanticProxy",
			@"Openfind",
			@"OpenLinkProfiler",
			@"Openstat\/",
			@"OpenVAS",
			@"OPPO A33",
			@"Optimizer",
			@"Orbiter",
			@"OrgProbe\/",
			@"orion-semantics",
			@"Outlook-Express",
			@"Outlook-iOS",
			@"Owler",
			@"Owlin",
			@"ownCloud News",
			@"ow\.ly",
			@"OxfordCloudService",
			@"page scorer",
			@"Page Valet",
			@"page2rss",
			@"PageFreezer",
			@"PageGrabber",
			@"PagePeeker",
			@"PageScorer",
			@"Pagespeed\/",
			@"PageThing",
			@"page_verifier",
			@"Panopta",
			@"panscient",
			@"Papa Foto",
			@"parsijoo",
			@"Pavuk",
			@"PayPal IPN",
			@"pcBrowser",
			@"Pcore-HTTP",
			@"PDF24 URL To PDF",
			@"Pearltrees",
			@"PECL::HTTP",
			@"peerindex",
			@"Peew",
			@"PeoplePal",
			@"Perlu -",
			@"PhantomJS Screenshoter",
			@"PhantomJS\/",
			@"Photon\/",
			@"php-requests",
			@"phpservermon",
			@"Pi-Monster",
			@"Picscout",
			@"Picsearch",
			@"PictureFinder",
			@"Pimonster",
			@"Pingability",
			@"PingAdmin\.Ru",
			@"Pingdom",
			@"Pingoscope",
			@"PingSpot",
			@"ping\.blo\.gs",
			@"pinterest\.com",
			@"Pixray",
			@"Pizilla",
			@"Plagger\/",
			@"Pleroma ",
			@"Ploetz \+ Zeller",
			@"Plukkie",
			@"plumanalytics",
			@"PocketImageCache",
			@"PocketParser",
			@"Pockey",
			@"PodcastAddict\/",
			@"POE-Component-Client-HTTP",
			@"Polymail\/",
			@"Pompos",
			@"Porkbun",
			@"Port Monitor",
			@"postano",
			@"postfix-mta-sts-resolver",
			@"PostmanRuntime",
			@"postplanner\.com",
			@"PostPost",
			@"postrank",
			@"PowerPoint\/",
			@"Prebid",
			@"Prerender",
			@"Priceonomics Analysis Engine",
			@"PrintFriendly",
			@"PritTorrent",
			@"Prlog",
			@"probely\.com",
			@"probethenet",
			@"Project ?25499",
			@"Project-Resonance",
			@"prospectb2b",
			@"Protopage",
			@"ProWebWalker",
			@"proximic",
			@"PRTG Network Monitor",
			@"pshtt, https scanning",
			@"PTST ",
			@"PTST\/[0-9]+",
			@"pulsetic\.com",
			@"Pump",
			@"Python-httplib2",
			@"python-httpx",
			@"python-requests",
			@"Python-urllib",
			@"Qirina Hurdler",
			@"QQDownload",
			@"QrafterPro",
			@"Qseero",
			@"Qualidator",
			@"QueryN Metasearch",
			@"queuedriver",
			@"quic-go-HTTP\/",
			@"QuiteRSS",
			@"Quora Link Preview",
			@"Qwantify",
			@"Radian6",
			@"RadioPublicImageResizer",
			@"Railgun\/",
			@"RankActive",
			@"RankFlex",
			@"RankSonicSiteAuditor",
			@"RapidLoad\/",
			@"Re-re Studio",
			@"ReactorNetty",
			@"Readability",
			@"RealDownload",
			@"RealPlayer%20Downloader",
			@"RebelMouse",
			@"Recorder",
			@"RecurPost\/",
			@"redback\/",
			@"ReederForMac",
			@"Reeder\/",
			@"ReGet",
			@"RepoMonkey",
			@"request\.js",
			@"reqwest\/",
			@"ResponseCodeTest",
			@"RestSharp",
			@"Riddler",
			@"Rival IQ",
			@"Robosourcer",
			@"Robozilla",
			@"ROI Hunter",
			@"RPT-HTTPClient",
			@"RSSMix\/",
			@"RSSOwl",
			@"RuxitSynthetic",
			@"RyowlEngine",
			@"safe-agent-scanner",
			@"SalesIntelligent",
			@"Saleslift",
			@"SAP NetWeaver Application Server",
			@"SauceNAO",
			@"SBIder",
			@"sc-downloader",
			@"scalaj-http",
			@"Scamadviser-Frontend",
			@"ScanAlert",
			@"scan\.lol",
			@"Scoop",
			@"scooter",
			@"ScopeContentAG-HTTP-Client",
			@"ScoutJet",
			@"ScoutURLMonitor",
			@"ScrapeBox Page Scanner",
			@"Scrapy",
			@"Screaming",
			@"ScreenShotService",
			@"Scrubby",
			@"Scrutiny\/",
			@"Search37",
			@"searchenginepromotionhelp",
			@"Searchestate",
			@"SearchExpress",
			@"SearchSight",
			@"SearchWP",
			@"search\.thunderstone",
			@"Seeker",
			@"semanticdiscovery",
			@"semanticjuice",
			@"Semiocast HTTP client",
			@"Semrush",
			@"Sendsay\.Ru",
			@"sentry\/",
			@"SEO Browser",
			@"Seo Servis",
			@"seo-nastroj\.cz",
			@"seo4ajax",
			@"Seobility",
			@"SEOCentro",
			@"SeoCheck",
			@"seocompany",
			@"SEOkicks",
			@"SEOlizer",
			@"Seomoz",
			@"SEOprofiler",
			@"seoscanners",
			@"SEOsearch",
			@"seositecheckup",
			@"SEOstats",
			@"servernfo",
			@"sexsearcher",
			@"Seznam",
			@"Shelob",
			@"Shodan",
			@"Shoppimon",
			@"ShopWiki",
			@"ShortLinkTranslate",
			@"shortURL lengthener",
			@"shrinktheweb",
			@"Sideqik",
			@"Siege",
			@"SimplePie",
			@"SimplyFast",
			@"Siphon",
			@"SISTRIX",
			@"Site Sucker",
			@"Site-Shot\/",
			@"Site24x7",
			@"SiteBar",
			@"Sitebeam",
			@"Sitebulb\/",
			@"SiteCondor",
			@"SiteExplorer",
			@"SiteGuardian",
			@"Siteimprove",
			@"SiteIndexed",
			@"Sitemap(s)? Generator",
			@"SitemapGenerator",
			@"SiteMonitor",
			@"Siteshooter B0t",
			@"SiteSnagger",
			@"SiteSucker",
			@"SiteTruth",
			@"Sitevigil",
			@"sitexy\.com",
			@"SkypeUriPreview",
			@"Slack\/",
			@"sli-systems\.com",
			@"slider\.com",
			@"slurp",
			@"SlySearch",
			@"SmartDownload",
			@"SMRF URL Expander",
			@"SMUrlExpander",
			@"Snake",
			@"Snappy",
			@"SnapSearch",
			@"Snarfer\/",
			@"SniffRSS",
			@"sniptracker",
			@"Snoopy",
			@"SnowHaze Search",
			@"sogou web",
			@"SortSite",
			@"Sottopop",
			@"sovereign\.ai",
			@"SpaceBison",
			@"SpamExperts",
			@"Spammen",
			@"Spanner",
			@"Spawning-AI",
			@"spaziodati",
			@"SPDYCheck",
			@"Specificfeeds",
			@"SpeedKit",
			@"speedy",
			@"SPEng",
			@"Spinn3r",
			@"spray-can",
			@"Sprinklr ",
			@"spyonweb",
			@"sqlmap",
			@"Sqlworm",
			@"Sqworm",
			@"SSL Labs",
			@"ssl-tools",
			@"StackRambler",
			@"Statastico\/",
			@"Statically-",
			@"StatusCake",
			@"Steeler",
			@"Stratagems Kumo",
			@"Stripe\/",
			@"Stroke\.cz",
			@"StudioFACA",
			@"StumbleUpon",
			@"suchen",
			@"Sucuri",
			@"summify",
			@"SuperHTTP",
			@"Surphace Scout",
			@"Suzuran",
			@"swcd ",
			@"Symfony BrowserKit",
			@"Symfony2 BrowserKit",
			@"Synapse\/",
			@"Syndirella\/",
			@"SynHttpClient-Built",
			@"Sysomos",
			@"sysscan",
			@"Szukacz",
			@"T0PHackTeam",
			@"tAkeOut",
			@"Tarantula\/",
			@"Taringa UGC",
			@"TarmotGezgin",
			@"tchelebi\.io",
			@"techiaith\.cymru",
			@"Teleport",
			@"Telesoft",
			@"Telesphoreo",
			@"Telesphorep",
			@"Tenon\.io",
			@"teoma",
			@"terrainformatica",
			@"Test Certificate Info",
			@"testuri",
			@"Tetrahedron",
			@"TextRazor Downloader",
			@"The Drop Reaper",
			@"The Expert HTML Source Viewer",
			@"The Intraformant",
			@"The Knowledge AI",
			@"theinternetrules",
			@"TheNomad",
			@"Thinklab",
			@"Thumbor",
			@"Thumbshots",
			@"ThumbSniper",
			@"timewe\.net",
			@"TinEye",
			@"Tiny Tiny RSS",
			@"TLSProbe\/",
			@"Toata",
			@"topster",
			@"touche\.com",
			@"Traackr\.com",
			@"tracemyfile",
			@"Trackuity",
			@"TrapitAgent",
			@"Trendiction",
			@"Trendsmap",
			@"trendspottr",
			@"truwoGPS",
			@"TryJsoup",
			@"TulipChain",
			@"Turingos",
			@"Turnitin",
			@"tweetedtimes",
			@"Tweetminster",
			@"Tweezler\/",
			@"twibble",
			@"Twice",
			@"Twikle",
			@"Twingly",
			@"Twisted PageGetter",
			@"Typhoeus",
			@"ubermetrics-technologies",
			@"uclassify",
			@"UdmSearch",
			@"ultimate_sitemap_parser",
			@"unchaos",
			@"unirest-java",
			@"UniversalFeedParser",
			@"unshortenit",
			@"Unshorten\.It",
			@"Untiny",
			@"UnwindFetchor",
			@"updated",
			@"updown\.io daemon",
			@"Upflow",
			@"Uptimia",
			@"URL Verifier",
			@"Urlcheckr",
			@"URLitor",
			@"urlresolver",
			@"Urlstat",
			@"URLTester",
			@"UrlTrends Ranking Updater",
			@"URLy Warning",
			@"URLy\.Warning",
			@"URL\/Emacs",
			@"Vacuum",
			@"Vagabondo",
			@"VB Project",
			@"vBSEO",
			@"VCI",
			@"Verity",
			@"via ggpht\.com GoogleImageProxy",
			@"Virusdie",
			@"visionutils",
			@"Visual Rights Group",
			@"vkShare",
			@"VoidEYE",
			@"Voil",
			@"voltron",
			@"voyager\/",
			@"VSAgent\/",
			@"VSB-TUO\/",
			@"Vulnbusters Meter",
			@"VYU2",
			@"w3af\.org",
			@"W3C-checklink",
			@"W3C-mobileOK",
			@"W3C_Unicorn",
			@"WAC-OFU",
			@"WakeletLinkExpander",
			@"WallpapersHD",
			@"Wallpapers\/[0-9]+",
			@"wangling",
			@"Wappalyzer",
			@"WatchMouse",
			@"WbSrch\/",
			@"WDT\.io",
			@"Web Auto",
			@"Web Collage",
			@"Web Enhancer",
			@"Web Fetch",
			@"Web Fuck",
			@"Web Pix",
			@"Web Sauger",
			@"Web spyder",
			@"Web Sucker",
			@"web-capture\.net",
			@"Web-sniffer",
			@"Webalta",
			@"Webauskunft",
			@"WebAuto",
			@"WebCapture",
			@"WebClient\/",
			@"webcollage",
			@"WebCookies",
			@"WebCopier",
			@"WebCorp",
			@"WebDataStats",
			@"WebDoc",
			@"WebEnhancer",
			@"WebFetch",
			@"WebFuck",
			@"WebGazer",
			@"WebGo IS",
			@"WebImageCollector",
			@"WebImages",
			@"WebIndex",
			@"webkit2png",
			@"WebLeacher",
			@"webmastercoffee",
			@"webmon ",
			@"WebPix",
			@"WebReaper",
			@"WebSauger",
			@"webscreenie",
			@"Webshag",
			@"Webshot",
			@"Website Quester",
			@"websitepulse agent",
			@"WebsiteQuester",
			@"Websnapr",
			@"WebSniffer",
			@"Webster",
			@"WebStripper",
			@"WebSucker",
			@"webtech\/",
			@"WebThumbnail",
			@"Webthumb\/",
			@"WebWhacker",
			@"WebZIP",
			@"WeLikeLinks",
			@"WEPA",
			@"WeSEE",
			@"wf84",
			@"Wfuzz\/",
			@"wget",
			@"WhatCMS",
			@"WhatsApp",
			@"WhatsMyIP",
			@"WhatWeb",
			@"WhereGoes\?",
			@"Whibse",
			@"WhoAPI\/",
			@"WhoRunsCoinHive",
			@"Whynder Magnet",
			@"Windows-RSS-Platform",
			@"WinHttp-Autoproxy-Service",
			@"WinHTTP\/",
			@"WinPodder",
			@"wkhtmlto",
			@"wmtips",
			@"Woko",
			@"Wolfram HTTPClient",
			@"woorankreview",
			@"WordPress\/",
			@"WordupinfoSearch",
			@"Word\/",
			@"worldping-api",
			@"wotbox",
			@"WP Engine Install Performance API",
			@"WP Rocket",
			@"wpif",
			@"wprecon\.com survey",
			@"WPScan",
			@"wscheck",
			@"Wtrace",
			@"WWW-Collector-E",
			@"WWW-Mechanize",
			@"WWW::Document",
			@"WWW::Mechanize",
			@"WWWOFFLE",
			@"www\.monitor\.us",
			@"x09Mozilla",
			@"x22Mozilla",
			@"XaxisSemanticsClassifier",
			@"XenForo\/",
			@"Xenu Link Sleuth",
			@"XING-contenttabreceiver",
			@"xpymep([0-9]?)\.exe",
			@"Y!J-[A-Z][A-Z][A-Z]",
			@"Yaanb",
			@"yacy",
			@"Yahoo Link Preview",
			@"YahooCacheSystem",
			@"YahooMailProxy",
			@"YahooYSMcm",
			@"YandeG",
			@"Yandex(?!Search)",
			@"yanga",
			@"yeti",
			@"Yo-yo",
			@"Yoleo Consumer",
			@"yomins\.com",
			@"yoogliFetchAgent",
			@"YottaaMonitor",
			@"Your-Website-Sucks",
			@"yourls\.org",
			@"YoYs\.net",
			@"YP\.PL",
			@"Zabbix",
			@"Zade",
			@"Zao",
			@"Zapier",
			@"Zauba",
			@"Zemanta Aggregator",
			@"Zend\\\\Http\\\\Client",
			@"Zend_Http_Client",
			@"Zermelo",
			@"Zeus ",
			@"zgrab",
			@"ZnajdzFoto",
			@"ZnHTTP",
			@"Zombie\.js",
			@"Zoom\.Mac",
			@"ZoteroTranslationServer",
			@"ZyBorg",
			@"[a-z0-9\-_]*(bot|crawl|headless|archiver|transcoder|spider|uptime|validator|fetcher|cron|checker|reader|extractor|monitoring|analyzer|scraper)"
		};

		static List<string> CrawlerbotExclusions { get; } = new List<string>
		{
			@"Safari.[\d\.]*",
			@"Firefox.[\d\.]*",
			@" Chrome.[\d\.]*",
			@"Chromium.[\d\.]*",
			@"MSIE.[\d\.]",
			@"Opera\/[\d\.]*",
			@"Mozilla.[\d\.]*",
			@"AppleWebKit.[\d\.]*",
			@"Trident.[\d\.]*",
			@"Windows NT.[\d\.]*",
			@"Android [\d\.]*",
			@"Macintosh.",
			@"Ubuntu",
			@"Linux",
			@"[ ]Intel",
			@"Mac OS X [\d_]*",
			@"(like )?Gecko(.[\d\.]*)?",
			@"KHTML,",
			@"CriOS.[\d\.]*",
			@"CPU iPhone OS ([0-9_])* like Mac OS X",
			@"CPU OS ([0-9_])* like Mac OS X",
			@"iPod",
			@"compatible",
			@"x86_..",
			@"i686",
			@"x64",
			@"X11",
			@"rv:[\d\.]*",
			@"Version.[\d\.]*",
			@"WOW64",
			@"Win64",
			@"Dalvik.[\d\.]*",
			@" \.NET CLR [\d\.]*",
			@"Presto.[\d\.]*",
			@"Media Center PC",
			@"BlackBerry",
			@"Build",
			@"Opera Mini\/\d{1,2}\.\d{1,2}\.[\d\.]*\/\d{1,2}\.",
			@"Opera",
			@" \.NET[\d\.]*",
			@"cubot",
			@"; M bot",
			@"; CRONO",
			@"; B bot",
			@"; IDbot",
			@"; ID bot",
			@"; POWER BOT",
			@"OCTOPUS-CORE",
			@";"
		};

		static Regex CrawlerbotsRegex { get; set; }

		static Regex CrawlerbotExclusionsRegex { get; set; }

		/// <summary>
		/// Determines the user is crawlerbot or not
		/// </summary>
		/// <param name="userAgent"></param>
		/// <param name="name"></param>
		/// <returns></returns>
		public static bool IsCrawlerbot(this string userAgent, out string name)
		{
			name = null;
			userAgent = userAgent ?? "";
			var osInfo = userAgent.GetOSInfo();

			if (CrawlerbotExclusionsRegex == null)
				CrawlerbotExclusionsRegex = new Regex("(" + string.Join("|", CrawlerbotExclusions) + ")", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
			userAgent = CrawlerbotExclusionsRegex.Replace(userAgent, "");

			if (!string.IsNullOrWhiteSpace(userAgent))
			{
				if (CrawlerbotsRegex == null)
					CrawlerbotsRegex = new Regex("(" + string.Join("|", Crawlerbots) + ")", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
				var matches = CrawlerbotsRegex.Matches(userAgent);
				name = matches.Count > 0 ? matches[0].Value : null;
			}

			name = name == null && "Generic OS".IsEquals(osInfo) ? "N/A" : name;
			return name != null;
		}

		/// <summary>
		/// Determines the user in this request is crawlerbot or not
		/// </summary>
		/// <param name="context"></param>
		/// <param name="name"></param>
		/// <returns></returns>
		public static bool IsCrawlerbot(this HttpContext context, out string name)
			=> (context.GetUserAgent() ?? "").IsCrawlerbot(out name);

		/// <summary>
		/// Determines the user in this request is crawlerbot or not
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public static bool IsCrawlerbot(this HttpContext context)
			=> context.IsCrawlerbot(out var _);

		/// <summary>
		/// Determines the user in this request is crawlerbot or not
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <param name="name"></param>
		/// <returns></returns>
		public static bool IsCrawlerbot(this RequestInfo requestInfo, out string name)
			=> (requestInfo.Session?.AppAgent ?? "").IsCrawlerbot(out name);

		/// <summary>
		/// Determines the user in this request is crawlerbot or not
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <returns></returns>
		public static bool IsCrawlerbot(this RequestInfo requestInfo)
			=> requestInfo.IsCrawlerbot(out var _);
		#endregion

		#region Statistics, Throttling & Monitoring
		/// <summary>
		/// Gets the statistics
		/// </summary>
		public static Statistics Statistics { get; internal set; }

		/// <summary>
		/// Gets the gate for calling RPC
		/// </summary>
		public static RouterRpcGate RpcGate { get; internal set; }

		/// <summary>
		/// Gets or set the state to monitor the system
		/// </summary>
		public static bool Monitor { get; set; } = false;

		/// <summary>
		/// Gets or set the state to monitor the caching status
		/// </summary>
		public static bool MonitorCache { get; set; } = true;

		/// <summary>
		/// Gets or sets the interval (seconds) for monitoring
		/// </summary>
		public static int MonitorInterval { get; set; } = 15;

		/// <summary>
		/// Gets or set the last-time of monitoring step
		/// </summary>
		public static DateTime MonitorLastTime{ get; set; } = DateTime.Now;

		/// <summary>
		/// Gets the path that store the log of monitoring information
		/// </summary>
		public static string MonitorLogFilePath { get; internal set; }

		/// <summary>
		/// Gets the pattern of file that store the log of monitoring information
		/// </summary>
		public static string MonitorLogFilePattern { get; set; }

		/// <summary>
		/// Starts monitor the system
		/// </summary>
		/// <param name="logPath"></param>
		public static void StartMonitor(string logPath)
		{
			ThreadPool.GetMaxThreads(out var maxWorker, out var maxIO);
			ThreadPool.GetMinThreads(out var minWorker, out var minIO);
			Global.Logger.LogInformation($"ThreadPool - Workers: {minWorker:###,##0} / {maxWorker:###,##0} - Async IO: {minIO:###,##0} / {maxIO:###,##0}");

			if (Global.Monitor && !string.IsNullOrWhiteSpace(logPath))
			{
				Global.Logger.LogInformation($"Start to monitor => {Global.MonitorLogFilePath = logPath}");

				if (!Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor:Cache:Ping:Warn"), out var warnPing) || warnPing < 0)
					warnPing = 5;
				if (!Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor:Cache:Ping:Critical"), out var criticalPing) || criticalPing < 0)
					criticalPing = 10;
				if (!Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor:Cache:QueueSize:Warn"), out var warnQS) || warnQS < 0)
					warnQS = 1000;
				if (!Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor:Cache:QueueSize:Critical"), out var criticalQS) || criticalQS < 0)
					criticalQS = 5000;

				Global.Cache.StartMonitor(
					(msg, details) => Global.OnMonitor(msg, details),
					(msg, _, ex) => Global.OnMonitor(msg, ("", 0, 0, 0), ex),
					(msg, _) => Global.OnMonitor(msg, ("", 0, 0, 0)),
					(msg, _, ex) => Global.OnMonitor(msg, ("", 0, 0, 0), ex),
					Global.MonitorInterval * 1000, warnPing, criticalPing, warnQS, criticalQS, Global.CancellationToken);
			}
		}

		/// <summary>
		/// Stops the monitor
		/// </summary>
		public static void StopMonitor()
		{
			try
			{
				Global.Cache.StopMonitor();
			}
			catch { }
		}

		internal static void OnMonitor(string message, (string Level, long Total, long Interactive, long PingMiliseconds) details, Exception ex = null)
		{
			var now = DateTime.Now;
			var elapsedSeconds = (now - Global.MonitorLastTime).TotalSeconds;
			var pid = Process.GetCurrentProcess().Id.ToString();
			var logs = $"{now:HH:mm:ss} - PID: {pid} - HTTP {Global.ServiceName} @ {Global.NodeID} -----\r\n";
			if (string.IsNullOrWhiteSpace(details.Level))
			{
				logs += message;
				if (ex != null)
					logs += "\r\n" + ex.Message + " [" + ex.GetTypeName(true) + "]" + "\r\n" + "Stack: " + ex.GetStack(false);
			}
			else
			{
				ThreadPool.GetAvailableThreads(out var availableWorkers, out var availableIO);
				ThreadPool.GetMaxThreads(out var maxWorkers, out var maxIO);
				var currentWorkers = maxWorkers - availableWorkers;
				var currentIO = maxIO - availableIO;
				logs += $"ThreadPool - Workers: {currentWorkers:###,##0} / {maxWorkers:###,##0} | Async IO: {currentIO:###,##0} / {maxIO:###,##0}" + "\r\n"
					+ $"Requests - Rate: {Global.Statistics.GetRequestsRate(elapsedSeconds):0.00}/s | InFlight: {Global.Statistics.RequestsInFlight:###,###,###,##0} | Total: {Global.Statistics.RequestsTotal:###,###,###,##0}" + "\r\n";
				if (Global.MonitorCache)
				{
					logs += $"Cache ({Global.Cache.Provider})" + "\r\n" + $"  Status - {message}" + "\r\n";
					if (Global.Cache.UseL1Cache)
						logs += $"  L1 - Hit Rate: {Global.Statistics.GetL1HitRate():0.##}% | Miss: {Global.Statistics.L1MissCount:###,###,###,##0} | 200: {Global.Statistics.L1Hit200Count:###,###,###,##0} | 304: {Global.Statistics.L1Hit304Count:###,###,###,##0} | Total: {Global.Cache.GetL1CacheCount():###,###,###,##0}" + "\r\n";
					logs += "  " + (Global.Cache.UseL1Cache ? "L2" : "Stats") + $" - Hit Rate: {Global.Statistics.GetL2HitRate(Global.Cache.UseL1Cache):0.##}% | Miss: {Global.Statistics.L2MissCount:###,###,###,##0} | 200: {Global.Statistics.L2Hit200Count:###,###,###,##0} | 304: {Global.Statistics.L2Hit304Count:###,###,###,##0}" + "\r\n";
				}
				logs += "RPC" + "\r\n"
					+ $"  Gate - Usage: {(Global.RpcGate.Usage * 100):0.00}% | Current: {Global.RpcGate.Current:###,##0} | Available: {Global.RpcGate.Available:###,##0} | Max: {Global.RpcGate.Max:###,##0}" + "\r\n"
					+ $"  Call - Rate: {Global.Statistics.GetRpcRate(elapsedSeconds):0.00}/s | InFlight: {Global.Statistics.RpcInFlightCount:###,###,###,##0} | Rejected: {Global.Statistics.RpcRejectedCount:###,###,###,##0} | Entered: {Global.Statistics.RpcEnteredCount:###,###,###,##0}";
			}
			logs += "\r\n\r\n";
			Global.MonitorLastTime = now;
			var service = Global.ServiceName.ToLower();
			var hour = now.ToString("yyyyMMddHH");
			var filePath = Path.Combine(Global.MonitorLogFilePath, Global.MonitorLogFilePattern.Replace(StringComparison.OrdinalIgnoreCase, "{service}", service).Replace(StringComparison.OrdinalIgnoreCase, "{pid}", pid).Replace(StringComparison.OrdinalIgnoreCase, "{hour}", hour));
			if (!Global.CancellationTokenSource.IsCancellationRequested)
#if NETSTANDARD2_0
				UtilityService.SaveAsTextAsync(logs, filePath, Global.CancellationToken, true).Execute();
#else
				File.AppendAllTextAsync(filePath, logs, Global.CancellationToken).Execute();
#endif			
		}
		#endregion

#if NETSTANDARD2_0
		/// <summary>
		/// Runs the ASP.NET Core app
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
			if (Global.UseIISInProcess)
				hostBuilder.UseIIS();

			else
			{
				hostBuilder.UseKestrel(options =>
				{
					options.AddServerHeader = false;
					options.AllowSynchronousIO = allowSynchronousIO;
					options.Limits.MaxRequestBodySize = 1024 * 1024 * Global.MaxRequestBodySize;
					options.ListenAnyIP(port > IPEndPoint.MinPort && port < IPEndPoint.MaxPort ? port : Global.GetListeningPort(args));
				});
				if (Global.UseIISIntegration)
					hostBuilder.UseIISIntegration();
			}

			// set min thread pool
			if (Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:ThreadPool:Workers"), out var workers) && workers > 0)
			{
				ThreadPool.GetMaxThreads(out var maxWorkers, out var _);
				if (workers > maxWorkers)
					workers = maxWorkers / 10;
				ThreadPool.SetMinThreads(workers, workers / 10);
			}

			// statistics
			Global.Statistics = new Statistics();

			// gate of Router RPC
			Global.RpcGate = new RouterRpcGate(Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:RpcGate:Max"), out var value) && value > 0 ? value : 500, Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:RpcGate:Timeout"), out value) && value > 0 ? value : 50);

			// monitorr
			Global.Monitor = "true".IsEquals(UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor"));
			Global.MonitorCache = "true".IsEquals(UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor:Cache"));
			Global.MonitorInterval = Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor:Interval"), out value) && value > 0 ? value : 5;
			Global.MonitorLogFilePattern = UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor:FilePattern", "{service}.http.{pid}-{hour}-monitor.txt");

			// build & run the web host
			using (var host = hostBuilder.Build())
			{
				Global.Cache = host.Services.GetService<ICache>() as Cache;
				host.Run();
			}
		}
#else
		/// <summary>
		/// Runs the ASP.NET Core app
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="builder"></param>
		/// <param name="args"></param>
		/// <param name="getAppConfig"></param>
		/// <param name="configAppServices"></param>
		/// <param name="configAppSettings"></param>
		/// <param name="port"></param>
		/// <param name="allowSynchronousIO"></param>
		public static void Run<T>(this WebApplicationBuilder builder, string[] args, Func<IConfiguration, T> getAppConfig, Action<T, IServiceCollection> configAppServices, Action<T, WebApplication> configAppSettings, int port = 0, bool allowSynchronousIO = false) where T : class
		{
			// prepare the startup class
			var startup = getAppConfig(builder.Configuration);
			configAppServices(startup, builder.Services);

			// prepare the web host
			if (Global.UseIISInProcess)
				builder.WebHost.UseIIS();

			else
			{
				builder.WebHost.UseKestrel(options =>
				{
					options.AddServerHeader = false;
					options.AllowSynchronousIO = allowSynchronousIO;
					options.Limits.MaxRequestBodySize = 1024 * 1024 * Global.MaxRequestBodySize;
					options.ListenAnyIP(port > IPEndPoint.MinPort && port < IPEndPoint.MaxPort ? port : Global.GetListeningPort(args));
				});
				if (Global.UseIISIntegration)
					builder.WebHost.UseIISIntegration();
			}

			// set min thread pool
			if (Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:ThreadPool:Workers"), out var workers) && workers > 0)
			{
				ThreadPool.GetMaxThreads(out var maxWorkers, out var _);
				if (workers > maxWorkers)
					workers = maxWorkers / 10;
				ThreadPool.SetMinThreads(workers, workers / 10);
			}

			// statistics
			Global.Statistics = new Statistics();

			// gate of Router RPC
			Global.RpcGate = new RouterRpcGate(Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:RpcGate:Max"), out var value) && value > 0 ? value : 500, Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:RpcGate:Timeout"), out value) && value > 0 ? value : 50);

			// monitor
			Global.Monitor = "true".IsEquals(UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor"));
			Global.MonitorCache = "true".IsEquals(UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor:Cache"));
			Global.MonitorInterval = Int32.TryParse(UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor:Interval"), out value) && value > 0 ? value : 5;
			Global.MonitorLogFilePattern = UtilityService.GetAppSetting($"{Global.ServiceName}:Monitor:FilePattern", "{service}.http.{pid}-{hour}-monitor.txt");

			// build & run the app
			using var app = builder.Build();
			configAppSettings(startup, app);
			Global.Cache = app.Services.GetService<ICache>() as Cache;
			app.Run();
		}
#endif

	}

	#region Response-Compression providers
	/// <summary>
	/// ZSTD compression provider.
	/// </summary>
	public class ZstdCompressionProvider : ICompressionProvider
	{
		public string EncodingName => "zstd";

		public bool SupportsFlush => true;

		public Stream CreateStream(Stream stream)
			=> new ZstdSharp.CompressionStream(stream, 10);
	}

	/// <summary>
	/// DEFLATE compression provider.
	/// </summary>
	public class DeflateCompressionProvider : ICompressionProvider
	{
		public string EncodingName => "deflate";

		public bool SupportsFlush => true;

		public Stream CreateStream(Stream stream)
			=> new DeflateStream(stream, CompressionLevel.Optimal, true);
	}
	#endregion

}