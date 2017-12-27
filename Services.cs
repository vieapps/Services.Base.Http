#region Related components
using System;
using System.Linq;
using System.Web;
using System.Threading;
using System.Threading.Tasks;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.Specialized;

using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Base.AspNet
{
	public static partial class Global
	{
		static Dictionary<string, IService> Services = new Dictionary<string, IService>(StringComparer.OrdinalIgnoreCase);

		/// <summary>
		/// Gets a business service
		/// </summary>
		/// <param name="name">The string that presents name of a business service (for marking related URIs)</param>
		/// <returns></returns>
		public static async Task<IService> GetServiceAsync(string name)
		{
			if (string.IsNullOrWhiteSpace(name))
				throw new ArgumentException("The name of the requested service is invalid", nameof(name));

			if (!Global.Services.TryGetValue(name, out IService service))
			{
				await Global.OpenOutgoingChannelAsync().ConfigureAwait(false);
				lock (Global.Services)
				{
					if (!Global.Services.TryGetValue(name, out service))
					{
						service = Global.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IService>(ProxyInterceptor.Create(name.ToLower()));
						Global.Services.Add(name, service);
					}
				}
			}

			return service;
		}

		/// <summary>
		/// Calls a business service
		/// </summary>
		/// <param name="requestInfo">The requesting information</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <param name="onStart">The action to run when start</param>
		/// <param name="onSuccess">The action to run when success</param>
		/// <param name="onError">The action to run when got an error</param>
		/// <returns></returns>
		public static async Task<JObject> CallServiceAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken), Action<RequestInfo> onStart = null, Action<RequestInfo, JObject> onSuccess = null, Action<RequestInfo, Exception> onError = null)
		{
			// get the instance of service
			IService service = null;
			try
			{
				service = await Global.GetServiceAsync(requestInfo.ServiceName).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				onError?.Invoke(requestInfo, ex);
				throw ex;
			}

			// call the service
			onStart?.Invoke(requestInfo);
			try
			{
				var json = await service.ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false);
				onSuccess?.Invoke(requestInfo, json);
				return json;
			}
			catch (WampSharp.V2.Client.WampSessionNotEstablishedException)
			{
				await Task.Delay(567, cancellationToken).ConfigureAwait(false);
				try
				{
					var json = await service.ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false);
					onSuccess?.Invoke(requestInfo, json);
					return json;
				}
				catch (Exception inner)
				{
					onError?.Invoke(requestInfo, inner);
					throw inner;
				}
			}
			catch (Exception ex)
			{
				onError?.Invoke(requestInfo, ex);
				throw ex;
			}
		}

		/// <summary>
		/// Calls a business service
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName"></param>
		/// <param name="objectName"></param>
		/// <param name="verb"></param>
		/// <param name="query"></param>
		/// <param name="extra"></param>
		/// <param name="onStart"></param>
		/// <param name="onSuccess"></param>
		/// <param name="onError"></param>
		/// <returns></returns>
		public static Task<JObject> CallServiceAsync(this HttpContext context, string serviceName, string objectName, string verb, Dictionary<string, string> query, Dictionary<string, string> extra = null, Action<RequestInfo> onStart = null, Action<RequestInfo, JObject> onSuccess = null, Action<RequestInfo, Exception> onError = null)
		{
			var requestInfo = new RequestInfo(context.GetSession(UtilityService.NewUID, context.User.Identity as User), serviceName, objectName, verb, query, null, null, extra, UtilityService.NewUID);
			return Global.CallServiceAsync(requestInfo, Global.CancellationTokenSource.Token, onStart, onSuccess, onError);
		}

		internal static ILoggingService _LoggingService = null;

		/// <summary>
		/// Gets the logging service
		/// </summary>
		public static ILoggingService LoggingService
		{
			get
			{
				if (Global._LoggingService == null)
					Task.WaitAll(new[] { Global.InitializeLoggingServiceAsync() }, TimeSpan.FromSeconds(13));
				return Global._LoggingService;
			}
		}

		/// <summary>
		/// Initializes the logging service
		/// </summary>
		/// <returns></returns>
		public static async Task InitializeLoggingServiceAsync()
		{
			if (Global._LoggingService == null)
			{
				await Global.OpenOutgoingChannelAsync().ConfigureAwait(false);
				Global._LoggingService = Global._OutgoingChannel.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create());
			}
		}

		internal static IRTUService _RTUService = null;

		/// <summary>
		/// Gets the RTU service
		/// </summary>
		public static IRTUService RTUService
		{
			get
			{
				if (Global._RTUService == null)
					Task.WaitAll(new[] { Global.InitializeRTUServiceAsync() }, TimeSpan.FromSeconds(13));
				return Global._RTUService;
			}
		}

		/// <summary>
		/// Initializes the real-time updater (RTU) service
		/// </summary>
		/// <returns></returns>
		public static async Task InitializeRTUServiceAsync()
		{
			if (Global._RTUService == null)
			{
				await Global.OpenOutgoingChannelAsync().ConfigureAwait(false);
				Global._RTUService = Global.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IRTUService>(ProxyInterceptor.Create());
			}
		}
	}
}