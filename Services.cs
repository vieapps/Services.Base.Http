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
using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Client;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Base.AspNet
{
	public static partial class Global
	{
		static ConcurrentDictionary<string, IService> Services = new ConcurrentDictionary<string, IService>(StringComparer.OrdinalIgnoreCase);

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
						Global.Services.TryAdd(name, service);
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

			var stopwatch = new Stopwatch();
			stopwatch.Start();
			var correlationID = requestInfo.CorrelationID ?? UtilityService.NewUID;
			var name = $"net.vieapps.services.{requestInfo.ServiceName}".ToLower();
			await Global.WriteDebugLogsAsync(correlationID, Global.ServiceName ?? "APIGateway", $"Call the service [{name}]\r\n{requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}");

			try
			{
				var json = await service.ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false);

				onSuccess?.Invoke(requestInfo, json);
				await Global.WriteDebugLogsAsync(correlationID, Global.ServiceName ?? "APIGateway", $"Results from the service [{name}]{(Global.IsDebugResultsEnabled ? "\r\n" + json?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None) : ": (Hidden)")}");

				// TO DO: track counter of success

				return json;
			}
			catch (WampSessionNotEstablishedException ex)
			{
				await Task.Delay(567, cancellationToken).ConfigureAwait(false);
				await Global.WriteDebugLogsAsync(correlationID, Global.ServiceName ?? "APIGateway", $"Re-call the service [{name}]\r\n{requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex).ConfigureAwait(false);

				try
				{
					var json = await service.ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false);

					onSuccess?.Invoke(requestInfo, json);
					await Global.WriteDebugLogsAsync(correlationID, Global.ServiceName ?? "APIGateway", $"Results from the service [{name}]{(Global.IsDebugResultsEnabled ? "\r\n" + json?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None) : ": (Hidden)")}");

					// TO DO: track counter of success

					return json;
				}
				catch (Exception inner)
				{
					onError?.Invoke(requestInfo, inner);
					await Global.WriteDebugLogsAsync(correlationID, Global.ServiceName ?? "APIGateway", $"Error occurred while re-calling the service [{name}]", inner).ConfigureAwait(false);

					// TO DO: track counter of error

					throw inner;
				}
			}
			catch (Exception ex)
			{
				onError?.Invoke(requestInfo, ex);
				await Global.WriteDebugLogsAsync(correlationID, Global.ServiceName ?? "APIGateway", $"Error occurred while calling the service [{name}]", ex).ConfigureAwait(false);

				// TO DO: track counter of error

				throw ex;
			}
			finally
			{
				stopwatch.Stop();
				await Global.WriteDebugLogsAsync(correlationID, Global.ServiceName ?? "APIGateway", $"Execution times of the service [{name}]: {stopwatch.GetElapsedTimes()}").ConfigureAwait(false);

				// TO DO: track counter of average times
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
			return Global.CallServiceAsync(new RequestInfo(context.GetSession(UtilityService.NewUID, context.User?.Identity as User), serviceName, objectName, verb, query, null, null, extra, UtilityService.NewUID), Global.CancellationTokenSource.Token, onStart, onSuccess, onError);
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