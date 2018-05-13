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

using Microsoft.AspNetCore.Http;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using WampSharp.Core.Listener;
using WampSharp.V2;
using WampSharp.V2.Client;
using WampSharp.V2.Realm;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services
{
	public static partial class Global
	{
		/// <summary>
		/// Opens the WAMP channels with default settings
		/// </summary>
		/// <param name="onIncommingConnectionEstablished"></param>
		/// <param name="onOutgoingConnectionEstablished"></param>
		/// <returns></returns>
		public static async Task OpenChannelsAsync(Action<object, WampSessionCreatedEventArgs> onIncommingConnectionEstablished = null, Action<object, WampSessionCreatedEventArgs> onOutgoingConnectionEstablished = null)
		{
			await Task.WhenAll(
				WAMPConnections.OpenIncomingChannelAsync(
					onIncommingConnectionEstablished,
					(sender, args) =>
					{
						if (!WAMPConnections.ChannelsAreClosedBySystem && !args.CloseType.Equals(SessionCloseType.Disconnection) && WAMPConnections.IncommingChannel != null)
							WAMPConnections.IncommingChannel.ReOpen(wampChannel => Global.WriteLogs("Re-connect the incoming connection successful"), ex => Global.WriteLogs("Error occurred while re-connecting the incoming connection", ex));
					},
					(sender, args) => Global.WriteLogs($"Got an error of incoming connection: {(args.Exception != null ? args.Exception.Message : "None")}", args.Exception)
				),
				WAMPConnections.OpenOutgoingChannelAsync(
					onOutgoingConnectionEstablished,
					(sender, args) =>
					{
						if (!WAMPConnections.ChannelsAreClosedBySystem && !args.CloseType.Equals(SessionCloseType.Disconnection) && WAMPConnections.OutgoingChannel != null)
							WAMPConnections.OutgoingChannel.ReOpen(wampChannel => Global.WriteLogs("Re-connect the outgoging connection successful"), ex => Global.WriteLogs("Error occurred while re-connecting the outgoging connection", ex));
					},
					(sender, args) => Global.WriteLogs($"Got an error of outgoing connection: {(args.Exception != null ? args.Exception.Message : "None")}", args.Exception)
				)
			).ConfigureAwait(false);
		}

		/// <summary>
		/// Calls a business service
		/// </summary>
		/// <param name="context"></param>
		/// <param name="requestInfo">The requesting information</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <param name="onStart">The action to run when start</param>
		/// <param name="onSuccess">The action to run when success</param>
		/// <param name="onError">The action to run when got an error</param>
		/// <returns></returns>
		public static async Task<JObject> CallServiceAsync(this HttpContext context, RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken), Action<RequestInfo> onStart = null, Action<RequestInfo, JObject> onSuccess = null, Action<RequestInfo, Exception> onError = null)
		{
			// get the instance of service
			IService service = null;
			try
			{
				service = await WAMPConnections.GetServiceAsync(requestInfo.ServiceName).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				onError?.Invoke(requestInfo, ex);
				throw ex;
			}

			// call the service
			onStart?.Invoke(requestInfo);

			var stopwatch = Stopwatch.StartNew();
			var name = $"net.vieapps.services.{requestInfo.ServiceName}".ToLower();
			if (Global.IsDebugLogEnabled)
				await context.WriteLogsAsync($"Call the service [{name}]\r\n{requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}");

			try
			{
				var json = await service.ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false);

				onSuccess?.Invoke(requestInfo, json);
				if (Global.IsDebugLogEnabled)
					await context.WriteLogsAsync($"Results from the service [{name}]{(Global.IsDebugResultsEnabled ? "\r\n" + json?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None) : ": (Hidden)")}");

				// TO DO: track counter of success

				return json;
			}
			catch (WampSessionNotEstablishedException ex)
			{
				await Task.Delay(567, cancellationToken).ConfigureAwait(false);
				if (Global.IsDebugLogEnabled)
					await context.WriteLogsAsync($"Re-call the service [{name}]\r\n{requestInfo.ToJson().ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}", ex).ConfigureAwait(false);

				try
				{
					var json = await service.ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false);

					onSuccess?.Invoke(requestInfo, json);
					if (Global.IsDebugLogEnabled)
						await context.WriteLogsAsync($"Results from the service [{name}]{(Global.IsDebugResultsEnabled ? "\r\n" + json?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None) : ": (Hidden)")}");

					// TO DO: track counter of success

					return json;
				}
				catch (Exception inner)
				{
					onError?.Invoke(requestInfo, inner);
					await context.WriteLogsAsync($"Error occurred while re-calling the service [{name}]", inner).ConfigureAwait(false);

					// TO DO: track counter of error

					throw inner;
				}
			}
			catch (Exception ex)
			{
				onError?.Invoke(requestInfo, ex);
				await context.WriteLogsAsync($"Error occurred while calling the service [{name}]", ex).ConfigureAwait(false);

				// TO DO: track counter of error

				throw ex;
			}
			finally
			{
				stopwatch.Stop();
				if (Global.IsDebugLogEnabled)
					await context.WriteLogsAsync($"Execution times of the service [{name}]: {stopwatch.GetElapsedTimes()}").ConfigureAwait(false);

				// TO DO: track counter of average times
			}
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
		public static Task<JObject> CallServiceAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken), Action<RequestInfo> onStart = null, Action<RequestInfo, JObject> onSuccess = null, Action<RequestInfo, Exception> onError = null)
			=> Global.CurrentHttpContext.CallServiceAsync(requestInfo, cancellationToken, onStart, onSuccess, onError);

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
			=> context.CallServiceAsync(new RequestInfo(context.GetSession(UtilityService.NewUUID, context.User?.Identity as UserIdentity), serviceName, objectName, verb, query, null, null, extra, context.GetCorrelationID()), Global.CancellationTokenSource.Token, onStart, onSuccess, onError);

		/// <summary>
		/// Calls a business service
		/// </summary>
		/// <param name="serviceName"></param>
		/// <param name="objectName"></param>
		/// <param name="verb"></param>
		/// <param name="query"></param>
		/// <param name="extra"></param>
		/// <param name="onStart"></param>
		/// <param name="onSuccess"></param>
		/// <param name="onError"></param>
		/// <returns></returns>
		public static Task<JObject> CallServiceAsync(string serviceName, string objectName, string verb, Dictionary<string, string> query, Dictionary<string, string> extra = null, Action<RequestInfo> onStart = null, Action<RequestInfo, JObject> onSuccess = null, Action<RequestInfo, Exception> onError = null)
			=> Global.CurrentHttpContext.CallServiceAsync(serviceName, objectName, verb, query, extra, onStart, onSuccess, onError);

		internal static ILoggingService _LoggingService = null;

		/// <summary>
		/// Gets the logging service
		/// </summary>
		public static ILoggingService LoggingService
		{
			get
			{
				if (Global._LoggingService == null)
					Task.WaitAll(new[] { Global.InitializeLoggingServiceAsync() }, TimeSpan.FromSeconds(3));
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
				await WAMPConnections.OpenOutgoingChannelAsync().ConfigureAwait(false);
				Global._LoggingService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create());
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
					Task.WaitAll(new[] { Global.InitializeRTUServiceAsync() }, TimeSpan.FromSeconds(3));
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
				await WAMPConnections.OpenOutgoingChannelAsync().ConfigureAwait(false);
				Global._RTUService = WAMPConnections.OutgoingChannel.RealmProxy.Services.GetCalleeProxy<IRTUService>(ProxyInterceptor.Create());
			}
		}
	}
}