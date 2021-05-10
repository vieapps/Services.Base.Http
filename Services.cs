#region Related components
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
#endregion

namespace net.vieapps.Services
{
	public static partial class Global
	{
		/// <summary>
		/// Calls a service
		/// </summary>
		/// <param name="context"></param>
		/// <param name="requestInfo">The requesting information</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object to write into log</param>
		/// <param name="onStart">The action to run when start</param>
		/// <param name="onSuccess">The action to run when success</param>
		/// <param name="onError">The action to run when got an error</param>
		/// <returns>A <see cref="JToken">JSON</see> object that presents the results of the business service</returns>
		public static async Task<JToken> CallServiceAsync(this HttpContext context, RequestInfo requestInfo, CancellationToken cancellationToken = default, ILogger logger = null, string objectName = null, Action<RequestInfo> onStart = null, Action<RequestInfo, JToken> onSuccess = null, Action<RequestInfo, Exception> onError = null)
		{
			Exception exception = null;
			var overallWatch = Stopwatch.StartNew();
			var callingWatch = Stopwatch.StartNew();
			var developerID = requestInfo.Session?.DeveloperID ?? context.GetSession(requestInfo.Session?.SessionID, requestInfo.Session?.User)?.DeveloperID;
			var appID = requestInfo.Session?.AppID ?? context.GetSession(requestInfo.Session?.SessionID, requestInfo.Session?.User)?.AppID;
			try
			{
				if (Global.IsDebugResultsEnabled)
					await context.WriteLogsAsync(developerID, appID, logger ?? Global.Logger, objectName ?? $"Http.{requestInfo.ServiceName}", new List<string> { $"Start call service {requestInfo.Verb} {requestInfo.GetURI()} - {requestInfo.Session.AppName} ({requestInfo.Session.AppMode.ToLower()} app) - {requestInfo.Session.AppPlatform} @ {requestInfo.Session.IP}" }, null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID);

				onStart?.Invoke(requestInfo);
				callingWatch = Stopwatch.StartNew();
				var service = Router.GetService(requestInfo.ServiceName);
				var json = service != null ? await service.ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false) : null;
				callingWatch.Stop();
				onSuccess?.Invoke(requestInfo, json);

				// TO DO: track counter of success
				// ...

				if (Global.IsDebugResultsEnabled)
					await context.WriteLogsAsync(developerID, appID, logger ?? Global.Logger, objectName ?? $"Http.{requestInfo.ServiceName}", new List<string> { "Call service successful" + "\r\n" +
						$"- Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
						$"- Response: {json?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" }
					, null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID).ConfigureAwait(false);

				return json;
			}
			catch (WampSharp.V2.Client.WampSessionNotEstablishedException)
			{
				await Task.Delay(567, cancellationToken).ConfigureAwait(false);
				try
				{
					var service = Router.GetService(requestInfo.ServiceName);
					var json = service != null ? await service.ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false) : null;
					callingWatch.Stop();
					onSuccess?.Invoke(requestInfo, json);

					// TO DO: track counter of success
					// ...

					if (Global.IsDebugResultsEnabled)
						await context.WriteLogsAsync(developerID, appID, logger ?? Global.Logger, objectName ?? $"Http.{requestInfo.ServiceName}", new List<string> { "Re-call service successful" + "\r\n" +
							$"- Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" + "\r\n" +
							$"- Response: {json?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" }
						, null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID).ConfigureAwait(false);

					return json;
				}
				catch (Exception)
				{
					throw;
				}
			}
			catch (Exception ex)
			{
				callingWatch.Stop();
				exception = ex;

				// TO DO: track counter of error
				// ...

				onError?.Invoke(requestInfo, ex);

				throw;
			}
			finally
			{
				overallWatch.Stop();

				// TO DO: track counter of average times
				// ...

				if (Global.IsDebugResultsEnabled)
					await context.WriteLogsAsync(developerID, appID, logger ?? Global.Logger, objectName ?? $"Http.{requestInfo.ServiceName}", new List<string> { $"Call service finished in {callingWatch.GetElapsedTimes()} - Overall: {overallWatch.GetElapsedTimes()}" }, exception, Global.ServiceName, exception == null ? LogLevel.Information : LogLevel.Error, requestInfo.CorrelationID, exception == null ? null : $"Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").ConfigureAwait(false);
			}
		}

		/// <summary>
		/// Calls a service
		/// </summary>
		/// <param name="requestInfo">The requesting information</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object to write into log</param>
		/// <param name="onStart">The action to run when start</param>
		/// <param name="onSuccess">The action to run when success</param>
		/// <param name="onError">The action to run when got an error</param>
		/// <returns></returns>
		public static Task<JToken> CallServiceAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default, ILogger logger = null, string objectName = null, Action<RequestInfo> onStart = null, Action<RequestInfo, JToken> onSuccess = null, Action<RequestInfo, Exception> onError = null)
			=> Global.CurrentHttpContext.CallServiceAsync(requestInfo, cancellationToken, logger, objectName, onStart, onSuccess, onError);

		/// <summary>
		/// Calls a service
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName"></param>
		/// <param name="objectName"></param>
		/// <param name="verb"></param>
		/// <param name="query"></param>
		/// <param name="extra"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <param name="onStart"></param>
		/// <param name="onSuccess"></param>
		/// <param name="onError"></param>
		/// <returns></returns>
		public static Task<JToken> CallServiceAsync(this HttpContext context, string serviceName, string objectName, string verb, Dictionary<string, string> query, Dictionary<string, string> extra = null, ILogger logger = null, CancellationToken cancellationToken = default, Action<RequestInfo> onStart = null, Action<RequestInfo, JToken> onSuccess = null, Action<RequestInfo, Exception> onError = null)
			=> context.CallServiceAsync(new RequestInfo(context.GetSession(UtilityService.NewUUID, context.User?.Identity as UserIdentity), serviceName, objectName, verb, query, null, null, extra, context.GetCorrelationID()), cancellationToken, logger, null, onStart, onSuccess, onError);

		/// <summary>
		/// Calls a service
		/// </summary>
		/// <param name="serviceName"></param>
		/// <param name="objectName"></param>
		/// <param name="verb"></param>
		/// <param name="query"></param>
		/// <param name="extra"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <param name="onStart"></param>
		/// <param name="onSuccess"></param>
		/// <param name="onError"></param>
		/// <returns></returns>
		public static Task<JToken> CallServiceAsync(string serviceName, string objectName, string verb, Dictionary<string, string> query, Dictionary<string, string> extra = null, ILogger logger = null, CancellationToken cancellationToken = default, Action<RequestInfo> onStart = null, Action<RequestInfo, JToken> onSuccess = null, Action<RequestInfo, Exception> onError = null)
			=> Global.CurrentHttpContext.CallServiceAsync(serviceName, objectName, verb, query, extra, logger, cancellationToken, onStart, onSuccess, onError);

		static ILoggingService _LoggingService = null;

		/// <summary>
		/// Gets the logging service
		/// </summary>
		public static ILoggingService LoggingService
		{
			get
			{
				if (Global._LoggingService == null)
					Global.InitializeLoggingServiceAsync().Wait(1234, Global.CancellationToken);
				return Global._LoggingService;
			}
		}

		/// <summary>
		/// Initializes the logging service
		/// </summary>
		/// <returns></returns>
		public static async Task<ILoggingService> InitializeLoggingServiceAsync()
		{
			if (Global._LoggingService == null)
			{
				await Router.OpenOutgoingChannelAsync().ConfigureAwait(false);
				Global._LoggingService = Router.OutgoingChannel?.RealmProxy.Services.GetCalleeProxy<ILoggingService>(ProxyInterceptor.Create());
			}
			return Global._LoggingService;
		}
	}
}