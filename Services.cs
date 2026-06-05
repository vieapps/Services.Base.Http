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
using WampSharp.V2.Client;
using WampSharp.V2.Core.Contracts;
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
			var isDebugLogEnabled = Global.IsDebugResultsEnabled || requestInfo.GetParameter("x-logs") != null || (context?.Request?.Query != null && context.Request.Query.ContainsKey("x-logs"));
			try
			{
				if (isDebugLogEnabled)
					context.WriteLogsAsync(developerID, appID, logger ?? Global.Logger, objectName ?? $"Http.{requestInfo.ServiceName}", new List<string> { $"Start call service {requestInfo.Verb} {requestInfo.GetURI()} - {requestInfo.Session.AppName} ({requestInfo.Session.AppMode.ToLower()} app) - {requestInfo.Session.AppPlatform} @ {requestInfo.Session.IP}" }, null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID).Execute();

				onStart?.Invoke(requestInfo);
				callingWatch = Stopwatch.StartNew();
				var json = await Router.GetService(requestInfo.ServiceName).ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false);
				callingWatch.Stop();
				onSuccess?.Invoke(requestInfo, json);

				if (isDebugLogEnabled || callingWatch.Elapsed.TotalMilliseconds > 1200)
					context.WriteLogsAsync(developerID, appID, logger ?? Global.Logger, objectName ?? $"Http.{requestInfo.ServiceName}", new List<string> {
						"Call service successful" +
						(isDebugLogEnabled ? $"\r\n\r\n- Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" : "") +
						(isDebugLogEnabled ? $"\r\n\r\n- Response: {json?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" : "")
					}, null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID).Execute();

				return json;
			}
			catch (WampSessionNotEstablishedException)
			{
				await Task.Delay(UtilityService.GetRandomNumber(567, 789), cancellationToken).ConfigureAwait(false);
				await Task.WhenAll
				(
					Router.IncomingChannelSessionID > 0 ? Task.CompletedTask : Router.IncomingChannel.OpenAsync(cancellationToken),
					Router.OutgoingChannelSessionID > 0 ? Task.CompletedTask : Router.OutgoingChannel.OpenAsync(cancellationToken)
				).ConfigureAwait(false);
				await Task.Delay(UtilityService.GetRandomNumber(567, 789), cancellationToken).ConfigureAwait(false);

				try
				{
					context.WriteLogsAsync(developerID, appID, logger ?? Global.Logger, objectName ?? $"Http.{requestInfo.ServiceName}", new List<string> {
						$"Re-try when got error [WampSessionNotEstablishedException]" +
						$"\r\n- Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
					}, null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID).Execute();

					var json = await Router.GetService(requestInfo.ServiceName).ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false);
					callingWatch.Stop();
					onSuccess?.Invoke(requestInfo, json);

					if (isDebugLogEnabled || callingWatch.Elapsed.TotalMilliseconds > 1200)
						context.WriteLogsAsync(developerID, appID, logger ?? Global.Logger, objectName ?? $"Http.{requestInfo.ServiceName}", new List<string> { 
							"Re-call service successful" +
							(isDebugLogEnabled ? $"\r\n\r\n- Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" : "") +
							(isDebugLogEnabled ? $"\r\n\r\n- Response: {json?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" : "")
						}, null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID).Execute();

					return json;
				}
				catch (Exception ex)
				{
					callingWatch.Stop();
					exception = ex;
					onError?.Invoke(requestInfo, ex);
					throw;
				}
			}
			catch (WampException wampException)
			{
				if ("ServiceUnavailableException".IsEquals(wampException.GetDetails(requestInfo).Type))
					try
					{
						context.WriteLogsAsync(developerID, appID, logger ?? Global.Logger, objectName ?? $"Http.{requestInfo.ServiceName}", new List<string> {
							$"Re-try when got error [ServiceUnavailableException]" +
							$"\r\n- Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}"
						}, null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID).Execute();

						var json = await Router.GetService(requestInfo.ServiceName).ProcessRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false);
						callingWatch.Stop();
						onSuccess?.Invoke(requestInfo, json);

						if (isDebugLogEnabled || callingWatch.Elapsed.TotalMilliseconds > 1200)
							context.WriteLogsAsync(developerID, appID, logger ?? Global.Logger, objectName ?? $"Http.{requestInfo.ServiceName}", new List<string> {
							"Re-call service successful" +
							(isDebugLogEnabled ? $"\r\n\r\n- Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" : "") +
							(isDebugLogEnabled ? $"\r\n\r\n- Response: {json?.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}" : "")
						}, null, Global.ServiceName, LogLevel.Information, requestInfo.CorrelationID).Execute();

						return json;
					}
					catch (Exception ex)
					{
						callingWatch.Stop();
						exception = ex;
						onError?.Invoke(requestInfo, ex);
						throw;
					}
				else
				{
					callingWatch.Stop();
					exception = wampException;
					onError?.Invoke(requestInfo, wampException);
					throw;
				}
			}
			catch (Exception ex)
			{
				callingWatch.Stop();
				exception = ex;
				onError?.Invoke(requestInfo, ex);
				throw;
			}
			finally
			{
				overallWatch.Stop();
				if (isDebugLogEnabled || overallWatch.Elapsed.TotalSeconds > 2)
					context.WriteLogsAsync(developerID, appID, logger ?? Global.Logger, objectName ?? $"Http.{requestInfo.ServiceName}", new List<string> { $"Call service finished in {callingWatch.GetElapsedTimes()} - Overall: {overallWatch.GetElapsedTimes()}" }, exception, Global.ServiceName, exception == null ? LogLevel.Information : LogLevel.Error, requestInfo.CorrelationID, exception == null ? null : $"Request: {requestInfo.ToString(Global.IsDebugLogEnabled ? Formatting.Indented : Formatting.None)}").Execute();
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
			=> Global.CallServiceAsync(Global.CurrentHttpContext, requestInfo, cancellationToken, logger, objectName, onStart, onSuccess, onError);

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
			=> Global.CallServiceAsync(Global.CurrentHttpContext, serviceName, objectName, verb, query, extra, logger, cancellationToken, onStart, onSuccess, onError);
	}
}