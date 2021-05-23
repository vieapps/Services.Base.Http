#region Related components
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using WampSharp.V2.Core.Contracts;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services
{
	public static partial class Global
	{
		static ConcurrentQueue<Tuple<Tuple<DateTime, string, string, string, string, string>, List<string>, string>> Logs { get; }  = new ConcurrentQueue<Tuple<Tuple<DateTime, string, string, string, string, string>, List<string>, string>>();

		/// <summary>
		/// Gets or sets the logger
		/// </summary>
		public static ILogger Logger { get; set; }

		/// <summary>
		/// Gets the state to write debug log (from app settings - parameter named 'vieapps:Logs:Debug')
		/// </summary>
		public static bool IsDebugLogEnabled => Global.Logger != null && Global.Logger.IsEnabled(LogLevel.Debug);

		/// <summary>
		/// Gets the state to write debug result into log (from app settings - parameter named 'vieapps:Logs:ShowResults')
		/// </summary>
		public static bool IsDebugResultsEnabled => Global.IsDebugLogEnabled || "true".IsEquals(UtilityService.GetAppSetting("Logs:ShowResults"));

		/// <summary>
		/// Gets the state to write error stack to client (from app settings - parameter named 'vieapps:Logs:ShowStacks')
		/// </summary>
		public static bool IsDebugStacksEnabled => Global.IsDebugLogEnabled || "true".IsEquals(UtilityService.GetAppSetting("Logs:ShowStacks"));

		/// <summary>
		/// Gets the state to write visit logs (from app settings - parameter named 'vieapps:Logs:Visits')
		/// </summary>
		public static bool IsVisitLogEnabled => Global.IsDebugLogEnabled || "true".IsEquals(UtilityService.GetAppSetting("Logs:Visits", "true"));

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="context"></param>
		/// <param name="developerID">The identity of the developer</param>
		/// <param name="appID">The identity of the app</param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(this HttpContext context, string developerID, string appID, ILogger logger, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
		{
			// prepare
			correlationID = correlationID ?? context?.GetCorrelationID() ?? UtilityService.NewUUID;
			var wampException = exception != null && exception is WampException
				? (exception as WampException).GetDetails()
				: null;

			// write to local logs
			logs?.ForEach(message => logger?.Log(exception == null ? mode : LogLevel.Error, $"{message} [{correlationID}]"));
			if (exception != null)
			{
				if (wampException != null)
					logger?.Log(LogLevel.Error, $"{wampException.Item3}: {wampException.Item2}\r\n{wampException.Item4} [{correlationID}]", exception);
				else
					logger?.Log(LogLevel.Error, $"{exception.Message} [{correlationID}]", exception);
			}
			if (!string.IsNullOrWhiteSpace(additional))
				logger?.Log(LogLevel.Error, $"{additional} [{correlationID}]");

			// prepare to write to centerlized logs
			logs = logs ?? new List<string>();
			if (wampException != null)
			{
				logs.Add($"> Message: {wampException.Item2}");
				logs.Add($"> Type: {wampException.Item3}");
			}
			else if (exception != null)
			{
				logs.Add($"> Message: {exception.Message}");
				logs.Add($"> Type: {exception.GetTypeName(true)}");
			}

			if (!string.IsNullOrWhiteSpace(additional))
				logs.Add(additional);

			// special: HTTP 404
			if (exception != null && exception.GetHttpStatusCode() == 404 && !string.IsNullOrWhiteSpace(context.GetReferUrl()))
			{
				logger?.Log(LogLevel.Information, $"Referer: {context.GetReferUrl()}");
				logs.Add($"> Referer: {context.GetReferUrl()}");
			}

			var stack = wampException != null
				? $"{wampException.Item3}: {wampException.Item2}\r\n{wampException.Item4}"
				: exception?.GetStack();

			// update queue & write to centerlized logs
			Global.Logs.Enqueue(new Tuple<Tuple<DateTime, string, string, string, string, string>, List<string>, string>(new Tuple<DateTime, string, string, string, string, string>(DateTime.Now, correlationID, developerID, appID, serviceName ?? Global.ServiceName ?? "APIGateway", objectName ?? "Http"), logs, stack));
			return Global.Logs.WriteLogsAsync(Global.CancellationToken, Global.Logger);
		}

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(this HttpContext context, ILogger logger, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
		{
			var session = context?.GetSession();
			return context.WriteLogsAsync(session?.DeveloperID, session?.AppID, logger, objectName, logs, exception, serviceName, mode, correlationID, additional);
		}

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="context"></param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(this HttpContext context, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogsAsync(context, Global.Logger, objectName, logs, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(this HttpContext context, ILogger logger, string objectName, string log, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogsAsync(context, logger, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string> { log } : null, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(this HttpContext context, string objectName, string log, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogsAsync(context, Global.Logger, objectName, log, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		public static void WriteLogs(this HttpContext context, ILogger logger, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogsAsync(context, logger, objectName, logs, exception, serviceName, mode, correlationID, additional).Run(ex => Global.Logger.LogError($"Error occurred while writting logs => {ex.Message}", ex));

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="context"></param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		public static void WriteLogs(this HttpContext context, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogs(context, Global.Logger, objectName, logs, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		public static void WriteLogs(this HttpContext context, ILogger logger, string objectName, string log, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogs(context, logger, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string> { log } : null, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		public static void WriteLogs(this HttpContext context, string objectName, string log, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogs(context, Global.Logger, objectName, log, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(ILogger logger, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogsAsync(Global.CurrentHttpContext, logger, objectName, logs, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogsAsync(Global.Logger, objectName, logs, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(ILogger logger, string objectName, string log, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogsAsync(logger, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string> { log } : null, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string objectName, string log, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogsAsync(Global.Logger, objectName, log, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		public static void WriteLogs(ILogger logger, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogsAsync(logger, objectName, logs, exception, serviceName, mode, correlationID, additional).Run(ex => Global.Logger.LogError($"Error occurred while writting logs => {ex.Message}", ex));

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		public static void WriteLogs(string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogs(Global.Logger, objectName, logs, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		public static void WriteLogs(ILogger logger, string objectName, string log, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogs(logger, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string> { log } : null, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		public static void WriteLogs(string objectName, string log, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Global.WriteLogs(Global.Logger, objectName, log, exception, serviceName, mode, correlationID, additional);

		/// <summary>
		/// Writes the starting of a visiting log
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <returns></returns>
		public static Task WriteVisitStartingLogAsync(this HttpContext context, ILogger logger = null, string objectName = null)
		{
			var userAgent = context.GetUserAgent();
			var refererURL = context.GetReferUrl();
			var requestURI = context.GetRequestUri();
			var protocol = context.Request.Protocol;
			var ipAddress = context.Connection.RemoteIpAddress;
			var visitlog = $"Request starting {context.Request.Method} {requestURI} {protocol}\r\n- IP: {ipAddress}{(string.IsNullOrWhiteSpace(userAgent) ? "" : $"\r\n- Agent: {userAgent}")}{(string.IsNullOrWhiteSpace(refererURL) ? "" : $"\r\n- Refer: {refererURL}")}";
			if (Global.IsDebugLogEnabled)
				visitlog += $"\r\n- Headers:\r\n\t{context.Request.Headers.ToString("\r\n\t", kvp => $"{kvp.Key}: {kvp.Value}")}";
			return context.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.Visits", visitlog);
		}

		/// <summary>
		/// Writes the ending of a visiting log
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <returns></returns>
		public static Task WriteVisitFinishingLogAsync(this HttpContext context, ILogger logger = null, string objectName = null)
			=> context.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.Visits", $"Request finished in {context.GetExecutionTimes()}");
	}
}