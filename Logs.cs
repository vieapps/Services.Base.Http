#region Related components
using System;
using System.Collections.Generic;
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
		/// Writes the service log into centerlized storage
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="developerID">The identity of the developer</param>
		/// <param name="appID">The identity of the app</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="additional">The additional information</param>
		/// <returns></returns>
		public static bool WriteServiceLog(this HttpContext context, ILogger logger, string developerID, string appID, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
		{
			if (exception != null && exception.GetHttpStatusCode() == 404 && !string.IsNullOrWhiteSpace(context.GetReferUrl()))
				additional = $"{additional ?? ""}{(string.IsNullOrWhiteSpace(additional) ? "" : "\r\n")}> Referer: {context.GetReferUrl()}";
			return Extensions.WriteServiceLog(logger ?? Global.Logger, Global.NodeID, correlationID ?? context?.GetCorrelationID() ?? UtilityService.NewUUID, developerID, appID, logs, exception, serviceName ?? Global.ServiceName, objectName, additional, mode);
		}

		/// <summary>
		/// Writes the service log into centerlized storage
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
		public static Task<bool> WriteLogsAsync(this HttpContext context, string developerID, string appID, ILogger logger, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null, string additional = null)
			=> Task.FromResult(context.WriteServiceLog(logger, developerID, appID, objectName, logs, exception, serviceName, mode, correlationID, additional));

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
			=> context.WriteServiceLog(logger, null, null, objectName, logs, exception, serviceName, mode, correlationID, additional);

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
			=> context.WriteLogs(Global.Logger, objectName, logs, exception, serviceName, mode, correlationID, additional);

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
			=> context.WriteLogs(logger, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string> { log } : null, exception, serviceName, mode, correlationID, additional);

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
			=> context.WriteLogs(Global.Logger, objectName, log, exception, serviceName, mode, correlationID, additional);

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
		{
			try
			{
				return Global.WriteLogsAsync(Global.CurrentHttpContext, logger, objectName, logs, exception, serviceName, mode, correlationID, additional);
			}
			catch
			{
				return Task.CompletedTask;
			}
		}

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
			=> Global.WriteLogs(logger, objectName, logs, exception, serviceName, mode, correlationID, additional);

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
		/// <param name="writeHeaders">true to write all headers</param>
		/// <returns></returns>
		public static Task WriteVisitStartingLogAsync(this HttpContext context, ILogger logger = null, string objectName = null, bool writeHeaders = false)
		{
			var userAgent = context.GetUserAgent();
			var refererURL = context.GetReferUrl();
			var requestURI = context.GetRequestUri();
			var protocol = context.Request.Protocol;
			var ipAddress = context.GetRemoteIPAddress();
			var visitlog = $"Request starting {context.Request.Method} {requestURI} {protocol}\r\n- IP: {ipAddress}{(string.IsNullOrWhiteSpace(userAgent) ? "" : $"\r\n- Agent: {userAgent}")}{(string.IsNullOrWhiteSpace(refererURL) ? "" : $"\r\n- Refer: {refererURL}")}";
			if (writeHeaders || Global.IsDebugLogEnabled || context.Request.Query.ContainsKey("x-logs"))
				visitlog += $"\r\n- Headers:\r\n\t{context.Request.Headers.ToString("\r\n\t", kvp => $"{kvp.Key}: {kvp.Value}")}";
			return context.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.Visits", visitlog);
		}

		/// <summary>
		/// Writes the starting of a visiting log
		/// </summary>
		/// <param name="writeHeaders">true to write all headers</param>
		/// <returns></returns>
		public static Task WriteVisitStartingLogAsync(this HttpContext context, bool writeHeaders)
			=> context.WriteVisitStartingLogAsync(null, null, writeHeaders);

		/// <summary>
		/// Writes the ending of a visiting log
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <returns></returns>
		public static Task WriteVisitFinishingLogAsync(this HttpContext context, ILogger logger = null, string objectName = null)
			=> context.WriteLogsAsync(logger ?? Global.Logger, objectName ?? "Http.Visits", $"Request finished in {context.GetExecutionTimes()}");

		/// <summary>
		/// Starts new trace
		/// </summary>
		/// <param name="parentID"></param>
		/// <param name="operation"></param>
		/// <param name="kind"></param>
		/// <param name="attributes"></param>
		/// <returns></returns>
		public static TraceInfo StartTrace(this HttpContext context, string parentID, string operation, string kind = "internal", Dictionary<string, object> attributes = null)
			=> Extensions.StartTrace(parentID, context.GetCorrelationID(), Global.NodeID, Global.ServiceName, operation, kind, attributes);

		/// <summary>
		/// Starts new trace
		/// </summary>
		/// <param name="operation"></param>
		/// <returns></returns>
		public static TraceInfo StartTrace(this HttpContext context, string operation)
			=> context.StartTrace(null, operation, "upstream", null);

		/// <summary>
		/// Starts new resource usage tracking
		/// </summary>
		/// <param name="context"></param>
		/// <param name="serviceName"></param>
		/// <param name="objectName"></param>
		/// <param name="operation"></param>
		/// <param name="type"></param>
		/// <param name="provider"></param>
		/// <param name="model"></param>
		/// <param name="systemID"></param>
		/// <param name="traceID"></param>
		/// <returns></returns>
		public static UsageInfo StartUsage(this HttpContext context, string serviceName, string objectName, string operation, string type, string provider, string model, string systemID, string traceID)
		{
			var session = context.GetSession();
			return Extensions.StartUsage(session?.DeveloperID, session?.AppID, session?.User?.ID, Global.NodeID, context.GetCorrelationID(), serviceName, objectName, operation, type, provider, model, systemID, traceID);
		}

		/// <summary>
		/// Starts new resource usage tracking
		/// </summary>
		/// <param name="context"></param>
		/// <param name="objectName"></param>
		/// <param name="operation"></param>
		/// <param name="type"></param>
		/// <param name="provider"></param>
		/// <param name="model"></param>
		/// <param name="traceID"></param>
		/// <returns></returns>
		public static UsageInfo StartUsage(this HttpContext context, string objectName, string operation, string type, string provider = null, string model = null, string traceID = null)
			=> context.StartUsage(Global.ServiceName, objectName, operation, type, provider, model, context.GetParameter("x-system-id"), traceID);
	}
}