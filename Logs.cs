﻿#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services
{
	public static partial class Global
	{
		static ConcurrentQueue<Tuple<string, string, string, List<string>, string>> Logs { get; }  = new ConcurrentQueue<Tuple<string, string, string, List<string>, string>>();

		/// <summary>
		/// Gets or sets the logger
		/// </summary>
		public static ILogger Logger { get; set; }

		/// <summary>
		/// Gets the state to write debug log (from app settings - parameter named 'vieapps:Logs:Debug')
		/// </summary>
		public static bool IsDebugLogEnabled => Global.Logger.IsEnabled(LogLevel.Debug);

		static string _IsDebugResultsEnabled = null, _IsDebugStacksEnabled = null;

		/// <summary>
		/// Gets the state to write debug result into log (from app settings - parameter named 'vieapps:Logs:ShowResults')
		/// </summary>
		public static bool IsDebugResultsEnabled => "true".IsEquals(Global._IsDebugResultsEnabled ?? (Global._IsDebugResultsEnabled = UtilityService.GetAppSetting("Logs:ShowResults", "false")));

		/// <summary>
		/// Gets the state to write error stack to client (from app settings - parameter named 'vieapps:Logs:ShowStacks')
		/// </summary>
		public static bool IsDebugStacksEnabled => "true".IsEquals(Global._IsDebugStacksEnabled ?? (Global._IsDebugStacksEnabled = UtilityService.GetAppSetting("Logs:ShowStacks", "false")));

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
		/// <returns></returns>
		public static async Task WriteLogsAsync(this HttpContext context, ILogger logger, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null)
		{
			// prepare
			correlationID = (correlationID ?? context?.GetCorrelationID()) ?? UtilityService.NewUUID;

			// write to local logs
			if (exception == null)
				logs?.ForEach(message => logger.Log(mode, $"{message} [{correlationID}]"));
			else
			{
				logs?.ForEach(message => logger.Log(LogLevel.Error, $"{message} [{correlationID}]"));
				logger.Log(LogLevel.Error, $"{exception.Message} [{correlationID}]", exception);
			}

			// write to centerlized logs
			logs = logs ?? new List<string>();
			if (exception != null && exception is WampException)
			{
				var details = (exception as WampException).GetDetails();
				logs.Add($"> Message: {details.Item2}");
				logs.Add($"> Type: {details.Item3}");
			}
			else if (exception != null)
			{
				logs.Add($"> Message: {exception.Message}");
				logs.Add($"> Type: {exception.GetType().ToString()}");
			}

			Tuple<string, string, string, List<string>, string> log = null;
			try
			{
				await Global.InitializeLoggingServiceAsync().ConfigureAwait(false);
				while (Global.Logs.TryDequeue(out log))
					await Global._LoggingService.WriteLogsAsync(log.Item1, log.Item2, log.Item3, log.Item4, log.Item5, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				await Global._LoggingService.WriteLogsAsync(correlationID, serviceName ?? (Global.ServiceName ?? "APIGateway"), objectName, logs, exception.GetStack(), Global.CancellationTokenSource.Token).ConfigureAwait(false);
			}
			catch
			{
				if (log != null)
					Global.Logs.Enqueue(log);
				Global.Logs.Enqueue(new Tuple<string, string, string, List<string>, string>(correlationID, serviceName ?? (Global.ServiceName ?? "APIGateway"), objectName, logs, exception.GetStack()));
			}
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(this HttpContext context, ILogger logger, string objectName, string log, Exception exception = null, string serviceName = null)
			=> Global.WriteLogsAsync(context, logger, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception, serviceName);

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
		/// <returns></returns>
		public static Task WriteLogsAsync(this HttpContext context, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null)
			=> Global.WriteLogsAsync(context, Global.Logger, objectName, logs, exception, serviceName, mode, correlationID);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(this HttpContext context, string objectName, string log, Exception exception = null, string serviceName = null)
			=> Global.WriteLogsAsync(context, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception, serviceName);

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
		public static void WriteLogs(this HttpContext context, ILogger logger, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null)
			=> Task.Run(() => Global.WriteLogsAsync(context, logger, objectName, logs, exception, serviceName, mode, correlationID)).ConfigureAwait(false);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		public static void WriteLogs(this HttpContext context, ILogger logger, string objectName, string log, Exception exception = null, string serviceName = null)
			=> Global.WriteLogs(context, logger, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception, serviceName);

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
		public static void WriteLogs(this HttpContext context, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null)
			=> Global.WriteLogs(context, Global.Logger, objectName, logs, exception, serviceName, mode, correlationID);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		public static void WriteLogs(this HttpContext context, string objectName, string log, Exception exception = null, string serviceName = null)
			=> Global.WriteLogs(context, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception, serviceName);

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
		/// <returns></returns>
		public static Task WriteLogsAsync(ILogger logger, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null)
			=> Global.WriteLogsAsync(Global.CurrentHttpContext, logger, objectName, logs, exception, serviceName, mode, correlationID);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(ILogger logger, string objectName, string log, Exception exception = null, string serviceName = null)
			=> Global.WriteLogsAsync(logger, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception, serviceName);

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null)
			=> Global.WriteLogsAsync(Global.Logger, objectName, logs, exception, serviceName, mode, correlationID);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string objectName, string log, Exception exception = null, string serviceName = null)
			=> Global.WriteLogsAsync(objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception, serviceName);

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
		public static void WriteLogs(ILogger logger, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null)
			=> Task.Run(() => Global.WriteLogsAsync(logger, objectName, logs, exception, serviceName, mode, correlationID)).ConfigureAwait(false);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="logger">The local logger</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		public static void WriteLogs(ILogger logger, string objectName, string log, Exception exception = null, string serviceName = null)
			=> Global.WriteLogs(logger, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception, serviceName);

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="mode">The logging mode</param>
		/// <param name="correlationID">The correlation identity</param>
		public static void WriteLogs(string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null)
			=> Global.WriteLogs(Global.Logger, objectName, logs, exception, serviceName, mode, correlationID);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <param name="serviceName">The name of service</param>
		public static void WriteLogs(string objectName, string log, Exception exception = null, string serviceName = null)
			=> Global.WriteLogs(objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception, serviceName);
	}
}