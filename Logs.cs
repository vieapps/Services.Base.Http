#region Related components
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
		static ConcurrentQueue<Tuple<string, string, string, List<string>, string>> Logs = new ConcurrentQueue<Tuple<string, string, string, List<string>, string>>();

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
		/// Gets the stack trace
		/// </summary>
		/// <param name="exception"></param>
		/// <returns></returns>
		public static string GetStack(this Exception exception)
		{
			var stack = "";
			if (exception != null && exception is WampException)
			{
				var details = (exception as WampException).GetDetails();
				stack = details.Item4?.Replace("\\r", "\r")?.Replace("\\n", "\n")?.Replace(@"\\", @"\");
				if (details.Item6 != null)
					stack = details.Item6.ToString(Newtonsoft.Json.Formatting.Indented).Replace("\\r", "\r").Replace("\\n", "\n").Replace(@"\\", @"\");
			}
			else if (exception != null)
			{
				stack = exception.StackTrace;
				var inner = exception.InnerException;
				var counter = 0;
				while (inner != null)
				{
					counter++;
					stack += "\r\n" + $"--- Inner ({counter}): ---------------------- " + "\r\n"
						+ "> Message: " + inner.Message + "\r\n"
						+ "> Type: " + inner.GetType().ToString() + "\r\n"
						+ inner.StackTrace;
					inner = inner.InnerException;
				}
			}
			return stack;
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
		/// <returns></returns>
		public static async Task WriteLogsAsync(this HttpContext context, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null)
		{
			// write to local logs
			correlationID = context.GetCorrelationID();
			if (exception == null)
				logs?.ForEach(message => Global.Logger?.Log(mode, $"{message} [{correlationID}]"));
			else
			{
				logs?.ForEach(message => Global.Logger?.Log(LogLevel.Error, $"{message} [{correlationID}]"));
				Global.Logger?.Log(LogLevel.Error, $"{exception.Message} [{correlationID}]", exception);
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

			try
			{
				await Global.InitializeLoggingServiceAsync().ConfigureAwait(false);
				while (Global.Logs.TryDequeue(out Tuple<string, string, string, List<string>, string> log))
					await Global._LoggingService.WriteLogsAsync(log.Item1, log.Item2, log.Item3, log.Item4, log.Item5, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				await Global._LoggingService.WriteLogsAsync(correlationID, serviceName ?? (Global.ServiceName ?? "APIGateway"), objectName, logs, exception.GetStack(), Global.CancellationTokenSource.Token).ConfigureAwait(false);
			}
			catch
			{
				Global.Logs.Enqueue(new Tuple<string, string, string, List<string>, string>(correlationID, serviceName ?? (Global.ServiceName ?? "APIGateway"), objectName, logs, exception.GetStack()));
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
		/// <returns></returns>
		public static Task WriteLogsAsync(string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information, string correlationID = null)
			=> Global.CurrentHttpContext.WriteLogsAsync(objectName, logs, exception, serviceName, mode, correlationID);

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="context"></param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <returns></returns>
		public static void WriteLogs(this HttpContext context, string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information)
			=> Task.Run(() => context.WriteLogsAsync(objectName, logs, exception, serviceName, mode)).ConfigureAwait(false);

		/// <summary>
		/// Writes the logs (to centerlized logging system and local logs)
		/// </summary>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The exception</param>
		/// <param name="serviceName">The name of service</param>
		/// <returns></returns>
		public static void WriteLogs(string objectName, List<string> logs, Exception exception = null, string serviceName = null, LogLevel mode = LogLevel.Information)
			=> Global.CurrentHttpContext.WriteLogs(objectName, logs, exception, serviceName, mode);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(this HttpContext context, string objectName, string log, Exception exception = null)
			=> context.WriteLogsAsync(objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string objectName, string log, Exception exception = null)
			=> Global.CurrentHttpContext.WriteLogsAsync(objectName, log, exception);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(this HttpContext context, string objectName, string log, Exception exception = null)
			=> context.WriteLogs(objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static void WriteLogs(string objectName, string log, Exception exception = null)
			=> Global.CurrentHttpContext.WriteLogs(objectName, log, exception);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(this HttpContext context, List<string> logs, Exception exception = null)
			=> context.WriteLogsAsync(null, logs, exception);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(List<string> logs, Exception exception = null)
			=> Global.CurrentHttpContext.WriteLogsAsync(logs, exception);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(this HttpContext context, List<string> logs, Exception exception = null)
			=> context.WriteLogs(null, logs, exception);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static void WriteLogs(List<string> logs, Exception exception = null)
			=> Global.CurrentHttpContext.WriteLogs(logs, exception);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(this HttpContext context, string log, Exception exception = null)
			=> context.WriteLogsAsync(null, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string log, Exception exception = null)
			=> Global.CurrentHttpContext.WriteLogsAsync(log, exception);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="context"></param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(this HttpContext context, string log, Exception exception = null)
			=> context.WriteLogs(null, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception);

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static void WriteLogs(string log, Exception exception = null)
			=> Global.CurrentHttpContext.WriteLogs(log, exception);
	}
}