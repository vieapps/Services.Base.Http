#region Related components
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Web;

using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.Base.AspNet
{
	public static partial class Global
	{
#if DEBUG || DEBUGLOGS
		static string _IsDebugLogEnabled = "true", _IsDebugResultsEnabled = "true", _IsInfoLogEnabled = "true";
#else
		static string _IsDebugLogEnabled = null, _IsDebugResultsEnabled = null, _IsInfoLogEnabled = null;
#endif

		static ConcurrentQueue<Tuple<string, string, string, List<string>, string>> Logs = new ConcurrentQueue<Tuple<string, string, string, List<string>, string>>();

		/// <summary>
		/// Gets or sets name of the working service
		/// </summary>
		public static string ServiceName { get; set; }

		/// <summary>
		/// Gets the cancellation token source (global scope)
		/// </summary>
		public static CancellationTokenSource CancellationTokenSource { get; internal set; } = new CancellationTokenSource();

		/// <summary>
		/// Gets the state to write debug log (from app settings - parameter named 'vieapps:Logs:Debug')
		/// </summary>
		public static bool IsDebugLogEnabled
		{
			get
			{
				return "true".IsEquals(Global._IsDebugLogEnabled ?? (Global._IsDebugLogEnabled = UtilityService.GetAppSetting("Logs:Debug", "false")));
			}
		}

		/// <summary>
		/// Gets the state to write debug result into log (from app settings - parameter named 'vieapps:Logs:Result')
		/// </summary>
		public static bool IsDebugResultsEnabled
		{
			get
			{
				return "true".IsEquals(Global._IsDebugResultsEnabled ?? (Global._IsDebugResultsEnabled = UtilityService.GetAppSetting("Logs:Result", "false")));
			}
		}

		/// <summary>
		/// Gets the state to write information log (from app settings - parameter named 'vieapps:Logs:Info')
		/// </summary>
		public static bool IsInfoLogEnabled
		{
			get
			{
				return Global.IsDebugLogEnabled || "true".IsEquals(Global._IsInfoLogEnabled ?? (Global._IsInfoLogEnabled = UtilityService.GetAppSetting("Logs:Info", "true")));
			}
		}

		/// <summary>
		/// Gets the correlation identity
		/// </summary>
		/// <param name="items"></param>
		/// <returns></returns>
		public static string GetCorrelationID(IDictionary items = null)
		{
			items = items ?? HttpContext.Current?.Items;
			if (items == null)
				return UtilityService.GetUUID();

			var id = items.Contains("Correlation-ID")
				? items["Correlation-ID"] as string
				: null;

			if (string.IsNullOrWhiteSpace(id))
			{
				id = UtilityService.GetUUID();
				items["Correlation-ID"] = id;
			}

			return id;
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="stack">The stack</param>
		/// <param name="serviceName">The name of service</param>
		/// <returns></returns>
		public static async Task WriteLogsAsync(string correlationID, string objectName, List<string> logs, string stack, string serviceName = null)
		{
			try
			{
				await Global.InitializeLoggingServiceAsync().ConfigureAwait(false);
				while (Global.Logs.TryDequeue(out Tuple<string, string, string, List<string>, string> log))
					await Global._LoggingService.WriteLogsAsync(log.Item1, log.Item2, log.Item3, log.Item4, log.Item5, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				await Global._LoggingService.WriteLogsAsync(correlationID, serviceName ?? (Global.ServiceName ?? "Unknown"), objectName, logs, stack, Global.CancellationTokenSource.Token).ConfigureAwait(false);
			}
			catch
			{
				Global.Logs.Enqueue(new Tuple<string, string, string, List<string>, string>(correlationID, serviceName ?? (Global.ServiceName ?? "Unknown"), objectName, logs, stack));
			}
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="stack">The stack</param>
		/// <param name="serviceName">The name of service</param>
		public static void WriteLogs(string correlationID, string objectName, List<string> logs, string stack, string serviceName = null)
		{
			try
			{
				Task.Run(async () =>
				{
					await Global.WriteLogsAsync(correlationID, objectName, logs, stack, serviceName).ConfigureAwait(false);
				}).ConfigureAwait(false);
			}
			catch { }
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string correlationID, string objectName, List<string> logs, Exception exception = null)
		{
			// prepare
			var stack = "";
			if (exception != null)
			{
				if (exception is WampException)
				{
					var details = (exception as WampException).GetDetails();
					logs = logs ?? new List<string>();
					logs.Add($"> Message: {details.Item2}");
					logs.Add($"> Type: {details.Item3}");
					stack = details.Item4;
					if (details.Item6 != null)
						stack = details.Item6.ToString(Newtonsoft.Json.Formatting.Indented);
				}
				else
				{
					logs = logs ?? new List<string>();
					logs.Add($"> Message: {exception.Message}");
					logs.Add($"> Type: {exception.GetType().ToString()}");
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
			}

			// write logs
			return Global.WriteLogsAsync(correlationID, objectName, logs, stack);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(string correlationID, string objectName, List<string> logs, Exception exception = null)
		{
			try
			{
				Task.Run(async () =>
				{
					await Global.WriteLogsAsync(correlationID, objectName, logs, exception).ConfigureAwait(false);
				}).ConfigureAwait(false);
			}
			catch { }
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string correlationID, string objectName, string log, Exception exception = null)
		{
			return Global.WriteLogsAsync(correlationID, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(string correlationID, string objectName, string log, Exception exception = null)
		{
			Global.WriteLogs(correlationID, objectName, !string.IsNullOrWhiteSpace(log) ? new List<string>() { log } : null, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string correlationID, List<string> logs, Exception exception = null)
		{
			return Global.WriteLogsAsync(correlationID ?? Global.GetCorrelationID(), null, logs, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(List<string> logs, Exception exception = null)
		{
			return Global.WriteLogsAsync(null, logs, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(string correlationID, List<string> logs, Exception exception = null)
		{
			Global.WriteLogs(correlationID ?? Global.GetCorrelationID(), null, logs, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(List<string> logs, Exception exception = null)
		{
			Global.WriteLogs(null, logs, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string correlationID, string log, Exception exception = null)
		{
			return Global.WriteLogsAsync(correlationID ?? Global.GetCorrelationID(), null, log, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string log, Exception exception = null)
		{
			return Global.WriteLogsAsync(null, log, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(string correlationID, string log, Exception exception = null)
		{
			Global.WriteLogs(correlationID ?? Global.GetCorrelationID(), null, log, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(string log, Exception exception = null)
		{
			Global.WriteLogs(null, log, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static async Task WriteDebugLogsAsync(string correlationID, string serviceName, List<string> logs, Exception exception = null)
		{
			// prepare
			if (exception != null)
			{
				if (exception is WampException)
				{
					var details = (exception as WampException).GetDetails();
					logs = logs ?? new List<string>();
					logs.Add($"> Message: {details.Item2}");
					logs.Add($"> Type: {details.Item3}");
					logs.Add($"> Stack: {details.Item4}");
					if (details.Item6 != null)
						logs.Add($"> Inners: {details.Item6.ToString(Newtonsoft.Json.Formatting.None)}");
				}
				else
				{
					logs = logs ?? new List<string>();
					logs.Add($"> Message: {exception.Message}");
					logs.Add($"> Type: {exception.GetType()}");
					logs.Add($"> Stack: {exception.StackTrace}");
					var inner = exception.InnerException;
					var counter = 1;
					while (inner != null)
					{
						logs.Add($"--- Inner ({counter}): ---------------------- ");
						logs.Add($"> Message: {inner.Message}");
						logs.Add($"> Type: {inner.GetType()}");
						logs.Add($"> Stack: {inner.StackTrace}");
						inner = inner.InnerException;
						counter++;
					}
				}
			}

			// write logs
			try
			{
				await Global.InitializeLoggingServiceAsync().ConfigureAwait(false);
				await Global._LoggingService.WriteDebugLogsAsync(correlationID, serviceName ?? (Global.ServiceName ?? "Unknown"), logs, Global.CancellationTokenSource.Token).ConfigureAwait(false);
			}
			catch { }
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteDebugLogsAsync(string correlationID, string serviceName, string logs, Exception exception = null)
		{
			return Global.WriteDebugLogsAsync(correlationID, serviceName, new List<string>() { logs }, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static void WriteDebugLogs(string correlationID, string serviceName, List<string> logs, Exception exception = null)
		{
			Task.Run(async () =>
			{
				await Global.WriteDebugLogsAsync(correlationID, serviceName, logs, exception).ConfigureAwait(false);
			}).ConfigureAwait(false);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static void WriteDebugLogs(string correlationID, string serviceName, string logs, Exception exception = null)
		{
			Global.WriteDebugLogs(correlationID, serviceName, new List<string>() { logs }, exception);
		}
	}
}