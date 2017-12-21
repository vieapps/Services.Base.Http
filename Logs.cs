#region Related components
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Web;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.Base.AspNet
{
	public static partial class Global
	{
		/// <summary>
		/// Gets or sets name of the working service
		/// </summary>
		public static string ServiceName { get; set; }

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
				items.Add("Correlation-ID", id);
			}

			return id;
		}

		internal static ConcurrentQueue<Tuple<string, string, string, List<string>, string>> Logs = new ConcurrentQueue<Tuple<string, string, string, List<string>, string>>();

		/// <summary>
		/// Gets the cancellation token source (global scope)
		/// </summary>
		public static CancellationTokenSource CancellationTokenSource { get; internal set; } = new CancellationTokenSource();

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="stack">The stack</param>
		/// <returns></returns>
		public static async Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, string stack)
		{
			try
			{
				await Global.InitializeLoggingServiceAsync().ConfigureAwait(false);
				while (Global.Logs.TryDequeue(out Tuple<string, string, string, List<string>, string> log))
					await Global._LoggingService.WriteLogsAsync(log.Item1, log.Item2, log.Item3, log.Item4, log.Item5, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				await Global._LoggingService.WriteLogsAsync(correlationID, serviceName, objectName, logs, stack, Global.CancellationTokenSource.Token).ConfigureAwait(false);
			}
			catch
			{
				Global.Logs.Enqueue(new Tuple<string, string, string, List<string>, string>(correlationID, serviceName, objectName, logs, stack));
			}
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="stack">The stack</param>
		public static void WriteLogs(string correlationID, string serviceName, string objectName, List<string> logs, string stack)
		{
			Task.Run(async () =>
			{
				await Global.WriteLogsAsync(correlationID, serviceName, objectName, logs, stack).ConfigureAwait(false);
			}).ConfigureAwait(false);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, Exception exception = null)
		{
			// prepare
			serviceName = string.IsNullOrWhiteSpace(serviceName)
				? Global.ServiceName ?? "Unknown"
				: serviceName;

			var stack = "";
			if (exception != null)
			{
				if (exception is WampSharp.V2.Core.Contracts.WampException)
				{
					var details = (exception as WampSharp.V2.Core.Contracts.WampException).GetDetails();
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
			return Global.WriteLogsAsync(correlationID, serviceName, objectName, logs, stack);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(string correlationID, string serviceName, string objectName, List<string> logs, Exception exception = null)
		{
			Task.Run(async () =>
			{
				await Global.WriteLogsAsync(correlationID, serviceName, objectName, logs, exception).ConfigureAwait(false);
			}).ConfigureAwait(false);
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
			return Global.WriteLogsAsync(correlationID, null, objectName, logs, exception);
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
			Global.WriteLogs(correlationID, null, objectName, logs, exception);
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
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(List<string> logs, Exception exception = null)
		{
			return Global.WriteLogsAsync(Global.GetCorrelationID(), null, logs, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="logs">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(List<string> logs, Exception exception = null)
		{
			Global.WriteLogs(Global.GetCorrelationID(), null, logs, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		/// <returns></returns>
		public static Task WriteLogsAsync(string log, Exception exception = null)
		{
			return Global.WriteLogsAsync(Global.GetCorrelationID(), null, log, exception);
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="log">The logs</param>
		/// <param name="exception">The error exception</param>
		public static void WriteLogs(string log, Exception exception = null)
		{
			Global.WriteLogs(Global.GetCorrelationID(), null, log, exception);
		}
	}
}