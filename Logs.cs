#region Related components
using System;
using System.Collections;
using System.Collections.Generic;
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

		internal static Queue<Tuple<string, string, string, List<string>, string, string>> Logs = new Queue<Tuple<string, string, string, List<string>, string, string>>();
		internal static CancellationTokenSource _CancellationTokenSource = new CancellationTokenSource();

		/// <summary>
		/// Gets the global cancellation token source
		/// </summary>
		public static CancellationTokenSource CancellationTokenSource
		{
			get
			{
				return Global._CancellationTokenSource;
			}
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="simpleStack">The simple stack</param>
		/// <param name="fullStack">The full stack</param>
		/// <returns></returns>
		public static async Task WriteLogsAsync(string correlationID, string serviceName, string objectName, List<string> logs, string simpleStack, string fullStack)
		{
			try
			{
				await Global.InitializeLoggingServiceAsync().ConfigureAwait(false);
				while (Global.Logs.Count > 0)
				{
					var log = Global.Logs.Dequeue();
					await Global._LoggingService.WriteLogsAsync(log.Item1, log.Item2, log.Item3, log.Item4, log.Item5, log.Item6, Global.CancellationTokenSource.Token).ConfigureAwait(false);
				}
				await Global._LoggingService.WriteLogsAsync(correlationID, serviceName, objectName, logs, simpleStack, fullStack, Global.CancellationTokenSource.Token).ConfigureAwait(false);
			}
			catch
			{
				Global.Logs.Enqueue(new Tuple<string, string, string, List<string>, string, string>(correlationID, serviceName, objectName, logs, simpleStack, fullStack));
			}
		}

		/// <summary>
		/// Writes the logs into centerlized logging system
		/// </summary>
		/// <param name="correlationID">The correlation identity</param>
		/// <param name="serviceName">The name of service</param>
		/// <param name="objectName">The name of object</param>
		/// <param name="logs">The logs</param>
		/// <param name="simpleStack">The simple stack</param>
		/// <param name="fullStack">The full stack</param>
		public static void WriteLogs(string correlationID, string serviceName, string objectName, List<string> logs, string simpleStack, string fullStack)
		{
			Task.Run(async () =>
			{
				await Global.WriteLogsAsync(correlationID, serviceName, objectName, logs, simpleStack, fullStack).ConfigureAwait(false);
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

			var simpleStack = exception != null
				? exception.StackTrace
				: "";

			var fullStack = "";
			if (exception != null)
			{
				fullStack = exception.StackTrace;
				var inner = exception.InnerException;
				var counter = 0;
				while (inner != null)
				{
					counter++;
					fullStack += "\r\n" + $"-> Inner ({counter}): ---->>>>" + "\r\n" + inner.StackTrace;
					inner = inner.InnerException;
				}
				fullStack += "\r\n" + "-------------------------------------" + "\r\n";
			}

			// write logs
			return Global.WriteLogsAsync(correlationID, serviceName, objectName, logs, simpleStack, fullStack);
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
			var logs = new List<string>();
			if (!string.IsNullOrEmpty(log))
				logs.Add(log);
			if (exception != null)
				logs.Add(exception.Message + " [" + exception.GetType().ToString() + "]");
			return Global.WriteLogsAsync(correlationID, objectName, logs, exception);
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
			var logs = new List<string>();
			if (!string.IsNullOrEmpty(log))
				logs.Add(log);
			if (exception != null)
				logs.Add(exception.Message + " [" + exception.GetType().ToString() + "]");
			Global.WriteLogs(correlationID, objectName, logs, exception);
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