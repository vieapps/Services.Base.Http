#region Related components
using System;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
#endregion

namespace net.vieapps.Services
{
	/// <summary>
	/// Abstract of all handlers for working with File HTTP service in the VIEApps NGX microservices
	/// </summary>
	public abstract class FileHttpHandler
    {
		/// <summary>
		/// Process the request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public abstract Task ProcessRequestAsync(HttpContext context, CancellationToken cancellationToken = default(CancellationToken));

		/// <summary>
		/// Send an inter-communicate message
		/// </summary>
		/// <param name="message"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		protected virtual Task SendInterCommunicateMessageAsync(CommunicateMessage message, CancellationToken cancellationToken = default(CancellationToken))
			=> Global.RTUService.SendInterCommunicateMessageAsync(message, cancellationToken);
    }
}