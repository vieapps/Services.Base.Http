#region Related components
using System;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

using net.vieapps.Components.Caching;
#endregion

namespace net.vieapps.Services
{
	/// <summary>
	/// Abstract of all handlers for working with VIEApps NGX File HTTP service
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
	}
}