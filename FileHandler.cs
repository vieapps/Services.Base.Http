using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
namespace net.vieapps.Services
{
	/// <summary>
	/// Abstract of all HTTP handlers for working with File HTTP services in the VIEApps NGX
	/// </summary>
	public abstract class FileHandler
    {
		/// <summary>
		/// Gets the logger for working with logs of the handler
		/// </summary>
		public virtual ILogger Logger { get; } = Components.Utility.Logger.CreateLogger<FileHandler>();

		/// <summary>
		/// Processes the request
		/// </summary>
		/// <param name="context">The processing context</param>
		/// <param name="cancellationToken">The cancellation token</param>
		/// <returns></returns>
		public abstract Task ProcessRequestAsync(HttpContext context, CancellationToken cancellationToken);
	}
}