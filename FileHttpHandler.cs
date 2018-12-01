using System.Threading;
namespace net.vieapps.Services
{
	/// <summary>
	/// Abstract of all HTTP handlers for working with VIEApps NGX File HTTP service
	/// </summary>
	public abstract class FileHandler
    {
		/// <summary>
		/// Process the request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public abstract System.Threading.Tasks.Task ProcessRequestAsync(Microsoft.AspNetCore.Http.HttpContext context, CancellationToken cancellationToken = default(CancellationToken));
	}
}