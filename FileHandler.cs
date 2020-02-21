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
		public virtual Microsoft.Extensions.Logging.ILogger Logger { get; } = Components.Utility.Logger.CreateLogger<FileHandler>();

		/// <summary>
		/// Process the request
		/// </summary>
		/// <param name="context"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public abstract System.Threading.Tasks.Task ProcessRequestAsync(Microsoft.AspNetCore.Http.HttpContext context, System.Threading.CancellationToken cancellationToken);
	}
}