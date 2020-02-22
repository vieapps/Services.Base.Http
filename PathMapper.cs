using Microsoft.AspNetCore.Hosting;
#if !NETCOREAPP2_1
using Microsoft.Extensions.Hosting;
#endif
namespace net.vieapps.Services
{
	/// <summary>
	/// Abstract for branching the request pipeline of all HTTP services in the VIEApps NGX
	/// </summary>
	public abstract class PathMapper
	{
		/// <summary>
		/// Branches the request pipeline based on matches of the given request path
		/// </summary>
		/// <param name="appBuilder">The application builder for processing</param>
		/// <param name="appLifetime">The application life-time for registering events</param>
		public abstract void Map(
			Microsoft.AspNetCore.Builder.IApplicationBuilder appBuilder,
#if !NETCOREAPP2_1
			IHostApplicationLifetime appLifetime = null
#else
			IApplicationLifetime appLifetime = null
#endif
		);
	}
}