namespace net.vieapps.Services
{
	/// <summary>
	/// Abstract of all HTTP path mapper for working with HTTP services in the VIEApps NGX
	/// </summary>
	public abstract class PathMapper
	{
		/// <summary>
		/// Branches the request pipeline based on matches of the given request path
		/// </summary>
		/// <param name="appBuilder"></param>
		public abstract void Map(Microsoft.AspNetCore.Builder.IApplicationBuilder appBuilder);
	}
}