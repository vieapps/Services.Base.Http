#region Related components
using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
#if !NETCOREAPP2_1
using Microsoft.Extensions.Hosting;
#endif
using WampSharp.V2.Realm;
#endregion

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
		/// <param name="onIncomingConnectionEstablished">The collection that contains the actions to run when the incoming connection to API Gateway Router is established</param>
		/// <param name="onOutgoingConnectionEstablished">The collection that contains the actions to run when the outgoing connection to API Gateway Router is established</param>
		public abstract void Map(
			IApplicationBuilder appBuilder,
#if !NETCOREAPP2_1
			IHostApplicationLifetime appLifetime = null,
#else
			IApplicationLifetime appLifetime = null,
#endif
			List<Action<object, WampSessionCreatedEventArgs>> onIncomingConnectionEstablished = null,
			List<Action<object, WampSessionCreatedEventArgs>> onOutgoingConnectionEstablished = null
		);
	}
}