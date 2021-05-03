using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using WampSharp.V2.Realm;

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
		public abstract void Map(IApplicationBuilder appBuilder, IHostApplicationLifetime appLifetime = null, List<Action<object, WampSessionCreatedEventArgs>> onIncomingConnectionEstablished = null, List<Action<object, WampSessionCreatedEventArgs>> onOutgoingConnectionEstablished = null);
	}
}