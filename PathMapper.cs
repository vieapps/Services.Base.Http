using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using WampSharp.V2.Realm;

namespace net.vieapps.Services
{
	/// <summary>
	/// Branchs the request pipeline of a HTTP service in the VIEApps NGX
	/// </summary>
	public class PathMapper
	{
		/// <summary>
		/// Branches the request pipeline based on matches of the given request path
		/// </summary>
		/// <param name="appBuilder">The application builder for processing</param>
		/// <param name="appLifetime">The application life-time for registering events</param>
		/// <param name="onIncomingConnectionEstablished">The collection that contains the actions to run when the incoming connection to API Gateway Router is established</param>
		/// <param name="onOutgoingConnectionEstablished">The collection that contains the actions to run when the outgoing connection to API Gateway Router is established</param>
		public virtual void Map(IApplicationBuilder appBuilder, IHostApplicationLifetime appLifetime, List<Action<object, WampSessionCreatedEventArgs>> onIncomingConnectionEstablished, List<Action<object, WampSessionCreatedEventArgs>> onOutgoingConnectionEstablished) { }
	}
}