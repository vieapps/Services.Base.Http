using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;

namespace net.vieapps.Services
{
	/// <summary>
	/// Forwards a request to a remote service in the VIEApps NGX
	/// </summary>
	public class ServiceForwarder
	{
		/// <summary>
		/// Prepares the request before sending
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <param name="url"></param>
		/// <param name="endpointURL"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public virtual Task PrepareAsync(RequestInfo requestInfo, string url, out string endpointURL, CancellationToken cancellationToken)
		{
			endpointURL = url ?? "";
			while (endpointURL.EndsWith("/"))
				endpointURL = endpointURL.Right(endpointURL.Length - 1);
			if (!string.IsNullOrWhiteSpace(requestInfo.ObjectName))
			{
				var objectIdentity = requestInfo.GetObjectIdentity();
				endpointURL += $"/{requestInfo.ObjectName.ToLower()}" + (string.IsNullOrWhiteSpace(objectIdentity) ? "" : $"/{objectIdentity}");
			}
			return Task.CompletedTask;
		}

		/// <summary>
		/// Normalizes the results before response to client
		/// </summary>
		/// <param name="requestInfo"></param>
		/// <param name="body"></param>
		/// <param name="cancellationToken"></param>
		/// <returns></returns>
		public virtual Task NormalizeAsync(RequestInfo requestInfo, JToken body, CancellationToken cancellationToken)
			=> Task.CompletedTask;
	}
}