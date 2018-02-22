#region Related components
using System;
using System.Linq;
using System.Web;
using System.Threading;
using System.Threading.Tasks;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.Specialized;

using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Security;
using net.vieapps.Components.Repository;
#endregion

namespace net.vieapps.Services.Base.AspNet
{
	public static partial class Global
	{
		/// <summary>
		/// Gets the state that determines the user is authenticated or not
		/// </summary>
		/// <param name="requestInfo">The requesting information that contains user information</param>
		/// <returns></returns>
		public static bool IsAuthenticated(RequestInfo requestInfo)
		{
			return requestInfo != null && requestInfo.Session != null && requestInfo.Session.User != null && requestInfo.Session.User.IsAuthenticated;
		}

		/// <summary>
		/// Gets the state that determines the user is system administrator or not
		/// </summary>
		/// <param name="user">The user information</param>
		/// /// <param name="correlationID">The correlation identity</param>
		/// <returns></returns>
		public static async Task<bool> IsSystemAdministratorAsync(User user, string correlationID = null)
		{
			if (user == null || !user.IsAuthenticated)
				return false;

			else
				try
				{
					var result = await Global.CallServiceAsync(new RequestInfo()
					{
						Session = new Session() { User = user },
						ServiceName = "users",
						ObjectName = "account",
						Verb = "GET",
						Extra = new Dictionary<string, string>()
						{
							{ "IsSystemAdministrator", "" }
						},
						CorrelationID = correlationID ?? UtilityService.NewUUID
					}).ConfigureAwait(false);
					return user.ID.IsEquals((result["ID"] as JValue)?.Value as string) && (result["IsSystemAdministrator"] as JValue)?.Value.CastAs<bool>() == true;
				}
				catch
				{
					return false;
				}
		}

		/// <summary>
		/// Gets the state that determines the user is system administrator or not
		/// </summary>
		/// <param name="session">The session information</param>
		/// /// <param name="correlationID">The correlation identity</param>
		/// <returns></returns>
		public static Task<bool> IsSystemAdministratorAsync(Session session, string correlationID = null)
		{
			return Global.IsSystemAdministratorAsync(session?.User, correlationID);
		}

		/// <summary>
		/// Gets the state that determines the user is system administrator or not
		/// </summary>
		/// <param name="requestInfo">The requesting information that contains user information</param>
		/// <returns></returns>
		public static Task<bool> IsSystemAdministratorAsync(RequestInfo requestInfo)
		{
			return Global.IsSystemAdministratorAsync(requestInfo?.Session?.User, requestInfo?.CorrelationID);
		}

		/// <summary>
		/// Gets the state that determines the user can perform the action or not
		/// </summary>
		/// <param name="user">The user information</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="action">The action to perform on the object of this service</param>
		/// <param name="privileges">The working privileges of the object (entity)</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static async Task<bool> IsAuthorizedAsync(User user, string serviceName, string objectName, string objectIdentity, Components.Security.Action action, Privileges privileges = null, Func<User, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
		{
			return await Global.IsSystemAdministratorAsync(user).ConfigureAwait(false)
				? true
				: user != null
					? user.IsAuthorized(serviceName, objectName, objectIdentity, action, privileges, getPrivileges, getActions)
					: false;
		}

		/// <summary>
		/// Gets the state that determines the user can perform the action or not
		/// </summary>
		/// <param name="requestInfo">The requesting information that contains user information</param>
		/// <param name="action">The action to perform on the object of this service</param>
		/// <param name="privileges">The working privileges of the object (entity)</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static Task<bool> IsAuthorizedAsync(RequestInfo requestInfo, Components.Security.Action action, Privileges privileges = null, Func<User, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
		{
			return Global.IsAuthorizedAsync(requestInfo.Session?.User, requestInfo.ServiceName, requestInfo.ObjectName, requestInfo.GetObjectIdentity(true), action, privileges, getPrivileges, getActions);
		}

		/// <summary>
		/// The the global privilege role of the user
		/// </summary>
		/// <param name="user"></param>
		/// <param name="serviceName"></param>
		/// <returns></returns>
		public static string GetPrivilegeRole(User user, string serviceName)
		{
			var privilege = user != null && user.Privileges != null
				? user.Privileges.FirstOrDefault(p => p.ServiceName.IsEquals(serviceName) && string.IsNullOrWhiteSpace(p.ObjectName) && string.IsNullOrWhiteSpace(p.ObjectIdentity))
				: null;
			return privilege?.Role ?? PrivilegeRole.Viewer.ToString();
		}

		/// <summary>
		/// Gets the default privileges  of the user
		/// </summary>
		/// <param name="user"></param>
		/// <param name="privileges"></param>
		/// <returns></returns>
		public static List<Privilege> GetPrivileges(User user, Privileges privileges, string serviceName)
		{
			return null;
		}

		/// <summary>
		/// Gets the default privilege actions
		/// </summary>
		/// <param name="role"></param>
		/// <returns></returns>
		public static List<string> GetPrivilegeActions(PrivilegeRole role)
		{
			var actions = new List<Components.Security.Action>();
			switch (role)
			{
				case PrivilegeRole.Administrator:
					actions = new List<Components.Security.Action>()
					{
						Components.Security.Action.Full
					};
					break;

				case PrivilegeRole.Moderator:
					actions = new List<Components.Security.Action>()
					{
						Components.Security.Action.Approve,
						Components.Security.Action.Update,
						Components.Security.Action.Create,
						Components.Security.Action.View,
						Components.Security.Action.Download
					};
					break;

				case PrivilegeRole.Editor:
					actions = new List<Components.Security.Action>()
					{
						Components.Security.Action.Update,
						Components.Security.Action.Create,
						Components.Security.Action.View,
						Components.Security.Action.Download
					};
					break;

				case PrivilegeRole.Contributor:
					actions = new List<Components.Security.Action>()
					{
						Components.Security.Action.Create,
						Components.Security.Action.View,
						Components.Security.Action.Download
					};
					break;

				default:
					actions = new List<Components.Security.Action>()
					{
						Components.Security.Action.View,
						Components.Security.Action.Download
					};
					break;
			}
			return actions.Select(a => a.ToString()).ToList();
		}

		/// <summary>
		/// Gets the state that determines the user can perform the action or not
		/// </summary>
		/// <param name="requestInfo">The requesting information that contains user information</param>
		/// <param name="entity">The business entity object</param>
		/// <param name="action">The action to perform on the object of this service</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public static async Task<bool> IsAuthorizedAsync(RequestInfo requestInfo, IBusinessEntity entity, Components.Security.Action action, Func<User, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
		{
			return await Global.IsSystemAdministratorAsync(requestInfo).ConfigureAwait(false)
				? true
				: requestInfo != null && requestInfo.Session != null && requestInfo.Session.User != null
					? requestInfo.Session.User.IsAuthorized(requestInfo.ServiceName, requestInfo.ObjectName, entity?.ID, action, entity?.WorkingPrivileges, getPrivileges, getActions)
					: false;
		}

		/// <summary>
		/// Gets the state that determines the user is able to manage or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <returns></returns>
		public static async Task<bool> CanManageAsync(User user, string serviceName, string objectName, string objectIdentity)
		{
			return await Global.IsSystemAdministratorAsync(user).ConfigureAwait(false)
				|| (user != null && user.IsAuthorized(serviceName, objectName, objectIdentity, Components.Security.Action.Full, null, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions));
		}

		/// <summary>
		/// Gets the state that determines the user is able to manage or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <returns></returns>
		public static async Task<bool> CanManageAsync(User user, string serviceName, string systemID, string definitionID, string objectID)
		{
			// check user
			if (user == null || string.IsNullOrWhiteSpace(user.ID))
				return false;

			// system administrator can do anything
			if (await Global.IsSystemAdministratorAsync(user).ConfigureAwait(false))
				return true;

			// get the business object
			var @object = await RepositoryMediator.GetAsync(definitionID, objectID, Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// get the permissions state
			return @object != null && @object is IBusinessEntity
				? user.IsAuthorized(serviceName, @object.GetType().GetTypeName(true), objectID, Components.Security.Action.Full, (@object as IBusinessEntity).WorkingPrivileges, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions)
				: false;
		}

		/// <summary>
		/// Gets the state that determines the user is able to moderate or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <returns></returns>
		public static async Task<bool> CanModerateAsync(User user, string serviceName, string objectName, string objectIdentity)
		{
			return await Global.CanManageAsync(user, serviceName, objectName, objectIdentity).ConfigureAwait(false)
				? true
				: user != null && user.IsAuthorized(serviceName, objectName, objectIdentity, Components.Security.Action.Approve, null, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions);
		}

		/// <summary>
		/// Gets the state that determines the user is able to moderate or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <returns></returns>
		public static async Task<bool> CanModerateAsync(User user, string serviceName, string systemID, string definitionID, string objectID)
		{
			// administrator can do
			if (await Global.CanManageAsync(user, serviceName, systemID, definitionID, objectID).ConfigureAwait(false))
				return true;

			// check user
			if (user == null || string.IsNullOrWhiteSpace(user.ID))
				return false;

			// get the business object
			var @object = await RepositoryMediator.GetAsync(definitionID, objectID, Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// get the permissions state
			return @object != null && @object is IBusinessEntity
				? user.IsAuthorized(serviceName, @object.GetType().GetTypeName(true), objectID, Components.Security.Action.Approve, (@object as IBusinessEntity).WorkingPrivileges, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions)
				: false;
		}

		/// <summary>
		/// Gets the state that determines the user is able to edit or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <returns></returns>
		public static async Task<bool> CanEditAsync(User user, string serviceName, string objectName, string objectIdentity)
		{
			return await Global.CanModerateAsync(user, serviceName, objectName, objectIdentity).ConfigureAwait(false)
				? true
				: user != null && user.IsAuthorized(serviceName, objectName, objectIdentity, Components.Security.Action.Update, null, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions);
		}

		/// <summary>
		/// Gets the state that determines the user is able to edit or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <returns></returns>
		public static async Task<bool> CanEditAsync(User user, string serviceName, string systemID, string definitionID, string objectID)
		{
			// moderator can do
			if (await Global.CanModerateAsync(user, serviceName, systemID, definitionID, objectID).ConfigureAwait(false))
				return true;

			// check user
			if (user == null || string.IsNullOrWhiteSpace(user.ID))
				return false;

			// get the business object
			var @object = await RepositoryMediator.GetAsync(definitionID, objectID, Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// get the permissions state
			return @object != null && @object is IBusinessEntity
				? user.IsAuthorized(serviceName, @object.GetType().GetTypeName(true), objectID, Components.Security.Action.Update, (@object as IBusinessEntity).WorkingPrivileges, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions)
				: false;
		}

		/// <summary>
		/// Gets the state that determines the user is able to contribute or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <returns></returns>
		public static async Task<bool> CanContributeAsync(User user, string serviceName, string objectName, string objectIdentity)
		{
			return await Global.CanEditAsync(user, serviceName, objectName, objectIdentity).ConfigureAwait(false)
				? true
				: user != null && user.IsAuthorized(serviceName, objectName, objectIdentity, Components.Security.Action.Create, null, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions);
		}

		/// <summary>
		/// Gets the state that determines the user is able to contribute or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <returns></returns>
		public static async Task<bool> CanContributeAsync(User user, string serviceName, string systemID, string definitionID, string objectID)
		{
			// editor can do
			if (await Global.CanEditAsync(user, serviceName, systemID, definitionID, objectID).ConfigureAwait(false))
				return true;

			// check user
			if (user == null || string.IsNullOrWhiteSpace(user.ID))
				return false;

			// get the business object
			var @object = await RepositoryMediator.GetAsync(definitionID, objectID, Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// get the permissions state
			return @object != null && @object is IBusinessEntity
				? user.IsAuthorized(serviceName, @object.GetType().GetTypeName(true), objectID, Components.Security.Action.Create, (@object as IBusinessEntity).WorkingPrivileges, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions)
				: false;
		}

		/// <summary>
		/// Gets the state that determines the user is able to view or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <returns></returns>
		public static async Task<bool> CanViewAsync(User user, string serviceName, string objectName, string objectIdentity)
		{
			return await Global.CanContributeAsync(user, serviceName, objectName, objectIdentity).ConfigureAwait(false)
				? true
				: user != null && user.IsAuthorized(serviceName, objectName, objectIdentity, Components.Security.Action.View, null, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions);
		}

		/// <summary>
		/// Gets the state that determines the user is able to view or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <returns></returns>
		public static async Task<bool> CanViewAsync(User user, string serviceName, string systemID, string definitionID, string objectID)
		{
			// contributor can do
			if (await Global.CanContributeAsync(user, serviceName, systemID, definitionID, objectID).ConfigureAwait(false))
				return true;

			// check user
			if (user == null || string.IsNullOrWhiteSpace(user.ID))
				return false;

			// get the business object
			var @object = await RepositoryMediator.GetAsync(definitionID, objectID, Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// get the permissions state
			return @object != null && @object is IBusinessEntity
				? user.IsAuthorized(serviceName, @object.GetType().GetTypeName(true), objectID, Components.Security.Action.View, (@object as IBusinessEntity).WorkingPrivileges, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions)
				: false;
		}

		/// <summary>
		/// Gets the state that determines the user is able to download or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <returns></returns>
		public static async Task<bool> CanDownloadAsync(User user, string serviceName, string objectName, string objectIdentity)
		{
			return await Global.CanModerateAsync(user, serviceName, objectName, objectIdentity).ConfigureAwait(false)
				? true
				: user != null && user.IsAuthorized(serviceName, objectName, objectIdentity, Components.Security.Action.Download, null, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions);
		}

		/// <summary>
		/// Gets the state that determines the user is able to download or not
		/// </summary>
		/// <param name="user">The user who performs the action</param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="systemID">The identity of the business system</param>
		/// <param name="definitionID">The identity of the entity definition</param>
		/// <param name="objectID">The identity of the business object</param>
		/// <returns></returns>
		public static async Task<bool> CanDownloadAsync(User user, string serviceName, string systemID, string definitionID, string objectID)
		{
			// moderator can do
			if (await Global.CanModerateAsync(user, serviceName, systemID, definitionID, objectID).ConfigureAwait(false))
				return true;

			// check user
			if (user == null || string.IsNullOrWhiteSpace(user.ID))
				return false;

			// get the business object
			var @object = await RepositoryMediator.GetAsync(definitionID, objectID, Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// get the permissions state
			return @object != null && @object is IBusinessEntity
				? user.IsAuthorized(serviceName, @object.GetType().GetTypeName(true), objectID, Components.Security.Action.Download, (@object as IBusinessEntity).WorkingPrivileges, (usr, privileges) => Global.GetPrivileges(usr, privileges, serviceName), Global.GetPrivilegeActions)
				: false;
		}
	}
}