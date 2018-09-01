using Newtonsoft.Json.Serialization;
using System.Linq;
using System.Net.Http.Formatting;
using System.Web.Http;

namespace AuthService
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            config.Routes.MapHttpRoute(
                name: "Proxy",
                routeTemplate: "subscriptions/{subscriptionId}/{api}",
                defaults: new { controller = "Proxy" });

            config.Routes.MapHttpRoute(
                name: "ProxyWithParam",
                routeTemplate: "subscriptions/{subscriptionId}/{api}/{val}",
                defaults: new { controller = "Proxy" });

            config.Routes.MapHttpRoute(
                name: "AdminProxy",
                routeTemplate: "adminproxy/{api}",
                defaults: new { controller = "AdminProxy" });

            config.Routes.MapHttpRoute(
                name: "AdminProxyWithParam",
                routeTemplate: "adminproxy/{api}/{val}",
                defaults: new { controller = "AdminProxy" });

            config.Routes.MapHttpRoute(
                name: "GetAllTenantAuthInfo",
                routeTemplate: "admin/GetAllTenantAuthInfo",
                defaults: new { controller = "Authorization", action = "GetAllTenantAuthInfo" });

            config.Routes.MapHttpRoute(
                name: "GetTenantAuthInfo",
                routeTemplate: "access/GetTenantAuthInfo/{subscriptionId}",
                defaults: new { controller = "Authorization", action = "GetTenantAuthInfo" });

            config.Routes.MapHttpRoute(
                name: "GetDisagnosticLinks",
                routeTemplate: "info/GetDisagnosticLinks",
                defaults: new { controller = "Authorization", action = "GetDisagnosticLinks" });

            config.Routes.MapHttpRoute(
                name: "UpdateUserAccess",
                routeTemplate: "admin/UpdateUserAccess",
                defaults: new { controller = "Authorization", action = "UpdateUserAccess" });

            config.Routes.MapHttpRoute(
                name: "GetAllUserRoles",
                routeTemplate: "admin/GetAllUserRoles",
                defaults: new { controller = "Authorization", action = "GetAllUserRoles" });

            config.Routes.MapHttpRoute(
                name: "GetTenantsForUser",
                routeTemplate: "admin/GetTenantsForUser",
                defaults: new { controller = "Authorization", action = "GetTenantsForUser" });

            config.Routes.MapHttpRoute(
                name: "GetUserRoleInfo",
                routeTemplate: "admin/GetUserRoleInfo",
                defaults: new { controller = "Authorization", action = "GetUserRoleInfo" });

            config.Routes.MapHttpRoute(
                name: "IsUserAdmin",
                routeTemplate: "admin/IsUserAdmin",
                defaults: new { controller = "Authorization", action = "IsUserAdmin" });

            config.Routes.MapHttpRoute(
                name: "UpdateUserRole",
                routeTemplate: "admin/UpdateUserRole",
                defaults: new { controller = "Authorization", action = "UpdateUserRole" });

            config.Routes.MapHttpRoute(
                name: "UpdateUserApiToken",
                routeTemplate: "admin/UpdateUserApiToken",
                defaults: new { controller = "Authorization", action = "UpdateUserApiToken" });

            config.Routes.MapHttpRoute(
                name: "ReverseProxy",
                routeTemplate: "_plugin/{*randomPath}",
                defaults: new { controller = "ReverseProxy" });

            // Local Elk Stack
            config.Routes.MapHttpRoute(
                name: "ReverseProxyKibanaLocal",
                routeTemplate: "auditor/kibana/{*randomPath}",
                defaults: new { controller = "ReverseProxy" });

            // Local Elk Stack
            config.Routes.MapHttpRoute(
                name: "ReverseProxyKibanaBundles",
                routeTemplate: "bundles/{*randomPath}",
                defaults: new { controller = "ReverseProxy" });
        }
    }
}