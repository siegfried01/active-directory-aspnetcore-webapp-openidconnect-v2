// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.TokenCacheProviders.InMemory;
using TodoListClient.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web.UI;
using Microsoft.Identity.Web.TokenCacheProviders.Session;
using Microsoft.Extensions.Caching.Distributed;
using System;
using Microsoft.Identity.Web.TokenCacheProviders.Distributed;
using Alachisoft.NCache.Client;

namespace WebApp_OpenIDConnect_DotNet
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDistributedMemoryCache();

            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
                // Handling SameSite cookie according to https://docs.microsoft.com/en-us/aspnet/core/security/samesite?view=aspnetcore-3.1
                options.HandleSameSiteCookieCompatibility();
            });

            services.AddOptions();

            services.AddSignIn(Configuration, "AzureAdB2C");

            // This is required to be instantiated before the OpenIdConnectOptions starts getting configured.
            // By default, the claims mapping will map claim names in the old format to accommodate older SAML applications.
            // 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' instead of 'roles'
            // This flag ensures that the ClaimsIdentity claims collection will be built from the claims in the token
            // JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

            var distCacheConn = Configuration.GetConnectionString("DistCache_ConnectionString");
            // Token acquisition service based on MSAL.NET
            // and chosen token cache implementation
            services.AddWebAppCallsProtectedWebApi(Configuration, new string[] {
                Configuration["TodoList:TodoListScope"] },
                configSectionName: "AzureAdB2C")

                 // .AddDistributedSqlServerCache(options => { options.ConnectionString = distCacheConn; options.SchemaName = "dbo"; options.TableName = "Tokens"; })
                // connection string redis: https://stackexchange.github.io/StackExchange.Redis/Configuration.html
                 .AddDistributedRedisCache(options => { options.InstanceName = "OIDCTokens"; options.Configuration = "127.0.0.1,password=secretpassword"; }) //https://dotnetcoretutorials.com/2017/01/06/using-redis-cache-net-core/
                 
                 //.AddInMemoryTokenCaches()
                 // https://docs.microsoft.com/en-us/aspnet/core/performance/caching/distributed?view=aspnetcore-3.1
                 //
                 // This NCache looks like too much trouble.
                 // pushd ${SRCROOT}/siegfried01gitub/aad-aspnetcore-webapp-openidconnect-v2/4-WebApp-your-API/4-2-B2C/Client
                 // dotnet add package Alachisoft.NCache.OpenSource.SDK --version 5.0.3
                 //.AddNCacheDistributedCache(configuration =>  { configuration.CacheName = "demoClusteredCache"; configuration.EnableLogs = true;  configuration.ExceptionsEnabled = true; })
                 .AddDistributedTokenCaches()
                ;

            // Add APIs
            services.AddTodoListService(Configuration);

            services.AddControllersWithViews(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            }).AddMicrosoftIdentityUI();

            services.AddRazorPages();

            //Configuring appsettings section AzureAdB2C, into IOptions
            services.AddOptions();
            services.Configure<OpenIdConnectOptions>(Configuration.GetSection("AzureAdB2C"));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IHostApplicationLifetime lifetime, IDistributedCache cache)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
            lifetime.ApplicationStarted.Register(() =>
            {
                var currentTimeUTC = DateTime.UtcNow.ToString();
                byte[] encodedCurrentTimeUTC = System.Text.Encoding.UTF8.GetBytes(currentTimeUTC);
                var options = new DistributedCacheEntryOptions()
                    .SetSlidingExpiration(TimeSpan.FromSeconds(20));
                cache.Set("cachedTimeUTC", encodedCurrentTimeUTC, options);
            });
        }
    }
}
