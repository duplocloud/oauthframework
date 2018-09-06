1. Open [/authservice/app.config](/authservice/app.config) and give the values for google clientID and secret.
2. Edit [/authservice/AuthService.cs](/authservice/AuthService.cs) and change line 83 to
   ```
   WebApp.Start<OwinConfig>("https://*:" + ServicePort);
   ```
   if you are not running in localhost.
3. Open [authservice.sln](/authservice.sln) and build the solution.
4. Copy all the files inside /authservice/bin/Debug and paste it anywhere you would like.
5. To run the application, simply open authservice.exe.
6. Open your browser and point it to the location configured in AuthService.cs. Default port is **60020**.

### Note:

For getting the client ID & Secret, create a google application using the [tutorial](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/social/google-logins?view=aspnetcore-2.1&tabs=aspnetcore2x) provided by Microsoft.