using BlazorSMTPServer.Components;
using SMTPServerSvc.TestClient;
using Azure.Storage.Blobs;
using BlazorSMTPServer.Services;

namespace BlazorSMTPServer;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.AddServiceDefaults();

        // Add Azure Blob Service client from Aspire resource reference ("blobs")
        builder.AddAzureBlobServiceClient("blobs");

        // Add services to the container.
        builder.Services.AddRazorComponents()
            .AddInteractiveServerComponents();

        // Register email service
        builder.Services.AddScoped<BlobEmailService>();

        var app = builder.Build();

        app.MapDefaultEndpoints();

        // Add SMTP test endpoint for development
        app.MapGet("/test-smtp", async () =>
        {
            try
            {
                await SmtpTestClient.TestSmtpServer();
                return Results.Ok("SMTP tests completed successfully. Check console output for details.");
            }
            catch (Exception ex)
            {
                return Results.Problem($"SMTP test failed: {ex.Message}");
            }
        });

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UseHttpsRedirection();

        app.UseAntiforgery();

        app.MapStaticAssets();
        app.MapRazorComponents<App>()
            .AddInteractiveServerRenderMode();

        app.Run();
    }
}
