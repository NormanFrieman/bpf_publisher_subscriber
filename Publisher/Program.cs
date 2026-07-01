using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
// app.UseHttpsRedirection();

var targetHost = Environment.GetEnvironmentVariable("BROKER_HOST") ?? "localhost";
const int brokerPort = 10000;
const int subscriberPort = 11000;

app.MapPost("/create-map", async ([FromBody] CreateMapDto createMap) =>
{
    using var udpClient = new UdpClient();
    udpClient.Connect(targetHost, brokerPort);

    var message = string.Concat("0", createMap.Key);
    var data = Encoding.UTF8.GetBytes(message);
    await udpClient.SendAsync(data, data.Length);
    
    return Results.Ok(message);
});
app.MapPost("/publish", async ([FromBody] CreateMapDto createMap) =>
{
    using var udpClient = new UdpClient();
    udpClient.Connect(targetHost, brokerPort);

    var message = string.Concat("2", createMap.Key, createMap.Text);
    var data = Encoding.UTF8.GetBytes(message);
    await udpClient.SendAsync(data, data.Length);
    
    return Results.Ok(message);
});

app.MapPost("/helper/subscribe", async ([FromBody] char key) =>
{
    using var udpClient = new UdpClient();
    udpClient.Connect(targetHost, subscriberPort);

    var message = string.Concat("helper:", key.ToString());
    var data = Encoding.UTF8.GetBytes(message);
    await udpClient.SendAsync(data, data.Length);
    
    return Results.Ok(message);
});

app.Run();

internal record struct CreateMapDto
{
    public required char Key { get; init; }
    public string Text { get; init; }
}
