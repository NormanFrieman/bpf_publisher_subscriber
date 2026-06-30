using System.Net.Sockets;
using System.Text;

var targetHost = Environment.GetEnvironmentVariable("SUBSCRIBER_HOST") ?? "localhost";
const int targetPort = 10000;

using var udpClient = new UdpClient();
udpClient.Connect(targetHost, targetPort);

var i = 0;
while (true)
{
    var text = $"{i}Amessage";
    var data = Encoding.UTF8.GetBytes(text);
    await udpClient.SendAsync(data, data.Length);
    i++;
    if (i > 2)
        i = 0;
    await Task.Delay(500);
}
