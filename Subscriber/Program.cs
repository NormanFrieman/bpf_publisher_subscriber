using System.Net.Sockets;
using System.Text;

var targetHost = Environment.GetEnvironmentVariable("BROKER_HOST") ?? "localhost";
const int brokerPort = 10000;

const int port = 11000;
using var udpClient = new UdpClient(port);

while (true)
{
    var result = await udpClient.ReceiveAsync();
    var message = Encoding.UTF8.GetString(result.Buffer);

    if (message.Contains("helper")) {
        using var udpBrokerClient = new UdpClient();
        udpBrokerClient.Connect(targetHost, brokerPort);

        var messageToBroker = string.Concat("1", message.Split(":")[1]);
        var data = Encoding.UTF8.GetBytes(messageToBroker);
        await udpBrokerClient.SendAsync(data, data.Length);
    }
    
    Console.WriteLine(message);
}