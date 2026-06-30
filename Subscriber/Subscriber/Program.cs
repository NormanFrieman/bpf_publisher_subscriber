using System.Net.Sockets;
using System.Text;

const int port = 11000;
using var udpClient = new UdpClient(port);

while (true)
{
    var result = await udpClient.ReceiveAsync();
    var message = Encoding.UTF8.GetString(result.Buffer);
    Console.WriteLine(message);
}