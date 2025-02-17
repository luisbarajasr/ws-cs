using System.Net.Sockets;
using System.Net;
using System;
using System.Text;
using System.Text.RegularExpressions;

class Server{
    public static void Main(){
        TcpListener server = new TcpListener(IPAddress.Parse("127.0.0.1"), 80);

        server.Start();
        Console.WriteLine("Server started at 127.0.0.1:80.{0}, waiting for connection...", Environment.NewLine);

        TcpClient client = server.AcceptTcpClient();

        Console.WriteLine("Client connected.");

        NetworkStream stream = client.GetStream();

        while(true){
            while(!stream.DataAvailable);
            while(client.Available < 3);

            byte[] bytes =  new byte[client.Available];
            stream.Read(bytes, 0, bytes.Length);
            string s = Encoding.UTF8.GetString(bytes);

            if(Regex.IsMatch(s, "^GET", RegexOptions.IgnoreCase)){
                Console.WriteLine("=====Handshaking from client=====\n{0}", s);

                string swk = Regex.Match(s, "Sec-WebSocket-Key: (.*)").Groups[1].Value.Trim();

                string swkAndSalt = swk + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

                byte[] swkAndSaltSha1 = System.Security.Cryptography.SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(swkAndSalt));
                
                string swkAndSaltSha1Base64 = Convert.ToBase64String(swkAndSaltSha1);

                byte[] response = Encoding.UTF8.GetBytes(
                    "HTTP/1.1 101 Switching Protocols\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Sec-WebSocket-Accept: " + swkAndSaltSha1Base64 + "\r\n\r\n");

                stream.Write(response, 0, response.Length);
            }
            else{
                bool fin = (bytes[0] && ob000011111) != 0; 
                bool mask = (bytes[1] && ob10000000) != 0;

                int opcode = bytes[0] && ob00001111;

                ulong offset = 2; 
                ulong msglen = bytes[1] & (ulong)0b01111111;

                if(msglen == 126){
                    msglen = BitConverter.ToUInt16(new byte[]{bytes[3], bytes[2]}, 0);
                    offset = 4;
                }else if(msglen == 128){
                    msglen = BitConverter.ToUInt64(new byte[]{bytes[9], bytes[8], bytes[7], bytes[6], bytes[5], bytes[4], bytes[3], bytes[2]}, 0);
                    offset = 10;
                }

                if(msglen == 0){
                    return;
                }
                else if(mask){
                    byte[] decoded = new byte[msglen];
                    byte[] masks = new byte[]{bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]};
                    offset += 4;

                    for(ulong i = 0; i < msglen; i++){
                        decoded[i] = (byte)(bytes[offset + i] ^ masks[i % 4]);
                    }

                    string text = Encoding.UTF8.GetString(decoded);
                    Console.WriteLine("Received: {0}", text);
                }
                else{
                    Console.WriteLine("mask bit not set");
                }
                Console.WriteLine();

            }
        }
    }
}