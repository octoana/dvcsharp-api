// this is a sample code to test the SSRF using local source but changed the threat model of CodeQL for testing purposes.
using System;
using System.Net;
using System.Text;
using System.Linq;

// Simple NameValue class to hold parameter pairs
public class NameValue
{
    public string name;
    public string value;

    public NameValue(string name, string value)
    {
        this.name = name;
        this.value = value;
    }
}

class Program
{
    static void Main(string[] args)
    {
        // Sample call to the ProxyPostRequest method
        var parameters = new NameValue[]
        {
            new NameValue("foo", "bar"),
            new NameValue("hello", "world")
        };

        string url = "http://httpbin.org/post"; // Use a test endpoint
        var result = ProxyPostRequest(url, parameters);

        Console.WriteLine("Response:\n" + result);
    }

    // A method to simulate UrlEncode (very basic)
    static string UrlEncode(string s) => Uri.EscapeDataString(s);

    // Simulate trace logging
    static void TraceWrite(string s) => Console.WriteLine("[TRACE] " + s);

    // Simple null guard
    static void GuardArgumentNotNull(object o, string name)
    {
        if (o == null)
            throw new ArgumentNullException(name);
    }

    public static string ProxyPostRequest(string url, NameValue[] parameters)
    {
        GuardArgumentNotNull(url, "url");
        GuardArgumentNotNull(parameters, "parameters");

        string stringData = string.Join("&", parameters.Select(
            p => string.Format("{0}={1}", UrlEncode(p.name), UrlEncode(p.value))));

        TraceWrite(string.Format("Proxying POST request: {0}", url));
        TraceWrite(stringData);

        var data = Encoding.UTF8.GetBytes(stringData);
        var webRequest = (HttpWebRequest)WebRequest.Create(url);
        webRequest.Method = "POST";
        webRequest.Timeout = 600000; // 10 min

        using (var stream = webRequest.GetRequestStream())
        {
            stream.Write(data, 0, data.Length);
        }

        using (var response = (HttpWebResponse)webRequest.GetResponse())
        using (var reader = new System.IO.StreamReader(response.GetResponseStream()))
        {
            string responseText = reader.ReadToEnd();
            return responseText;
        }
    }
}
