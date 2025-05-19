// for testing a SSRF in c# using extended query suite + local threat model
using System;
using System.Net;
using System.Text;
using System.Linq;
using System.Text.RegularExpressions;

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

    // Validate URL to prevent SSRF
    static void ValidateUrl(string url)
    {
        GuardArgumentNotNull(url, "url");

        // Allow only specific domains (e.g., httpbin.org for testing)
        var allowedDomainPattern = @"^https?:\/\/(www\.)?httpbin\.org\/.*$";
        if (!Regex.IsMatch(url, allowedDomainPattern, RegexOptions.IgnoreCase))
        {
            throw new ArgumentException("The URL is not allowed.", nameof(url));
        }
    }

    public static string ProxyPostRequest(string url, NameValue[] parameters)
    {
        GuardArgumentNotNull(parameters, "parameters");

        // Validate the URL to prevent SSRF
        ValidateUrl(url);

        string stringData = string.Join("&", parameters.Select(
            p => string.Format("{0}={1}", UrlEncode(p.name), UrlEncode(p.value))));

        TraceWrite(string.Format("Proxying POST request: {0}", url));
        TraceWrite(stringData);

        var data = Encoding.UTF8.GetBytes(stringData);

        // Enforce secure protocols
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

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
