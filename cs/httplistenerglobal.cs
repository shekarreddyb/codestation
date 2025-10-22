using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;

public static class HttpDiagnostics
{
    private static IDisposable _allListenerSub;
    private static IDisposable _httpListenerSub;

    public static void Start()
    {
        _allListenerSub = DiagnosticListener.AllListeners.Subscribe(new AllListenersObserver(l =>
        {
            // This is the built-in name for HttpClient diagnostics
            if (l.Name == "HttpHandlerDiagnosticListener")
            {
                _httpListenerSub = l.Subscribe(new HttpObserver(),
                    // filter for just the events we care about
                    (eventName, _, __) =>
                        eventName == "System.Net.Http.HttpRequestOut.Start" ||
                        eventName == "System.Net.Http.HttpRequestOut.Stop"  ||
                        eventName == "System.Net.Http.Exception");
            }
        }));
    }

    private sealed class AllListenersObserver : IObserver<DiagnosticListener>
    {
        private readonly Action<DiagnosticListener> _onNext;
        public AllListenersObserver(Action<DiagnosticListener> onNext) => _onNext = onNext;

        public void OnNext(DiagnosticListener value) => _onNext?.Invoke(value);
        public void OnError(Exception error) { }
        public void OnCompleted() { }
    }

    private sealed class HttpObserver : IObserver<KeyValuePair<string, object>>
    {
        public void OnNext(KeyValuePair<string, object> kvp)
        {
            try
            {
                switch (kvp.Key)
                {
                    case "System.Net.Http.HttpRequestOut.Start":
                    {
                        var req = GetProp<HttpRequestMessage>(kvp.Value, "Request");
                        LogRequest(req);
                        break;
                    }
                    case "System.Net.Http.HttpRequestOut.Stop":
                    {
                        var req  = GetProp<HttpRequestMessage>(kvp.Value, "Request");
                        var resp = GetProp<HttpResponseMessage>(kvp.Value, "Response");
                        LogResponse(req, resp);
                        break;
                    }
                    case "System.Net.Http.Exception":
                    {
                        var req = GetProp<HttpRequestMessage>(kvp.Value, "Request");
                        var ex  = GetProp<Exception>(kvp.Value, "Exception");
                        Trace.WriteLine($"[HTTP EXCEPTION] {req?.Method} {req?.RequestUri} :: {ex}");
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"[HTTP DIAG ERROR] {ex}");
            }
        }

        public void OnError(Exception error) { }
        public void OnCompleted() { }

        private static T GetProp<T>(object obj, string name)
        {
            if (obj == null) return default;
            var p = obj.GetType().GetProperty(name);
            return p != null ? (T)p.GetValue(obj) : default;
        }

        private static void LogRequest(HttpRequestMessage req)
        {
            if (req == null) return;

            Trace.WriteLine($"[HTTP OUT →] {req.Method} {req.RequestUri}");
            Trace.WriteLine($"Headers: {req.Headers}");

            // OPTIONAL body logging — safe attempt, bounded size
            if (req.Content != null)
            {
                TryLogContent("Request Body", req.Content);
            }
        }

        private static void LogResponse(HttpRequestMessage req, HttpResponseMessage resp)
        {
            if (resp == null) return;

            Trace.WriteLine($"[HTTP OUT ←] {(int)resp.StatusCode} {resp.ReasonPhrase} for {req?.Method} {req?.RequestUri}");
            Trace.WriteLine($"Headers: {resp.Headers}");

            // OPTIONAL body logging — safe attempt, bounded size
            if (resp.Content != null)
            {
                TryLogContent("Response Body", resp.Content);
            }
        }

        private static void TryLogContent(string label, HttpContent content)
        {
            try
            {
                // This blocks intentionally inside the diag pipeline; avoids async/await here.
                var bytes = content.ReadAsByteArrayAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                const int cap = 4096; // cap to 4 KB to avoid huge logs
                var length = bytes?.Length ?? 0;

                string preview;
                try
                {
                    preview = System.Text.Encoding.UTF8.GetString(bytes, 0, Math.Min(length, cap));
                }
                catch
                {
                    preview = $"<non-text {length} bytes>";
                }

                Trace.WriteLine($"{label} ({length} bytes){(length > cap ? $" [showing first {cap}]" : "")}: {preview}");
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"[{label}] <unavailable>: {ex.Message}");
            }
        }
    }
}