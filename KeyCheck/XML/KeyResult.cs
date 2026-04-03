namespace GenerateXML
{
    public class KeyResult
    {
        public string HResult { get; private set; }
        public string Message { get; private set; }
        public bool Success { get; private set; }

        public KeyResult(string hResult, string message, bool success)
        {
            HResult = hResult;
            Message = message;
            Success = success;
        }
    }
}