namespace IdenGrid.Core;

public static class LoginPresentation
{
    public static string FailureMessage(int? statusCode, int? retryAfterSeconds = null)
    {
        if (statusCode == 429)
        {
            var remaining = Math.Max(1, retryAfterSeconds ?? 60);
            return $"尝试次数过多，请在 {remaining / 60:00}:{remaining % 60:00} 后重试";
        }
        return statusCode is 401 or 403
            ? "用户名或者密码错误"
            : "登录失败，请稍后重试";
    }
}

public static class AccessTokenRefreshSchedule
{
    private static readonly TimeSpan Margin = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan MinimumDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan InitialRetry = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaximumRetry = TimeSpan.FromMinutes(5);

    public static TimeSpan Delay(DateTimeOffset expiresAt, DateTimeOffset now)
    {
        var delay = expiresAt - now - Margin;
        return delay < MinimumDelay ? MinimumDelay : delay;
    }

    public static TimeSpan RetryDelay(int attempt)
    {
        var exponent = Math.Clamp(attempt, 0, 4);
        var seconds = InitialRetry.TotalSeconds * Math.Pow(2, exponent);
        return TimeSpan.FromSeconds(Math.Min(seconds, MaximumRetry.TotalSeconds));
    }
}
