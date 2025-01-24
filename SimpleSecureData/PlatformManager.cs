namespace SimpleSecureData {

    public enum PlatformType {
        Unknown,
        Windows,
        Linux,
        MacOS,
        Android,
        iOS,
        FreeBSD,
        Browser,
        MacCatalyst,
        TvOS,
        WatchOS
    }

    internal static class PlatformManager {
        public readonly static PlatformType CurrentPlatform = GetCurrentPlatform();

        ///<summary> Gets the current platform. </summary>
        ///<returns> The current platform. </returns>
        public static PlatformType GetCurrentPlatform() {
            if      (OperatingSystem.IsIOS())         return PlatformType.iOS;
            else if (OperatingSystem.IsAndroid())     return PlatformType.Android;
            else if (OperatingSystem.IsLinux())       return PlatformType.Linux;
            else if (OperatingSystem.IsWindows())     return PlatformType.Windows;
            else if (OperatingSystem.IsMacOS())       return PlatformType.MacOS;
            else if (OperatingSystem.IsFreeBSD())     return PlatformType.FreeBSD;
            else if (OperatingSystem.IsBrowser())     return PlatformType.Browser;
            else if (OperatingSystem.IsMacCatalyst()) return PlatformType.MacCatalyst;
            else if (OperatingSystem.IsTvOS())        return PlatformType.TvOS;
            else if (OperatingSystem.IsWatchOS())     return PlatformType.WatchOS;

            return PlatformType.Unknown; 
        }

        ///<summary> Checks if the current platform is at least the specified version. </summary>
        ///<returns> Whether the current platform is at least the specified version. </returns>
        ///<remarks> for Linux and Browser, this will always return true. If the platform is unknown, this will always return false. </remarks>
        public static bool IsVersionAtLeast(int major, int minor = 0, int build = 0) {
            switch (CurrentPlatform) {
                case PlatformType.iOS:         return OperatingSystem.IsIOSVersionAtLeast(major, minor, build);
                case PlatformType.Android:     return OperatingSystem.IsAndroidVersionAtLeast(major, minor, build);
                case PlatformType.Linux:       return true;
                case PlatformType.Windows:     return OperatingSystem.IsWindowsVersionAtLeast(major, minor, build);
                case PlatformType.MacOS:       return OperatingSystem.IsMacOSVersionAtLeast(major, minor, build);
                case PlatformType.FreeBSD:     return OperatingSystem.IsFreeBSDVersionAtLeast(major, minor, build);
                case PlatformType.Browser:     return true;
                case PlatformType.MacCatalyst: return OperatingSystem.IsMacCatalystVersionAtLeast(major, minor, build);
                case PlatformType.TvOS:        return OperatingSystem.IsTvOSVersionAtLeast(major, minor, build);
                case PlatformType.WatchOS:     return OperatingSystem.IsWatchOSVersionAtLeast(major, minor, build);
                default:                       return false;
            }
        }          
    }
}
