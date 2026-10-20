# The dashboard calls these from JavaScript.
-keepclassmembers class com.cellowalla.app.MainActivity$Bridge {
    @android.webkit.JavascriptInterface <methods>;
}
