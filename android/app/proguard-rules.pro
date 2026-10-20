# WorkManager's database is created by reflection (R8 full mode would strip its constructor).
-keep class * extends androidx.room.RoomDatabase { <init>(); }

# The dashboard calls these from JavaScript.
-keepclassmembers class com.cellowalla.app.MainActivity$Bridge {
    @android.webkit.JavascriptInterface <methods>;
}
