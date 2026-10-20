import java.util.Properties

plugins {
    id("com.android.application")
}

val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}

android {
    namespace = "com.cellowalla.app"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.cellowalla.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 5
        versionName = "0.3.1"
    }

    signingConfigs {
        if (keystoreProps.isNotEmpty()) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                // The password lives in the secrets vault (DPAPI): load it first (. secrets\vault.ps1; Import-VaultSecrets).
                val pass = keystoreProps.getProperty("storePassword") ?: System.getenv("CELLOWALLA_KEYSTORE_PASSWORD")
                    ?: throw GradleException("Release signing needs the keystore password: run . C:\\MyReverseProjects\\secrets\\vault.ps1; Import-VaultSecrets first")
                storePassword = pass
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword") ?: pass
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (keystoreProps.isNotEmpty()) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.work:work-runtime:2.12.0")
}
