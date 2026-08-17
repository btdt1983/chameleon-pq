plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.chameleonpq.android"
    // Locked to the real test device's Android version (14, API 34) — see
    // android/README.md and the plan. Simplest possible choice for a
    // personal-use MVP tested on one known device: no back-compat shims, no
    // API-level branching in Kotlin.
    compileSdk = 34

    defaultConfig {
        applicationId = "com.chameleonpq.android"
        minSdk = 34
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    // `libchameleon_jni.so` lands directly under src/main/jniLibs/<abi>/ (see
    // ../README.md's build command) — this is Gradle's default native-libs
    // source set, no extra `sourceSets` config needed. Not committed (see
    // the root .gitignore); regenerate it before every build with real
    // Rust changes.
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    implementation(platform("androidx.compose:compose-bom:2024.10.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
