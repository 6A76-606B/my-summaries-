# My Summaries Android APK

## Build APK from GitHub
1. Create a new GitHub repository named `my-summaries`.
2. Upload all files and folders from this project to the repository root (keep `.github/workflows/build-apk.yml`).
3. Open **Actions** and enable workflows if GitHub asks.
4. Select **Build My Summaries APK** and press **Run workflow**.
5. When it finishes, open the run and download the `My-Summaries-APK` artifact.
6. Extract the downloaded ZIP and install `app-debug.apk` on Android.

The app ID is `com.mysummaries.app` and the display name is `My Summaries`.

## Firebase push notifications
The workflow can include `google-services.json` when the repository secret `GOOGLE_SERVICES_JSON_BASE64` is configured with the Base64 contents of your Firebase Android app's `google-services.json`. This is only the Android Firebase configuration step. Actual remote push delivery also requires Firebase Cloud Messaging registration in the app and a trusted server-side sender. Never put Firebase service-account private keys in the HTML or public repository.

`firestore-hardening.rules` is a rules fragment, not a complete replacement for your deployed Firestore rules. Merge and test it before publishing.
