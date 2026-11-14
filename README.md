# My Summaries Android APK

1. ارفع كل الملفات (بما فيها فولدر `.github` وفولدر `www`) على جذر الريبو.
2. افتح تبويب **Actions** > **Build My Summaries APK** > **Run workflow**.
3. بعد ما يخلص (علامة خضرا) افتح الـ run ونزّل `My-Summaries-APK` من Artifacts.
4. فك الـ ZIP وثبّت `app-debug.apk` على الموبايل.

App ID: `com.mysummaries.app`

أيقونة التطبيق: بتتولّد تلقائيًا من `icon.jpg` في الـ workflow (خطوة **Apply app icon**). لتغيير الأيقونة بدّل `icon.jpg`.

تسجيل الدخول بجوجل داخل التطبيق بيستخدم الـ native (مش المتصفح). لازم تضيف بصمة التوقيع في Firebase مرة واحدة:
SHA-1: `3C:7B:4B:70:E5:B6:90:C6:6D:52:15:0D:54:45:3C:99:79:57:70:BB`
Firebase Console ← Project settings ← تطبيق Android ← Add fingerprint، ثم نزّل `google-services.json` الجديد واستبدل بيه القديم في الريبو.
