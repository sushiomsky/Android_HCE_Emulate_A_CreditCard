package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.widget.Button;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

public class MainActivity extends AppCompatActivity {

    private static final String PREFS = "hce_cc_prefs";
    private static final String KEY_PROFILE = "profile";

    private static final String PROFILE_VISA = "visa";
    private static final String PROFILE_MASTERCARD = "mastercard";
    private static final String PROFILE_BASIC = "basic";

    private TextView tvHceServiceLog;
    private TextView tvNfcStatus;
    private RadioGroup rgProfile;
    private String hceServiceLog = "";
    private boolean suppressProfileCallback = false;

    @SuppressLint("SourceLockedOrientationActivity")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.viewMainActivity), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
        tvHceServiceLog = findViewById(R.id.tvHceServiceLog);
        tvNfcStatus = findViewById(R.id.tvNfcStatus);
        rgProfile = findViewById(R.id.rgProfile);
        Button btnClearLog = findViewById(R.id.btnClearLog);

        /**
         * Note on this setting: Do NOT remove this setting or the app will fail when the screen goes
         * from portrait to landscape and vice versa. The app will then run the onDestroy() method, but
         * the BroadcastReceiver is not registered yet. The only way to solve this issue would be to
         * use a STATIC BroadcastReceiver.
         */
        this.setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);

        updateNfcStatus();

        // HCE services send via LocalBroadcastManager, so receive the same way on all API levels.
        // (A previous version used Context.registerReceiver on API 33+, which never receives
        // LocalBroadcastManager broadcasts, leaving the log empty on modern phones.)
        LocalBroadcastManager.getInstance(MainActivity.this).registerReceiver(
                mMessageReceiver, new IntentFilter("HceCcEmulatorService"));

        String activeProfile = getActiveProfile();
        checkProfileRadio(activeProfile);

        rgProfile.setOnCheckedChangeListener((group, checkedId) -> {
            if (suppressProfileCallback) return;
            if (checkedId == R.id.rbVisa) {
                applyProfile(PROFILE_VISA);
            } else if (checkedId == R.id.rbMastercard) {
                applyProfile(PROFILE_MASTERCARD);
            } else if (checkedId == R.id.rbBasic) {
                applyProfile(PROFILE_BASIC);
            }
        });

        btnClearLog.setOnClickListener(v -> {
            hceServiceLog = "";
            tvHceServiceLog.setText(getString(R.string.hce_service_log));
        });
    }

    @Override
    public void onResume() {
        super.onResume();
        updateNfcStatus();
    }

    @Override
    public void onPause() {
        super.onPause();
    }

    @Override
    public void onStop() {
        super.onStop();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        LocalBroadcastManager.getInstance(this).unregisterReceiver(mMessageReceiver);
    }

    private void updateNfcStatus() {
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter == null) {
            tvNfcStatus.setText("NFC: not available on this device");
        } else if (!adapter.isEnabled()) {
            tvNfcStatus.setText("NFC: available but disabled - enable NFC in system settings");
        } else {
            tvNfcStatus.setText("NFC: ready");
        }
    }

    private String getActiveProfile() {
        SharedPreferences prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String stored = prefs.getString(KEY_PROFILE, null);
        if (stored != null) return stored;
        // derive from component state (fresh install: Visa enabled in manifest)
        PackageManager pm = getPackageManager();
        if (isServiceEnabled(pm, HceCcEmulationServiceMastercard.class)) return PROFILE_MASTERCARD;
        if (isServiceEnabled(pm, HceCcEmulationServiceBasic.class)) return PROFILE_BASIC;
        return PROFILE_VISA;
    }

    private boolean isServiceEnabled(PackageManager pm, Class<?> serviceClass) {
        int state = pm.getComponentEnabledSetting(new ComponentName(this, serviceClass));
        if (state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED) return true;
        if (state == PackageManager.COMPONENT_ENABLED_STATE_DISABLED) return false;
        // COMPONENT_ENABLED_STATE_DEFAULT: fall back to manifest android:enabled value
        try {
            return pm.getServiceInfo(new ComponentName(this, serviceClass), 0).enabled;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private void checkProfileRadio(String profile) {
        suppressProfileCallback = true;
        int id = R.id.rbVisa;
        if (PROFILE_MASTERCARD.equals(profile)) id = R.id.rbMastercard;
        else if (PROFILE_BASIC.equals(profile)) id = R.id.rbBasic;
        RadioButton rb = findViewById(id);
        if (rb != null) rb.setChecked(true);
        suppressProfileCallback = false;
    }

    private void applyProfile(String profile) {
        PackageManager pm = getPackageManager();
        setServiceEnabled(pm, HceCcEmulationServiceVisa.class, PROFILE_VISA.equals(profile));
        setServiceEnabled(pm, HceCcEmulationServiceMastercard.class, PROFILE_MASTERCARD.equals(profile));
        setServiceEnabled(pm, HceCcEmulationServiceBasic.class, PROFILE_BASIC.equals(profile));
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY_PROFILE, profile).apply();
        showAToast(this, "Profile: " + profile + " - re-check Tap and Pay default");
        appendMessageToLog("profile switched", profile);
    }

    private void setServiceEnabled(PackageManager pm, Class<?> serviceClass, boolean enabled) {
        pm.setComponentEnabledSetting(new ComponentName(this, serviceClass),
                enabled ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
    }

    private void appendMessageToLog(String message, String data) {
        hceServiceLog += message + " | " + data + "\n";
        tvHceServiceLog.setText(hceServiceLog);
    }

    private void showAToast(Context context, String message) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
    }

    private final BroadcastReceiver mMessageReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            // Get extra data included in the Intent
            String message = intent.getStringExtra("Message");
            String data = intent.getStringExtra("Data");
            appendMessageToLog(message, data);
        }
    };

}
