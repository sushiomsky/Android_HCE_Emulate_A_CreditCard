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
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.widget.Button;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final String PREFS = "hce_cc_prefs";
    private static final String KEY_PROFILE = "profile";
    private static final String SAMPLE_ASSET = "sample_visa_card.json";

    private static final String PROFILE_VISA = "visa";
    private static final String PROFILE_MASTERCARD = "mastercard";
    private static final String PROFILE_BASIC = "basic";
    private static final String PROFILE_IMPORTED = "imported";

    private TextView tvHceServiceLog;
    private TextView tvNfcStatus;
    private TextView tvImportedProfile;
    private RadioGroup rgProfile;
    private String hceServiceLog = "";
    private boolean suppressProfileCallback = false;

    private final ActivityResultLauncher<String[]> importLauncher =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(), this::onCardDocumentPicked);

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
        tvImportedProfile = findViewById(R.id.tvImportedProfile);
        rgProfile = findViewById(R.id.rgProfile);
        Button btnClearLog = findViewById(R.id.btnClearLog);
        Button btnShareLog = findViewById(R.id.btnShareLog);
        Button btnImportCard = findViewById(R.id.btnImportCard);
        Button btnDeleteCard = findViewById(R.id.btnDeleteCard);

        /**
         * Note on this setting: Do NOT remove this setting or the app will fail when the screen goes
         * from portrait to landscape and vice versa. The app will then run the onDestroy() method, but
         * the BroadcastReceiver is not registered yet. The only way to solve this issue would be to
         * use a STATIC BroadcastReceiver.
         */
        this.setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);

        updateNfcStatus();

        // ship a bundled sample card on first start so the Imported profile works out of the box
        CardProfileStore.ensureSampleAsset(this, SAMPLE_ASSET);
        updateImportedLabel();

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
            } else if (checkedId == R.id.rbImported) {
                if (CardProfileStore.list(this).isEmpty()) {
                    showAToast(this, "No card imported yet - pick a JSON file");
                    importLauncher.launch(new String[]{"application/json", "text/plain", "*/*"});
                    checkProfileRadio(getActiveProfile());
                } else {
                    if (CardProfileStore.getActiveFileName(this) == null) {
                        List<String> files = CardProfileStore.list(this);
                        CardProfileStore.setActiveFileName(this, files.get(0));
                        updateImportedLabel();
                    }
                    applyProfile(PROFILE_IMPORTED);
                }
            }
        });

        btnClearLog.setOnClickListener(v -> {
            hceServiceLog = "";
            tvHceServiceLog.setText(getString(R.string.hce_service_log));
        });

        btnShareLog.setOnClickListener(v -> {
            Intent share = new Intent(Intent.ACTION_SEND);
            share.setType("text/plain");
            share.putExtra(Intent.EXTRA_SUBJECT, "HCE session log");
            share.putExtra(Intent.EXTRA_TEXT, hceServiceLog.isEmpty()
                    ? getString(R.string.hce_service_log) : hceServiceLog);
            startActivity(Intent.createChooser(share, getString(R.string.share_log)));
        });

        btnImportCard.setOnClickListener(v ->
                importLauncher.launch(new String[]{"application/json", "text/plain", "*/*"}));

        btnDeleteCard.setOnClickListener(v -> {
            String active = CardProfileStore.getActiveFileName(this);
            if (active == null) {
                showAToast(this, "No imported card to delete");
                return;
            }
            CardProfileStore.delete(this, active);
            updateImportedLabel();
            showAToast(this, "Deleted " + active);
            if (PROFILE_IMPORTED.equals(getActiveProfile())) {
                applyProfile(PROFILE_VISA);
                checkProfileRadio(PROFILE_VISA);
            }
        });
    }

    private void onCardDocumentPicked(Uri uri) {
        if (uri == null) return;
        try (InputStream is = getContentResolver().openInputStream(uri)) {
            if (is == null) {
                showAToast(this, "Cannot read file");
                return;
            }
            byte[] buf = new byte[65536];
            StringBuilder sb = new StringBuilder();
            int n;
            while ((n = is.read(buf)) > 0) {
                sb.append(new String(buf, 0, n, StandardCharsets.UTF_8));
                if (sb.length() > 1024 * 1024) throw new java.io.IOException("file too large");
            }
            String name = uri.getLastPathSegment();
            if (name == null || name.isEmpty()) name = "card";
            String saved = CardProfileStore.save(this, name, sb.toString());
            CardProfileStore.setActiveFileName(this, saved);
            EmvCardProfile profile = CardProfileStore.load(this, saved);
            updateImportedLabel();
            showAToast(this, "Imported [" + profile.getLabel() + "], "
                    + profile.getEntries().size() + " APDUs");
            applyProfile(PROFILE_IMPORTED);
            checkProfileRadio(PROFILE_IMPORTED);
        } catch (Exception e) {
            showAToast(this, "Import failed: " + e.getMessage());
        }
    }

    private void updateImportedLabel() {
        String active = CardProfileStore.getActiveFileName(this);
        List<String> files = CardProfileStore.list(this);
        if (active != null) {
            try {
                EmvCardProfile p = CardProfileStore.load(this, active);
                tvImportedProfile.setText(getString(R.string.imported_profile_label)
                        + ": [" + p.getLabel() + "] " + active
                        + " (" + p.getEntries().size() + " APDUs)");
                return;
            } catch (Exception ignored) {
            }
        }
        tvImportedProfile.setText(getString(R.string.imported_profile_label)
                + ": none (" + files.size() + " stored)");
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
        if (isServiceEnabled(pm, HceCcEmulationServiceImported.class)) return PROFILE_IMPORTED;
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
        else if (PROFILE_IMPORTED.equals(profile)) id = R.id.rbImported;
        RadioButton rb = findViewById(id);
        if (rb != null) rb.setChecked(true);
        suppressProfileCallback = false;
    }

    private void applyProfile(String profile) {
        PackageManager pm = getPackageManager();
        setServiceEnabled(pm, HceCcEmulationServiceVisa.class, PROFILE_VISA.equals(profile));
        setServiceEnabled(pm, HceCcEmulationServiceMastercard.class, PROFILE_MASTERCARD.equals(profile));
        setServiceEnabled(pm, HceCcEmulationServiceBasic.class, PROFILE_BASIC.equals(profile));
        setServiceEnabled(pm, HceCcEmulationServiceImported.class, PROFILE_IMPORTED.equals(profile));
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
