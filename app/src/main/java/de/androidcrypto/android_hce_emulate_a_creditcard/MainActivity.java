package de.androidcrypto.android_hce_emulate_a_creditcard;

import static de.androidcrypto.android_hce_emulate_a_creditcard.Utils.getTimestampShort;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
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
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.RelativeSizeSpan;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
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

import com.google.android.material.card.MaterialCardView;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final String PREFS = "hce_cc_prefs";
    private static final String KEY_PROFILE = "profile";
    private static final String SAMPLE_ASSET = "sample_visa_card.json";

    private static final String PROFILE_VISA = "visa";
    private static final String PROFILE_MASTERCARD = "mastercard";
    private static final String PROFILE_AMEX = "amex";
    private static final String PROFILE_DISCOVER = "discover";
    private static final String PROFILE_BASIC = "basic";
    private static final String PROFILE_IMPORTED = "imported";

    private static final int MAX_LOG_LINES = 300;

    /**
     * Research-use notice: this app replays EMVCo 3-D Secure test profiles for
     * reader-compatibility lab testing. It holds no real cardholder data and
     * cannot authorize a transaction.
     */
    public static final String RESEARCH_USE_NOTICE =
            "Research fixture only - EMVCo test PANs, no real cardholder data, "
                    + "replayed cryptograms cannot authorize transactions.";

    private TextView tvHceServiceLog;
    private TextView tvNfcStatus;
    private TextView tvActiveProfile;
    private TextView tvImportedProfile;
    private RadioGroup rgProfile;
    private ScrollView scrollMain;
    private MaterialCardView cardImported;
    private CheckBox cbLabLongResponse;
    private CheckBox cbLabAutoSweep;
    private CheckBox cbLabProbe;
    private CheckBox cbStrictAfl;
    private CheckBox cbStrictLength;
    private EditText etLabLen;
    private final ArrayDeque<String> logLines = new ArrayDeque<>();
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
        tvActiveProfile = findViewById(R.id.tvActiveProfile);
        tvImportedProfile = findViewById(R.id.tvImportedProfile);
        rgProfile = findViewById(R.id.rgProfile);
        scrollMain = findViewById(R.id.scrollMain);
        cardImported = findViewById(R.id.cardImported);
        Button btnClearLog = findViewById(R.id.btnClearLog);
        Button btnCopyLog = findViewById(R.id.btnCopyLog);
        Button btnShareLog = findViewById(R.id.btnShareLog);
        Button btnShareTap = findViewById(R.id.btnShareTap);
        Button btnImportCard = findViewById(R.id.btnImportCard);
        Button btnDeleteCard = findViewById(R.id.btnDeleteCard);
        Button btnEditProfile = findViewById(R.id.btnEditProfile);
        cbLabLongResponse = findViewById(R.id.cbLabLongResponse);
        cbLabAutoSweep = findViewById(R.id.cbLabAutoSweep);
        cbLabProbe = findViewById(R.id.cbLabProbe);
        cbStrictAfl = findViewById(R.id.cbStrictAfl);
        cbStrictLength = findViewById(R.id.cbStrictLength);
        etLabLen = findViewById(R.id.etLabLen);

        styleRadio(R.id.rbVisa, getString(R.string.profile_visa), getString(R.string.profile_visa_aid));
        styleRadio(R.id.rbMastercard, getString(R.string.profile_mastercard), getString(R.string.profile_mastercard_aid));
        styleRadio(R.id.rbAmex, getString(R.string.profile_amex), getString(R.string.profile_amex_aid));
        styleRadio(R.id.rbDiscover, getString(R.string.profile_discover), getString(R.string.profile_discover_aid));
        styleRadio(R.id.rbBasic, getString(R.string.profile_basic), getString(R.string.profile_basic_aid));
        styleRadio(R.id.rbImported, getString(R.string.profile_imported), getString(R.string.profile_imported_aid));

        SharedPreferences labPrefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        cbLabLongResponse.setChecked(labPrefs.getBoolean("lab_long_response", false));
        cbLabAutoSweep.setChecked(labPrefs.getBoolean("lab_auto_sweep", false));
        cbLabProbe.setChecked(labPrefs.getBoolean("lab_probe", false));
        int savedLen = labPrefs.getInt("lab_response_len", 512);
        etLabLen.setText(String.valueOf(savedLen));
        cbLabLongResponse.setOnCheckedChangeListener((v, checked) -> {
            int len = parseLabLen(etLabLen.getText().toString(), 512);
            labPrefs.edit().putBoolean("lab_long_response", checked)
                    .putInt("lab_response_len", len).apply();
            showAToast(this, checked
                    ? "Lab long response ON: " + len + " bytes (Basic profile)"
                    : "Lab long response OFF");
            appendMessageToLog("lab long response", checked ? len + " bytes" : "off");
        });
        cbLabAutoSweep.setOnCheckedChangeListener((v, checked) -> {
            labPrefs.edit().putBoolean("lab_auto_sweep", checked).apply();
            if (checked) {
                labPrefs.edit().putInt("lab_sweep_index", 0).apply();
                showAToast(this, "Auto sweep ON: lengths step up on each tap");
                appendMessageToLog("lab auto sweep", "on, 9 steps 256B..64KB");
            } else {
                appendMessageToLog("lab auto sweep", "off");
            }
        });
        cbLabProbe.setOnCheckedChangeListener((v, checked) -> {
            labPrefs.edit().putBoolean("lab_probe", checked).apply();
            if (checked) {
                labPrefs.edit().putInt("lab_probe_index", 0).apply();
                showAToast(this, "Probe mode ON: malformed case per tap");
                appendMessageToLog("lab probes", "on, " + LabProbe.cases().size() + " cases");
            } else {
                appendMessageToLog("lab probes", "off");
            }
        });
        // Reader-policy toggles: read by BaseHceEmulationService on every tap.
        cbStrictAfl.setChecked(labPrefs.getBoolean(BaseHceEmulationService.PREF_STRICT_AFL, false));
        cbStrictLength.setChecked(labPrefs.getBoolean(BaseHceEmulationService.PREF_STRICT_LENGTH, false));
        cbStrictAfl.setOnCheckedChangeListener((v, checked) -> {
            labPrefs.edit().putBoolean(BaseHceEmulationService.PREF_STRICT_AFL, checked).apply();
            showAToast(this, checked
                    ? "Strict AFL ON: out-of-AFL READs declined 6A83"
                    : "Strict AFL OFF: lenient, mismatches only logged");
            appendMessageToLog("strict AFL", checked ? "on (6A83)" : "off (lenient)");
        });
        cbStrictLength.setOnCheckedChangeListener((v, checked) -> {
            labPrefs.edit().putBoolean(BaseHceEmulationService.PREF_STRICT_LENGTH, checked).apply();
            showAToast(this, checked
                    ? "Strict length ON: PDOL/CDOL mismatch declined 6700"
                    : "Strict length OFF: lenient, mismatches only logged");
            appendMessageToLog("strict length", checked ? "on (6700)" : "off (lenient)");
        });

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

        String session = FileLog.newSession(this);
        appendMessageToLog("session file", session);
        appendMessageToLog("notice", RESEARCH_USE_NOTICE);

        // HCE services send via LocalBroadcastManager, so receive the same way on all API levels.
        // (A previous version used Context.registerReceiver on API 33+, which never receives
        // LocalBroadcastManager broadcasts, leaving the log empty on modern phones.)
        LocalBroadcastManager.getInstance(MainActivity.this).registerReceiver(
                mMessageReceiver, new IntentFilter("HceCcEmulatorService"));

        String activeProfile = getActiveProfile();
        checkProfileRadio(activeProfile);
        refreshProfileDependentUi(activeProfile);
        updateActiveProfileLabel(activeProfile);

        rgProfile.setOnCheckedChangeListener((group, checkedId) -> {
            if (suppressProfileCallback) return;
            if (checkedId == R.id.rbVisa) {
                applyProfile(PROFILE_VISA);
            } else if (checkedId == R.id.rbMastercard) {
                applyProfile(PROFILE_MASTERCARD);
            } else if (checkedId == R.id.rbAmex) {
                applyProfile(PROFILE_AMEX);
            } else if (checkedId == R.id.rbDiscover) {
                applyProfile(PROFILE_DISCOVER);
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
            logLines.clear();
            tvHceServiceLog.setText(getString(R.string.log_empty));
        });

        btnCopyLog.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("HCE session log", getLogText()));
                showAToast(this, "Log copied (" + logLines.size() + " lines)");
            }
        });

        btnShareLog.setOnClickListener(v -> {
            Intent share = new Intent(Intent.ACTION_SEND);
            share.setType("text/plain");
            share.putExtra(Intent.EXTRA_SUBJECT, "HCE session log");
            share.putExtra(Intent.EXTRA_TEXT, getLogText());
            startActivity(Intent.createChooser(share, getString(R.string.share_log)));
        });

        btnShareTap.setOnClickListener(v -> {
            String name = TapExport.lastExportName(this);
            if (name == null) {
                showAToast(this, "No tap exported yet — tap a reader first");
                return;
            }
            String body = TapExport.readTap(this, name);
            if (body.isEmpty()) {
                showAToast(this, "Tap file unreadable: " + name);
                return;
            }
            Intent share = new Intent(Intent.ACTION_SEND);
            share.setType("text/plain");
            share.putExtra(Intent.EXTRA_SUBJECT, "HCE tap export " + name);
            share.putExtra(Intent.EXTRA_TEXT, body);
            startActivity(Intent.createChooser(share, getString(R.string.share_tap)));
        });

        btnImportCard.setOnClickListener(v ->
                importLauncher.launch(new String[]{"application/json", "text/plain", "*/*"}));

        btnEditProfile.setOnClickListener(v -> {
            if (!ProfileEditorActivity.hasEditableProfile(this)) {
                showAToast(this, "No imported profile yet — import a JSON first");
                return;
            }
            startActivity(new Intent(this, ProfileEditorActivity.class));
        });

        btnDeleteCard.setOnClickListener(v -> {
            String active = CardProfileStore.getActiveFileName(this);
            if (active == null) {
                showAToast(this, "No imported card to delete");
                return;
            }
            new MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.delete_confirm_title)
                    .setMessage(getString(R.string.delete_confirm_message, active))
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(R.string.delete_card, (d, w) -> {
                        CardProfileStore.delete(this, active);
                        updateImportedLabel();
                        showAToast(this, "Deleted " + active);
                        if (PROFILE_IMPORTED.equals(getActiveProfile())) {
                            applyProfile(PROFILE_VISA);
                            checkProfileRadio(PROFILE_VISA);
                        }
                    })
                    .show();
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
                tvImportedProfile.setText(getString(R.string.imported_active,
                        p.getLabel(), active, p.getEntries().size()));
                return;
            } catch (Exception ignored) {
            }
        }
        tvImportedProfile.setText(getString(R.string.imported_none, files.size()));
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
        if (isServiceEnabled(pm, HceCcEmulationServiceAmex.class)) return PROFILE_AMEX;
        if (isServiceEnabled(pm, HceCcEmulationServiceDiscover.class)) return PROFILE_DISCOVER;
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
        else if (PROFILE_AMEX.equals(profile)) id = R.id.rbAmex;
        else if (PROFILE_DISCOVER.equals(profile)) id = R.id.rbDiscover;
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
        setServiceEnabled(pm, HceCcEmulationServiceAmex.class, PROFILE_AMEX.equals(profile));
        setServiceEnabled(pm, HceCcEmulationServiceDiscover.class, PROFILE_DISCOVER.equals(profile));
        setServiceEnabled(pm, HceCcEmulationServiceBasic.class, PROFILE_BASIC.equals(profile));
        setServiceEnabled(pm, HceCcEmulationServiceImported.class, PROFILE_IMPORTED.equals(profile));
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY_PROFILE, profile).apply();
        showAToast(this, "Profile: " + profile + " - re-check Tap and Pay default");
        appendMessageToLog("profile switched", profile);
        refreshProfileDependentUi(profile);
        updateActiveProfileLabel(profile);
    }

    private void setServiceEnabled(PackageManager pm, Class<?> serviceClass, boolean enabled) {
        pm.setComponentEnabledSetting(new ComponentName(this, serviceClass),
                enabled ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
    }

    private void appendMessageToLog(String message, String data) {
        logLines.addLast(getTimestampShort() + " | " + message + " | " + data);
        while (logLines.size() > MAX_LOG_LINES) logLines.removeFirst();
        tvHceServiceLog.setText(getLogText());
        scrollMain.post(() -> scrollMain.fullScroll(ScrollView.FOCUS_DOWN));
    }

    private String getLogText() {
        if (logLines.isEmpty()) return getString(R.string.log_empty);
        StringBuilder sb = new StringBuilder();
        for (String line : logLines) sb.append(line).append('\n');
        return sb.toString();
    }

    private void updateActiveProfileLabel(String profile) {
        tvActiveProfile.setText(getString(R.string.active_profile, profile));
    }

    /** Import card only makes sense for the Imported profile; lab only for Basic. */
    private void refreshProfileDependentUi(String profile) {
        boolean imported = PROFILE_IMPORTED.equals(profile);
        boolean basic = PROFILE_BASIC.equals(profile);
        cardImported.setEnabled(imported);
        cardImported.setAlpha(imported ? 1f : 0.5f);
        cbLabLongResponse.setEnabled(basic);
        cbLabAutoSweep.setEnabled(basic);
        cbLabProbe.setEnabled(basic);
        etLabLen.setEnabled(basic);
    }

    /** Two-line radio label: name + smaller AID caption. */
    private void styleRadio(int id, String name, String caption) {
        RadioButton rb = findViewById(id);
        if (rb == null) return;
        SpannableStringBuilder sb = new SpannableStringBuilder(name + "\n" + caption);
        sb.setSpan(new RelativeSizeSpan(0.8f), name.length() + 1, sb.length(),
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        rb.setText(sb);
    }

    private void showAToast(Context context, String message) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
    }

    private static int parseLabLen(String text, int fallback) {
        try {
            int len = Integer.parseInt(text.trim());
            if (len < 0) return 0;
            return Math.min(len, LabPayload.MAX_LEN);
        } catch (NumberFormatException e) {
            return fallback;
        }
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
