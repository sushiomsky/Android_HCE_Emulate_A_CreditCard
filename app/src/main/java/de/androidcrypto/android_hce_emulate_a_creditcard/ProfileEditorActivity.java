package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.util.ArrayList;

/**
 * On-device profile editor for the Imported card: lists the active profile's
 * APDU pairs, and supports edit label/AID, add / edit / delete entries, and
 * save-back with the same validation rules as {@link EmvCardProfile}.
 *
 * <p>The Imported HCE service re-reads the JSON on every tap, so saved edits
 * take effect on the next tap without reinstalling.</p>
 */
public class ProfileEditorActivity extends AppCompatActivity {

    private EmvCardProfile profile;
    private String fileName;
    private LinearLayout entryList;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);

        MaterialToolbar toolbar = new MaterialToolbar(this);
        toolbar.setTitle("Edit imported profile");
        toolbar.setNavigationIcon(androidx.appcompat.R.drawable.abc_ic_ab_back_material);
        toolbar.setNavigationOnClickListener(v -> finish());
        root.addView(toolbar, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        ScrollView scroll = new ScrollView(this);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        body.setPadding(pad, pad, pad, pad);
        scroll.addView(body);
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);

        fileName = CardProfileStore.getActiveFileName(this);
        if (fileName == null) {
            toast("No imported profile active");
            finish();
            return;
        }
        try {
            profile = CardProfileStore.load(this, fileName);
        } catch (Exception e) {
            toast("Cannot load profile: " + e.getMessage());
            finish();
            return;
        }

        TextView meta = new TextView(this);
        meta.setTypeface(android.graphics.Typeface.MONOSPACE);
        body.addView(meta);

        MaterialButton btnMeta = new MaterialButton(this,
                null, com.google.android.material.R.attr.materialButtonOutlinedStyle);
        btnMeta.setText("Edit label / AID");
        btnMeta.setOnClickListener(v -> showMetaDialog(meta));
        body.addView(btnMeta);

        TextView section = new TextView(this);
        section.setText("APDU pairs (" + profile.getEntries().size() + ")");
        section.setTextAppearance(android.R.style.TextAppearance_Medium);
        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        slp.topMargin = pad;
        body.addView(section, slp);

        entryList = new LinearLayout(this);
        entryList.setOrientation(LinearLayout.VERTICAL);
        body.addView(entryList);

        MaterialButton btnAdd = new MaterialButton(this);
        btnAdd.setText("Add APDU pair");
        btnAdd.setOnClickListener(v -> showEntryDialog(-1));
        LinearLayout.LayoutParams alp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        alp.topMargin = pad;
        body.addView(btnAdd, alp);

        refreshMeta(meta);
        refreshList();
    }

    private void refreshMeta(TextView meta) {
        meta.setText("[" + profile.getLabel() + "] " + fileName
                + "\nAID " + profile.getAid()
                + " • " + profile.getEntries().size() + " pairs");
    }

    private void refreshList() {
        entryList.removeAllViews();
        int pad = (int) (8 * getResources().getDisplayMetrics().density);
        for (int i = 0; i < profile.getEntries().size(); i++) {
            final int index = i;
            EmvCardProfile.ApduEntry e = profile.getEntries().get(i);
            MaterialCardView card = new MaterialCardView(this);
            LinearLayout inner = new LinearLayout(this);
            inner.setOrientation(LinearLayout.VERTICAL);
            inner.setPadding(pad, pad, pad, pad);

            TextView title = new TextView(this);
            title.setTypeface(android.graphics.Typeface.MONOSPACE);
            String cmd = e.normalizedCommand();
            String rsp = e.getResponse();
            title.setText((e.isPrefixMatch() ? "[prefix] " : "[exact] ")
                    + shorten(cmd) + "\n→ " + shorten(rsp));
            inner.addView(title);

            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            MaterialButton btnEdit = new MaterialButton(this);
            btnEdit.setText("Edit");
            btnEdit.setOnClickListener(v -> showEntryDialog(index));
            MaterialButton btnDel = new MaterialButton(this,
                    null, com.google.android.material.R.attr.materialButtonOutlinedStyle);
            btnDel.setText("Delete");
            btnDel.setTextColor(getColor(android.R.color.holo_red_dark));
            btnDel.setOnClickListener(v -> confirmDelete(index));
            row.addView(btnEdit);
            row.addView(btnDel);
            inner.addView(row);

            card.addView(inner);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.topMargin = pad / 2;
            entryList.addView(card, lp);
        }
        if (profile.getEntries().isEmpty()) {
            TextView empty = new TextView(this);
            empty.setText("No pairs yet — add the first one below.");
            entryList.addView(empty);
        }
    }

    private static String shorten(String hex) {
        if (hex.length() <= 48) return hex;
        return hex.substring(0, 44) + "…(" + hex.length() / 2 + "B)";
    }

    private void showMetaDialog(TextView metaView) {
        LinearLayout form = dialogForm();
        EditText etLabel = dialogField(form, "Label", profile.getLabel());
        EditText etAid = dialogField(form, "AID hex (5-16 bytes)", profile.getAid());
        new MaterialAlertDialogBuilder(this)
                .setTitle("Label / AID")
                .setView(form)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Save", (d, w) -> {
                    String aidError = EmvCardProfile.validateAid(etAid.getText().toString());
                    if (aidError != null) {
                        toast("AID: " + aidError);
                        return;
                    }
                    profile.setLabel(etLabel.getText().toString().trim());
                    profile.setAid(etAid.getText().toString().trim().toLowerCase(java.util.Locale.US));
                    if (persist()) {
                        refreshMeta(metaView);
                    }
                })
                .show();
    }

    private void showEntryDialog(int index) {
        boolean isNew = index < 0;
        EmvCardProfile.ApduEntry existing =
                isNew ? null : profile.getEntries().get(index);
        LinearLayout form = dialogForm();
        EditText etCmd = dialogField(form, "Command APDU hex",
                isNew ? "" : existing.normalizedCommand());
        EditText etRsp = dialogField(form, "Response hex (no 9000 — SW appended at tap)",
                isNew ? "" : existing.getResponse());
        CheckBox cbPrefix = new CheckBox(this);
        cbPrefix.setText("Prefix match (for GPO 80a8 — PDOL changes each tap)");
        cbPrefix.setChecked(!isNew && existing.isPrefixMatch());
        form.addView(cbPrefix);

        new MaterialAlertDialogBuilder(this)
                .setTitle(isNew ? "Add APDU pair" : "Edit APDU pair")
                .setView(form)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(isNew ? "Add" : "Save", (d, w) -> {
                    String cmd = etCmd.getText().toString().trim();
                    String rsp = etRsp.getText().toString().trim();
                    String error = EmvCardProfile.validateEntry(cmd, rsp);
                    if (error != null) {
                        toast(error);
                        return;
                    }
                    if (isNew) {
                        profile.getEntries().add(new EmvCardProfile.ApduEntry(
                                cmd.toLowerCase(java.util.Locale.US),
                                rsp.toLowerCase(java.util.Locale.US),
                                cbPrefix.isChecked()));
                    } else {
                        existing.setCommand(cmd.toLowerCase(java.util.Locale.US));
                        existing.setResponse(rsp.toLowerCase(java.util.Locale.US));
                        existing.setPrefixMatch(cbPrefix.isChecked());
                    }
                    if (persist()) {
                        refreshList();
                    }
                })
                .show();
    }

    private void confirmDelete(int index) {
        String cmd = profile.getEntries().get(index).normalizedCommand();
        new MaterialAlertDialogBuilder(this)
                .setTitle("Delete pair?")
                .setMessage(shorten(cmd))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Delete", (d, w) -> {
                    // keep a mutable copy: getEntries() may return a fresh list
                    profile.getEntries().remove(index);
                    if (persist()) {
                        refreshList();
                    }
                })
                .show();
    }

    /** Validates (non-empty, GPO kept) and saves; toasts on success/failure. */
    private boolean persist() {
        if (profile.getEntries().isEmpty()) {
            toast("Profile needs at least one APDU pair");
            return false;
        }
        try {
            CardProfileStore.save(this, fileName, profile.toJson());
            toast("Saved (" + profile.getEntries().size() + " pairs) — live on next tap");
            return true;
        } catch (Exception e) {
            toast("Save failed: " + e.getMessage());
            return false;
        }
    }

    private LinearLayout dialogForm() {
        LinearLayout form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        form.setPadding(pad, pad / 2, pad, 0);
        return form;
    }

    private EditText dialogField(ViewGroup form, String hint, String value) {
        EditText et = new EditText(this);
        et.setHint(hint);
        et.setText(value);
        et.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        et.setTypeface(android.graphics.Typeface.MONOSPACE);
        et.setTextSize(13);
        form.addView(et);
        return et;
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }

    /** Entry point used by MainActivity: profile with zero stored files has nothing to edit. */
    public static boolean hasEditableProfile(android.content.Context context) {
        return CardProfileStore.getActiveFileName(context) != null;
    }

    /** Live lookup for unit-test-free callers: entries currently loaded. */
    public ArrayList<String> currentCommands() {
        ArrayList<String> out = new ArrayList<>();
        for (EmvCardProfile.ApduEntry e : profile.getEntries()) {
            out.add(e.normalizedCommand());
        }
        return out;
    }
}
