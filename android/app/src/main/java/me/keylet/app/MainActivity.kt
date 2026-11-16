package me.keylet.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import me.keylet.app.data.BiometricKeyStore
import me.keylet.app.data.DecryptedCipher
import me.keylet.app.data.VaultAuthState
import me.keylet.app.data.VaultRepository
import me.keylet.app.ui.CipherDetailScreen
import me.keylet.app.ui.CipherFormScreen
import me.keylet.app.ui.GeneratorScreen
import me.keylet.app.ui.KeyletTheme
import me.keylet.app.ui.LockScreen
import me.keylet.app.ui.LoginScreen
import me.keylet.app.ui.SettingsScreen
import me.keylet.app.ui.VaultScreen
import javax.crypto.Cipher

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val repo = VaultRepository.get(this)

        setContent {
            KeyletTheme {
                val state by repo.state.collectAsState()
                val scope = rememberCoroutineScope()
                var selectedCipher by remember { mutableStateOf<DecryptedCipher?>(null) }
                var subScreen by remember { mutableStateOf("list") }

                fun copyToClipboard(label: String, value: String) {
                    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = ClipData.newPlainText(label, value).apply {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            description.extras = PersistableBundle().apply {
                                putBoolean("android.content.extra.IS_SENSITIVE", true)
                            }
                        }
                    }
                    cm.setPrimaryClip(clip)
                    Toast.makeText(this, "Copied $label", Toast.LENGTH_SHORT).show()
                }

                when {
                    state.authState == VaultAuthState.LOGGED_OUT || subScreen == "add_account" -> {
                        LoginScreen(
                            onCancel = if (state.accounts.isNotEmpty()) {
                                { subScreen = "list" }
                            } else null
                        ) { serverUrl, email, pw, provider, token ->
                            repo.login(serverUrl, email, pw, provider, token)
                            subScreen = "list"
                        }
                    }

                    state.authState == VaultAuthState.LOCKED -> {
                        LockScreen(
                            state = state,
                            onUnlockPassword = { pw -> repo.unlock(pw) },
                            onTriggerBiometric = {
                                val cipher = repo.getBiometricDecryptCipher()
                                if (cipher != null) {
                                    authenticateWithBiometrics("Unlock Keylet", cipher) { unlocked ->
                                        scope.launch { repo.unlockWithBiometricCipher(unlocked) }
                                    }
                                }
                            },
                            onSwitchAccount = { id -> repo.switchAccount(id) },
                            onAddAccount = { subScreen = "add_account" },
                            onLogout = { repo.logout() }
                        )
                    }

                    state.authState == VaultAuthState.UNLOCKED -> {
                        when {
                            subScreen == "generator" -> {
                                GeneratorScreen(
                                    onBack = { subScreen = "list" },
                                    onCopy = ::copyToClipboard
                                )
                            }

                            subScreen == "settings" -> {
                                SettingsScreen(
                                    state = state,
                                    onBack = { subScreen = "list" },
                                    onSync = {
                                        repo.sync()
                                        Toast.makeText(this, "Vault synced", Toast.LENGTH_SHORT).show()
                                    },
                                    onToggleBiometric = { enabled ->
                                        val activeId = state.activeAccountId
                                        if (enabled && activeId != null) {
                                            val cipher = BiometricKeyStore.getEncryptCipher(activeId)
                                            authenticateWithBiometrics("Enable Biometric Unlock", cipher) { authed ->
                                                repo.enableBiometric(authed)
                                            }
                                        } else {
                                            repo.disableBiometric()
                                        }
                                    },
                                    onOpenAutofillSettings = {
                                        val intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).apply {
                                            data = Uri.parse("package:$packageName")
                                        }
                                        startActivity(intent)
                                    },
                                    onSwitchAccount = { id ->
                                        selectedCipher = null
                                        subScreen = "list"
                                        repo.switchAccount(id)
                                    },
                                    onAddAccount = {
                                        selectedCipher = null
                                        subScreen = "add_account"
                                    },
                                    onLock = {
                                        selectedCipher = null
                                        subScreen = "list"
                                        repo.lock()
                                    },
                                    onLogout = {
                                        selectedCipher = null
                                        subScreen = "list"
                                        repo.logout()
                                    }
                                )
                            }

                            subScreen == "create" || subScreen == "edit" -> {
                                CipherFormScreen(
                                    initial = if (subScreen == "edit") selectedCipher else null,
                                    symKey = repo.getSymmetricKeyOrThrow(),
                                    onCancel = { subScreen = "list" },
                                    onSave = { req, id ->
                                        repo.saveCipher(req, id)
                                        selectedCipher = null
                                        subScreen = "list"
                                    }
                                )
                            }

                            selectedCipher != null -> {
                                val current = state.ciphers.firstOrNull { it.id == selectedCipher?.id }
                                    ?: selectedCipher!!
                                CipherDetailScreen(
                                    cipher = current,
                                    onBack = { selectedCipher = null },
                                    onEdit = { subScreen = "edit" },
                                    onDelete = {
                                        repo.deleteCipher(current.id)
                                        selectedCipher = null
                                    },
                                    onCopy = ::copyToClipboard
                                )
                            }

                            else -> {
                                VaultScreen(
                                    state = state,
                                    onSelectCipher = { selectedCipher = it },
                                    onCopySecret = ::copyToClipboard,
                                    onCreateNew = {
                                        selectedCipher = null
                                        subScreen = "create"
                                    },
                                    onOpenGenerator = { subScreen = "generator" },
                                    onOpenSettings = { subScreen = "settings" },
                                    onLock = { repo.lock() }
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    private fun authenticateWithBiometrics(
        title: String,
        cipher: Cipher,
        onSuccess: (Cipher) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    result.cryptoObject?.cipher?.let(onSuccess)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    Toast.makeText(this@MainActivity, errString, Toast.LENGTH_SHORT).show()
                }
            }
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setNegativeButtonText("Cancel")
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }
}
