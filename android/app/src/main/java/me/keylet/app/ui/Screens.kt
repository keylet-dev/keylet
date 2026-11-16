package me.keylet.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import me.keylet.app.crypto.KeyletCrypto
import me.keylet.app.crypto.PasswordGenerator
import me.keylet.app.crypto.PasswordOptions
import me.keylet.app.crypto.SymmetricKey
import me.keylet.app.crypto.TotpGenerator
import me.keylet.app.crypto.TotpResult
import me.keylet.app.data.CipherType
import me.keylet.app.data.CreateCipherRequest
import me.keylet.app.data.DecryptedCipher
import me.keylet.app.data.EncryptedCard
import me.keylet.app.data.EncryptedLogin
import me.keylet.app.data.EncryptedSecureNote
import me.keylet.app.data.EncryptedUri
import me.keylet.app.data.TwoFactorRequiredException
import me.keylet.app.data.VaultUiState

@Composable
fun LoginScreen(
    onLogin: suspend (serverUrl: String, email: String, password: String, twoFactorProvider: Int?, twoFactorToken: String?) -> Unit
) {
    val scope = rememberCoroutineScope()
    var preset by remember { mutableStateOf("us") }
    var customUrl by remember { mutableStateOf("https://") }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var twoFactorProviders by remember { mutableStateOf<List<Int>?>(null) }
    var twoFactorToken by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val serverUrl = when (preset) {
        "us" -> "https://vault.bitwarden.com"
        "eu" -> "https://vault.bitwarden.eu"
        else -> customUrl
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(KeyletColors.BgBase)
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Spacer(Modifier.height(16.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(KeyletColors.Accent.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(Icons.Default.Key, contentDescription = null, tint = KeyletColors.Accent)
            }
            Spacer(Modifier.width(12.dp))
            Column {
                Text("Keylet", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = KeyletColors.TextPrimary)
                Text("Connect to Bitwarden or Vaultwarden", fontSize = 12.sp, color = KeyletColors.TextSecondary)
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("us" to "bitwarden.com", "eu" to "bitwarden.eu", "custom" to "Self-hosted").forEach { (id, label) ->
                FilterChip(
                    selected = preset == id,
                    onClick = { preset = id },
                    label = { Text(label, fontSize = 12.sp) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = KeyletColors.BgActive,
                        selectedLabelColor = KeyletColors.TextPrimary
                    )
                )
            }
        }

        if (preset == "custom") {
            OutlinedTextField(
                value = customUrl,
                onValueChange = { customUrl = it },
                label = { Text("Server URL") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
        }

        OutlinedTextField(
            value = email,
            onValueChange = { email = it },
            label = { Text("Email Address") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Master Password") },
            singleLine = true,
            visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                IconButton(onClick = { showPassword = !showPassword }) {
                    Icon(if (showPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility, null)
                }
            },
            modifier = Modifier.fillMaxWidth()
        )

        if (twoFactorProviders != null) {
            OutlinedTextField(
                value = twoFactorToken,
                onValueChange = { twoFactorToken = it },
                label = { Text("2FA Verification Code") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
        }

        if (error != null) {
            Text(error!!, color = KeyletColors.Danger, fontSize = 12.sp)
        }

        Button(
            onClick = {
                if (loading) return@Button
                loading = true
                error = null
                scope.launch {
                    try {
                        onLogin(
                            serverUrl,
                            email,
                            password,
                            twoFactorProviders?.firstOrNull(),
                            twoFactorToken.takeIf { it.isNotBlank() }
                        )
                    } catch (e: TwoFactorRequiredException) {
                        twoFactorProviders = e.providers
                        error = "Enter your two-factor authentication code."
                    } catch (e: Exception) {
                        error = e.message ?: "Login failed"
                    } finally {
                        loading = false
                    }
                }
            },
            enabled = !loading && email.isNotBlank() && password.isNotEmpty(),
            modifier = Modifier.fillMaxWidth().height(48.dp)
        ) {
            if (loading) {
                CircularProgressIndicator(modifier = Modifier.size(18.dp), color = Color.White, strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text("Signing in & Syncing…")
            } else {
                Text("Sign in & Sync Vault")
            }
        }
    }
}

@Composable
fun LockScreen(
    state: VaultUiState,
    onUnlockPassword: suspend (String) -> Unit,
    onTriggerBiometric: () -> Unit,
    onLogout: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(KeyletColors.BgBase)
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier
                .size(52.dp)
                .clip(RoundedCornerShape(14.dp))
                .background(KeyletColors.BgElevated)
                .border(1.dp, KeyletColors.BorderSubtle, RoundedCornerShape(14.dp)),
            contentAlignment = Alignment.Center
        ) {
            Icon(Icons.Default.Lock, null, tint = KeyletColors.Accent)
        }
        Spacer(Modifier.height(12.dp))
        Text("Vault Locked", fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = KeyletColors.TextPrimary)
        Text(state.email.orEmpty(), fontSize = 13.sp, color = KeyletColors.TextSecondary)
        Text(state.serverUrl.orEmpty(), fontSize = 11.sp, color = KeyletColors.TextMuted)
        Spacer(Modifier.height(20.dp))

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Master Password") },
            singleLine = true,
            visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                IconButton(onClick = { showPassword = !showPassword }) {
                    Icon(if (showPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility, null)
                }
            },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(10.dp))

        if (error != null) {
            Text(error!!, color = KeyletColors.Danger, fontSize = 12.sp)
            Spacer(Modifier.height(8.dp))
        }

        Button(
            onClick = {
                if (loading) return@Button
                loading = true
                error = null
                scope.launch {
                    try {
                        onUnlockPassword(password)
                    } catch (e: Exception) {
                        error = e.message ?: "Invalid master password"
                    } finally {
                        loading = false
                    }
                }
            },
            enabled = !loading && password.isNotEmpty(),
            modifier = Modifier.fillMaxWidth().height(48.dp)
        ) {
            Text(if (loading) "Unlocking…" else "Unlock Vault")
        }

        if (state.biometricEnabled) {
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = onTriggerBiometric,
                modifier = Modifier.fillMaxWidth().height(44.dp)
            ) {
                Icon(Icons.Default.Fingerprint, null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Unlock with Biometrics")
            }
        }

        Spacer(Modifier.height(8.dp))
        OutlinedButton(
            onClick = onLogout,
            modifier = Modifier.fillMaxWidth().height(42.dp)
        ) {
            Text("Log Out")
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultScreen(
    state: VaultUiState,
    onSelectCipher: (DecryptedCipher) -> Unit,
    onCopySecret: (label: String, value: String) -> Unit,
    onCreateNew: () -> Unit,
    onOpenGenerator: () -> Unit,
    onOpenSettings: () -> Unit,
    onLock: () -> Unit
) {
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf("all") }

    val filtered = remember(state.ciphers, query, filter) {
        val q = query.trim().lowercase()
        state.ciphers.filter { c ->
            val typeOk = when (filter) {
                "logins" -> c.type == CipherType.LOGIN
                "notes" -> c.type == CipherType.SECURE_NOTE
                "cards" -> c.type == CipherType.CARD
                "favs" -> c.favorite
                else -> true
            }
            if (!typeOk) return@filter false
            if (q.isEmpty()) return@filter true
            val hay = buildString {
                append(c.name).append(' ')
                append(c.username.orEmpty()).append(' ')
                c.uris.forEach { append(it.uri).append(' ') }
                append(c.notes.orEmpty())
            }.lowercase()
            q in hay
        }
    }

    Scaffold(
        containerColor = KeyletColors.BgBase,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(containerColor = KeyletColors.BgBase),
                title = { Text("Keylet", fontWeight = FontWeight.SemiBold, fontSize = 18.sp) },
                actions = {
                    IconButton(onClick = onCreateNew) { Icon(Icons.Default.Add, "New Item") }
                    IconButton(onClick = onOpenGenerator) { Icon(Icons.Default.AutoAwesome, "Generator") }
                    IconButton(onClick = onOpenSettings) { Icon(Icons.Default.Settings, "Settings") }
                    IconButton(onClick = onLock) { Icon(Icons.Default.Lock, "Lock") }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 12.dp)
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("Search vault…") },
                leadingIcon = { Icon(Icons.Default.Search, null) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))

            LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                val tabs = listOf(
                    "all" to "All",
                    "logins" to "Logins",
                    "notes" to "Notes",
                    "cards" to "Cards",
                    "favs" to "Favs"
                )
                items(tabs) { (id, label) ->
                    FilterChip(
                        selected = filter == id,
                        onClick = { filter = id },
                        label = { Text(label, fontSize = 12.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = KeyletColors.BgActive,
                            selectedLabelColor = KeyletColors.TextPrimary
                        )
                    )
                }
            }
            Spacer(Modifier.height(6.dp))

            if (filtered.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        if (query.isBlank()) "No items in vault" else "No matches for \"$query\"",
                        color = KeyletColors.TextMuted
                    )
                }
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(bottom = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    items(filtered, key = { it.id }) { cipher ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .background(KeyletColors.BgElevated)
                                .clickable { onSelectCipher(cipher) }
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = when (cipher.type) {
                                    CipherType.LOGIN -> Icons.Default.Key
                                    CipherType.CARD -> Icons.Default.CreditCard
                                    CipherType.IDENTITY -> Icons.Default.Person
                                    else -> Icons.Default.Description
                                },
                                contentDescription = null,
                                tint = KeyletColors.TextSecondary,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        cipher.name,
                                        color = KeyletColors.TextPrimary,
                                        fontWeight = FontWeight.Medium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    if (cipher.favorite) {
                                        Spacer(Modifier.width(4.dp))
                                        Icon(Icons.Default.Star, null, tint = KeyletColors.Warning, modifier = Modifier.size(12.dp))
                                    }
                                }
                                val sub = when (cipher.type) {
                                    CipherType.LOGIN -> cipher.username ?: "No username"
                                    CipherType.CARD -> "${cipher.cardBrand ?: "Card"} •••• ${cipher.cardNumber?.takeLast(4) ?: "••••"}"
                                    else -> "Secure Note"
                                }
                                Text(sub, color = KeyletColors.TextSecondary, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            if (cipher.type == CipherType.LOGIN && !cipher.password.isNullOrEmpty()) {
                                IconButton(onClick = { onCopySecret("Password", cipher.password) }) {
                                    Icon(Icons.Default.ContentCopy, "Copy password", tint = KeyletColors.TextSecondary, modifier = Modifier.size(16.dp))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CipherDetailScreen(
    cipher: DecryptedCipher,
    onBack: () -> Unit,
    onEdit: () -> Unit,
    onDelete: suspend () -> Unit,
    onCopy: (String, String) -> Unit
) {
    val scope = rememberCoroutineScope()
    var showPass by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    var totp by remember { mutableStateOf<TotpResult?>(null) }

    LaunchedEffect(cipher.totp) {
        val secret = cipher.totp
        if (secret.isNullOrBlank()) {
            totp = null
            return@LaunchedEffect
        }
        while (true) {
            totp = runCatching { TotpGenerator.generate(secret) }.getOrNull()
            delay(1000)
        }
    }

    Scaffold(
        containerColor = KeyletColors.BgBase,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(containerColor = KeyletColors.BgBase),
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") }
                },
                title = { Text(cipher.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                actions = {
                    IconButton(onClick = onEdit) { Icon(Icons.Default.Edit, "Edit") }
                    IconButton(onClick = { confirmDelete = !confirmDelete }) {
                        Icon(Icons.Default.Delete, "Delete", tint = if (confirmDelete) KeyletColors.Danger else KeyletColors.TextSecondary)
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (confirmDelete) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(KeyletColors.Danger.copy(alpha = 0.15f))
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("Delete this item?", color = KeyletColors.TextPrimary, fontSize = 13.sp)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { confirmDelete = false }) { Text("Cancel") }
                        Button(
                            onClick = { scope.launch { onDelete() } },
                            colors = ButtonDefaults.buttonColors(containerColor = KeyletColors.Danger)
                        ) { Text("Delete") }
                    }
                }
            }

            if (!cipher.username.isNullOrEmpty()) {
                DetailRow("Username", cipher.username) { onCopy("Username", cipher.username) }
            }

            if (!cipher.password.isNullOrEmpty()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(KeyletColors.BgElevated)
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Password", fontSize = 11.sp, color = KeyletColors.TextMuted)
                        Text(
                            if (showPass) cipher.password else "••••••••••••",
                            fontFamily = FontFamily.Monospace,
                            color = KeyletColors.TextPrimary
                        )
                    }
                    IconButton(onClick = { showPass = !showPass }) {
                        Icon(if (showPass) Icons.Default.VisibilityOff else Icons.Default.Visibility, null)
                    }
                    IconButton(onClick = { onCopy("Password", cipher.password) }) {
                        Icon(Icons.Default.ContentCopy, null)
                    }
                }
            }

            totp?.let { t ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(KeyletColors.BgElevated)
                        .clickable { onCopy("TOTP", t.code) }
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text("Verification Code (TOTP)", fontSize = 11.sp, color = KeyletColors.TextMuted)
                        val formatted = if (t.code.length == 6) "${t.code.take(3)} ${t.code.drop(3)}" else t.code
                        Text(formatted, fontSize = 22.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, color = KeyletColors.Accent)
                    }
                    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(34.dp)) {
                        val sweep = 360f * (t.remainingSeconds.toFloat() / t.period.toFloat())
                        Canvas(modifier = Modifier.fillMaxSize()) {
                            drawArc(Color.White.copy(alpha = 0.1f), 0f, 360f, false, style = Stroke(width = 6f))
                            drawArc(
                                color = if (t.remainingSeconds <= 5) KeyletColors.Warning else KeyletColors.Accent,
                                startAngle = -90f,
                                sweepAngle = sweep,
                                useCenter = false,
                                style = Stroke(width = 6f, cap = StrokeCap.Round)
                            )
                        }
                        Text("${t.remainingSeconds}", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = KeyletColors.TextSecondary)
                    }
                }
            }

            cipher.uris.forEachIndexed { idx, u ->
                DetailRow("Website ${idx + 1}", u.uri) { onCopy("URL", u.uri) }
            }

            if (!cipher.cardNumber.isNullOrEmpty()) {
                DetailRow("Card Number", cipher.cardNumber) { onCopy("Card Number", cipher.cardNumber) }
            }

            if (!cipher.notes.isNullOrEmpty()) {
                DetailRow("Notes", cipher.notes) { onCopy("Notes", cipher.notes) }
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String, onCopy: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(KeyletColors.BgElevated)
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, fontSize = 11.sp, color = KeyletColors.TextMuted)
            Text(value, color = KeyletColors.TextPrimary, fontSize = 13.sp)
        }
        IconButton(onClick = onCopy) {
            Icon(Icons.Default.ContentCopy, null, tint = KeyletColors.TextSecondary, modifier = Modifier.size(16.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CipherFormScreen(
    initial: DecryptedCipher?,
    symKey: SymmetricKey,
    onCancel: () -> Unit,
    onSave: suspend (CreateCipherRequest, String?) -> Unit
) {
    val scope = rememberCoroutineScope()
    var type by remember { mutableIntStateOf(initial?.type ?: CipherType.LOGIN) }
    var name by remember { mutableStateOf(initial?.name.orEmpty()) }
    var username by remember { mutableStateOf(initial?.username.orEmpty()) }
    var password by remember { mutableStateOf(initial?.password.orEmpty()) }
    var uri by remember { mutableStateOf(initial?.uris?.firstOrNull()?.uri.orEmpty()) }
    var totp by remember { mutableStateOf(initial?.totp.orEmpty()) }
    var cardNumber by remember { mutableStateOf(initial?.cardNumber.orEmpty()) }
    var notes by remember { mutableStateOf(initial?.notes.orEmpty()) }
    var favorite by remember { mutableStateOf(initial?.favorite ?: false) }
    var saving by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    Scaffold(
        containerColor = KeyletColors.BgBase,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(containerColor = KeyletColors.BgBase),
                navigationIcon = { IconButton(onClick = onCancel) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Cancel") } },
                title = { Text(if (initial == null) "New Item" else "Edit Item") }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            if (initial == null) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(CipherType.LOGIN to "Login", CipherType.SECURE_NOTE to "Note", CipherType.CARD to "Card").forEach { (t, label) ->
                        FilterChip(
                            selected = type == t,
                            onClick = { type = t },
                            label = { Text(label) }
                        )
                    }
                }
            }

            OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())

            if (type == CipherType.LOGIN) {
                OutlinedTextField(value = username, onValueChange = { username = it }, label = { Text("Username") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Password") },
                    singleLine = true,
                    trailingIcon = {
                        IconButton(onClick = { password = PasswordGenerator.generate().first }) {
                            Icon(Icons.Default.AutoAwesome, "Generate")
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(value = uri, onValueChange = { uri = it }, label = { Text("Website / androidapp://...") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = totp, onValueChange = { totp = it }, label = { Text("TOTP Secret") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            } else if (type == CipherType.CARD) {
                OutlinedTextField(value = cardNumber, onValueChange = { cardNumber = it }, label = { Text("Card Number") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            }

            OutlinedTextField(value = notes, onValueChange = { notes = it }, label = { Text("Notes") }, minLines = 3, modifier = Modifier.fillMaxWidth())

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("Favorite", color = KeyletColors.TextPrimary)
                Switch(checked = favorite, onCheckedChange = { favorite = it })
            }

            if (error != null) Text(error!!, color = KeyletColors.Danger, fontSize = 12.sp)

            Button(
                onClick = {
                    if (saving || name.isBlank()) return@Button
                    saving = true
                    error = null
                    scope.launch {
                        try {
                            fun encOpt(s: String): String? =
                                s.trim().takeIf { it.isNotEmpty() }?.let { KeyletCrypto.encryptString(it, symKey) }

                            val req = CreateCipherRequest(
                                type = type,
                                name = KeyletCrypto.encryptString(name.trim(), symKey),
                                notes = encOpt(notes),
                                favorite = favorite,
                                folderId = initial?.folderId,
                                login = if (type == CipherType.LOGIN) {
                                    EncryptedLogin(
                                        username = encOpt(username),
                                        password = password.takeIf { it.isNotEmpty() }?.let { KeyletCrypto.encryptString(it, symKey) },
                                        totp = encOpt(totp),
                                        uris = encOpt(uri)?.let { listOf(EncryptedUri(uri = it)) } ?: emptyList()
                                    )
                                } else null,
                                secureNote = if (type == CipherType.SECURE_NOTE) EncryptedSecureNote(0) else null,
                                card = if (type == CipherType.CARD) EncryptedCard(number = encOpt(cardNumber)) else null
                            )
                            onSave(req, initial?.id)
                        } catch (e: Exception) {
                            error = e.message ?: "Save failed"
                        } finally {
                            saving = false
                        }
                    }
                },
                enabled = !saving && name.isNotBlank(),
                modifier = Modifier.fillMaxWidth().height(48.dp)
            ) {
                Text(if (saving) "Saving…" else "Save Item")
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GeneratorScreen(
    onBack: () -> Unit,
    onCopy: (String, String) -> Unit
) {
    var length by remember { mutableFloatStateOf(20f) }
    var upper by remember { mutableStateOf(true) }
    var lower by remember { mutableStateOf(true) }
    var numbers by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }
    var avoidAmbiguous by remember { mutableStateOf(false) }
    var seed by remember { mutableIntStateOf(0) }

    val (pw, entropy) = remember(length, upper, lower, numbers, symbols, avoidAmbiguous, seed) {
        PasswordGenerator.generate(
            PasswordOptions(length.toInt(), upper, lower, numbers, symbols, avoidAmbiguous)
        )
    }

    Scaffold(
        containerColor = KeyletColors.BgBase,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(containerColor = KeyletColors.BgBase),
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
                title = { Text("Password Generator") }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(KeyletColors.BgElevated)
                    .padding(14.dp)
            ) {
                Text(pw, fontFamily = FontFamily.Monospace, fontSize = 16.sp, color = KeyletColors.TextPrimary)
                Spacer(Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("$entropy bits entropy", color = KeyletColors.Success, fontSize = 12.sp)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { seed++ }) {
                            Icon(Icons.Default.Refresh, null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("New")
                        }
                        Button(onClick = { onCopy("Generated password", pw) }) {
                            Icon(Icons.Default.ContentCopy, null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Copy")
                        }
                    }
                }
            }

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(KeyletColors.BgElevated)
                    .padding(14.dp)
            ) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Length", color = KeyletColors.TextSecondary)
                    Text("${length.toInt()}", fontFamily = FontFamily.Monospace, color = KeyletColors.TextPrimary)
                }
                Slider(
                    value = length,
                    onValueChange = { length = it },
                    valueRange = 8f..64f,
                    colors = SliderDefaults.colors(thumbColor = KeyletColors.Accent, activeTrackColor = KeyletColors.Accent)
                )
            }

            listOf(
                Triple("Uppercase (A-Z)", upper) { v: Boolean -> upper = v },
                Triple("Lowercase (a-z)", lower) { v: Boolean -> lower = v },
                Triple("Numbers (0-9)", numbers) { v: Boolean -> numbers = v },
                Triple("Symbols (!@#...)", symbols) { v: Boolean -> symbols = v },
                Triple("Avoid Ambiguous", avoidAmbiguous) { v: Boolean -> avoidAmbiguous = v }
            ).forEach { (label, checked, onChange) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(KeyletColors.BgElevated)
                        .padding(horizontal = 14.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(label, color = KeyletColors.TextPrimary, fontSize = 14.sp)
                    Switch(checked = checked, onCheckedChange = onChange)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    state: VaultUiState,
    onBack: () -> Unit,
    onSync: suspend () -> Unit,
    onToggleBiometric: (Boolean) -> Unit,
    onOpenAutofillSettings: () -> Unit,
    onLock: () -> Unit,
    onLogout: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var syncing by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = KeyletColors.BgBase,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(containerColor = KeyletColors.BgBase),
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
                title = { Text("Settings") }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(KeyletColors.BgElevated)
                    .padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(state.email.orEmpty(), color = KeyletColors.TextPrimary, fontWeight = FontWeight.Medium)
                Text(state.serverUrl.orEmpty(), color = KeyletColors.TextSecondary, fontSize = 12.sp)
                HorizontalDivider(color = KeyletColors.BorderSubtle)
                Text("${state.ciphers.size} items synced", color = KeyletColors.TextMuted, fontSize = 12.sp)
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(KeyletColors.BgElevated)
                    .padding(horizontal = 14.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("Biometric Unlock", color = KeyletColors.TextPrimary)
                Switch(checked = state.biometricEnabled, onCheckedChange = onToggleBiometric)
            }

            OutlinedButton(onClick = onOpenAutofillSettings, modifier = Modifier.fillMaxWidth()) {
                Text("Enable Android Autofill Service")
            }

            Button(
                onClick = {
                    if (syncing) return@Button
                    syncing = true
                    scope.launch {
                        try { onSync() } finally { syncing = false }
                    }
                },
                enabled = !syncing,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (syncing) "Syncing…" else "Sync Vault Now")
            }

            OutlinedButton(onClick = onLock, modifier = Modifier.fillMaxWidth()) {
                Text("Lock Vault")
            }

            Button(
                onClick = onLogout,
                colors = ButtonDefaults.buttonColors(containerColor = KeyletColors.Danger),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Log Out")
            }
        }
    }
}
