package me.keylet.app.autofill

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import me.keylet.app.data.VaultAuthState
import me.keylet.app.data.VaultRepository

class KeyletAutofillService : AutofillService() {

    private data class ParsedFields(
        var usernameId: AutofillId? = null,
        var passwordId: AutofillId? = null,
        var webDomain: String? = null
    )

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val repo = VaultRepository.get(this)
        val state = repo.state.value
        if (state.authState != VaultAuthState.UNLOCKED) {
            callback.onSuccess(null)
            return
        }

        val context = request.fillContexts.lastOrNull() ?: run {
            callback.onSuccess(null)
            return
        }
        val structure = context.structure
        val parsed = ParsedFields()
        val packageName = structure.activityComponent?.packageName

        for (i in 0 until structure.windowNodeCount) {
            traverseNode(structure.getWindowNodeAt(i).rootViewNode, parsed)
        }

        if (parsed.usernameId == null && parsed.passwordId == null) {
            callback.onSuccess(null)
            return
        }

        val matches = repo.findMatchesForAutofill(packageName, parsed.webDomain)
        if (matches.isEmpty()) {
            callback.onSuccess(null)
            return
        }

        val responseBuilder = FillResponse.Builder()
        for (cipher in matches.take(5)) {
            val presentation = RemoteViews(this.packageName, android.R.layout.simple_list_item_2).apply {
                setTextViewText(android.R.id.text1, cipher.name)
                setTextViewText(android.R.id.text2, cipher.username ?: "Keylet")
            }
            val datasetBuilder = Dataset.Builder(presentation)
            var hasField = false
            parsed.usernameId?.let { id ->
                cipher.username?.let { u ->
                    datasetBuilder.setValue(id, AutofillValue.forText(u))
                    hasField = true
                }
            }
            parsed.passwordId?.let { id ->
                cipher.password?.let { p ->
                    datasetBuilder.setValue(id, AutofillValue.forText(p))
                    hasField = true
                }
            }
            if (hasField) {
                responseBuilder.addDataset(datasetBuilder.build())
            }
        }
        callback.onSuccess(responseBuilder.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onSuccess()
    }

    private fun traverseNode(node: AssistStructure.ViewNode, out: ParsedFields) {
        if (!node.webDomain.isNullOrBlank() && out.webDomain == null) {
            out.webDomain = node.webDomain
        }

        val id = node.autofillId
        if (id != null && node.autofillType == View.AUTOFILL_TYPE_TEXT) {
            val hints = node.autofillHints.orEmpty().map { it.lowercase() }
            val inputType = node.inputType
            val isPassword = hints.any { it.contains("password") } ||
                (inputType and InputType.TYPE_MASK_VARIATION) == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                (inputType and InputType.TYPE_MASK_VARIATION) == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
            val isUsername = hints.any {
                it.contains("username") || it.contains("email") || it == "phone"
            } || (inputType and InputType.TYPE_MASK_VARIATION) == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
                (inputType and InputType.TYPE_MASK_VARIATION) == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS

            if (isPassword && out.passwordId == null) {
                out.passwordId = id
            } else if (isUsername && out.usernameId == null) {
                out.usernameId = id
            }
        }

        for (i in 0 until node.childCount) {
            traverseNode(node.getChildAt(i), out)
        }
    }
}
