package com.amurcanov.tgwsproxy.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.amurcanov.tgwsproxy.R
import com.amurcanov.tgwsproxy.SettingsStore
import com.amurcanov.tgwsproxy.SupportReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun SupportReportDialog(store: SettingsStore, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var note by remember { mutableStateOf("") }
    var report by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var failed by remember { mutableStateOf(false) }
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(modifier = Modifier.fillMaxWidth(0.94f).heightIn(max = 680.dp), shape = MaterialTheme.shapes.extraLarge) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.support_report), style = MaterialTheme.typography.titleLarge)
                Text(stringResource(R.string.support_report_help), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedTextField(value = note, onValueChange = { note = it.take(2000); report = null },
                    label = { Text(stringResource(R.string.support_description)) },
                    modifier = Modifier.fillMaxWidth(), minLines = 2, maxLines = 4, enabled = !busy)
                TextButton(enabled = !busy, onClick = {
                    busy = true; failed = false
                    scope.launch {
                        try { report = SupportReport.prepare(context, store, note) }
                        catch (_: Exception) { failed = true }
                        finally { busy = false }
                    }
                }) { Text(stringResource(if (busy) R.string.support_preparing else R.string.build_report)) }
                if (failed) Text(stringResource(R.string.support_failed), color = MaterialTheme.colorScheme.error)
                report?.let { text ->
                    Text(stringResource(R.string.support_preview), style = MaterialTheme.typography.titleSmall)
                    SelectionContainer {
                        Text(text, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                            modifier = Modifier.fillMaxWidth().heightIn(max = 240.dp).verticalScroll(rememberScrollState()))
                    }
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = {
                            (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                                .setPrimaryClip(ClipData.newPlainText("TG WS Proxy support report", text))
                        }) { Text(stringResource(R.string.copy)) }
                        TextButton(enabled = !busy, onClick = {
                            busy = true; failed = false
                            scope.launch {
                                try {
                                    val send = withContext(Dispatchers.IO) { SupportReport.shareIntent(context, text) }
                                    context.startActivity(Intent.createChooser(send, context.getString(R.string.support_share)))
                                } catch (_: Exception) { failed = true }
                                finally { busy = false }
                            }
                        }) { Text(stringResource(R.string.support_share)) }
                    }
                }
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) }
            }
        }
    }
}
