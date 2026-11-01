package com.amurcanov.tgwsproxy.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.amurcanov.tgwsproxy.BuildConfig
import com.amurcanov.tgwsproxy.EngineOptions
import com.amurcanov.tgwsproxy.R
import com.amurcanov.tgwsproxy.SettingsStore
import kotlinx.coroutines.launch

@Composable
fun EngineSettingsSection(store: SettingsStore, running: Boolean, cfEnabled: Boolean) {
    val saved by store.engineOptions.collectAsStateWithLifecycle(initialValue = EngineOptions())
    var raw by rememberSaveable { mutableStateOf<String?>(null) }
    val options = EngineOptions.fromJson(raw ?: saved.toJson())
    val scope = rememberCoroutineScope()
    fun save(value: EngineOptions) {
        raw = value.toJson()
        scope.launch { store.saveEngineOptions(value) }
    }
    AppSectionCard {
        Text(stringResource(R.string.engine_options_title, BuildConfig.UPSTREAM_VERSION), style = MaterialTheme.typography.titleSmall)
        EngineSwitch(stringResource(R.string.engine_h2), options.h2, !running && cfEnabled && !options.noSecure && !options.testDc) { save(options.copy(h2 = it)) }
        if (!cfEnabled || options.noSecure || options.testDc) {
            Text(stringResource(R.string.engine_h2_unavailable), style = MaterialTheme.typography.bodySmall)
        }
        EngineSwitch(stringResource(R.string.engine_no_secure), options.noSecure, !running) { save(options.copy(noSecure = it)) }
        OutlinedTextField(value = options.workers, onValueChange = { save(options.copy(workers = it)) },
            label = { Text(stringResource(R.string.engine_workers)) }, modifier = Modifier.fillMaxWidth(),
            supportingText = { Text(stringResource(R.string.engine_workers_help)) }, enabled = !running)
        OutlinedTextField(value = options.fakeTls, onValueChange = { save(options.copy(fakeTls = it)) },
            label = { Text(stringResource(R.string.engine_fake_tls)) }, modifier = Modifier.fillMaxWidth(),
            supportingText = { Text(stringResource(R.string.engine_fake_tls_help)) }, singleLine = true, enabled = !running)
        if (!options.isValid()) Text(stringResource(R.string.invalid_network_settings), color = MaterialTheme.colorScheme.error)
        var advanced by rememberSaveable { mutableStateOf(false) }
        TextButton(onClick = { advanced = !advanced }) { Text(stringResource(R.string.engine_advanced)) }
        if (advanced) {
            EngineSwitch(stringResource(R.string.engine_test_dc), options.testDc, !running) { save(options.copy(testDc = it)) }
            EngineSwitch(stringResource(R.string.engine_proxy_protocol), options.proxyProtocol, !running) { save(options.copy(proxyProtocol = it)) }
            OutlinedTextField(value = options.bufferKb.toString(), onValueChange = { text -> text.toIntOrNull()?.let { save(options.copy(bufferKb = it)) } },
                label = { Text(stringResource(R.string.engine_buffer_kb)) }, modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), singleLine = true, enabled = !running)
        }
    }
}

@Composable
private fun EngineSwitch(label: String, checked: Boolean, enabled: Boolean, change: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f).padding(end = 12.dp), style = MaterialTheme.typography.bodyMedium)
        Switch(checked = checked, onCheckedChange = change, enabled = enabled)
    }
}
