package com.amurcanov.tgwsproxy

import android.Manifest
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.compose.animation.*
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.shape.GenericShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.input.pointer.pointerInput

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.luminance

import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.amurcanov.tgwsproxy.ui.AppUpdateDialog
import com.amurcanov.tgwsproxy.ui.ConnectionTab
import com.amurcanov.tgwsproxy.ui.FloatingToolbar
import com.amurcanov.tgwsproxy.ui.InfoTab
import com.amurcanov.tgwsproxy.ui.LogsTab
import com.amurcanov.tgwsproxy.ui.SettingsTab
import com.amurcanov.tgwsproxy.ui.TgWsProxyTheme
import com.amurcanov.tgwsproxy.ui.openUrlInBrowser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

import java.util.Locale

class MainActivity : ComponentActivity() {

    override fun attachBaseContext(newBase: Context) {
        val prefs = newBase.getSharedPreferences("lang_prefs", Context.MODE_PRIVATE)
        val lang = prefs.getString("app_language", "ru") ?: "ru"
        val locale = Locale(lang)
        Locale.setDefault(locale)
        val config = android.content.res.Configuration(newBase.resources.configuration)
        config.setLocale(locale)
        super.attachBaseContext(newBase.createConfigurationContext(config))
    }

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        
        androidx.core.view.WindowCompat.setDecorFitsSystemWindows(window, false)

        setContent {
            val context = LocalContext.current
            val settingsStore = remember { SettingsStore(context) }
            val themeMode by settingsStore.themeMode
                .collectAsStateWithLifecycle(initialValue = "system")
            val isDynamicColor by settingsStore.isDynamicColor
                .collectAsStateWithLifecycle(initialValue = true)
            val themePalette by settingsStore.themePalette
                .collectAsStateWithLifecycle(initialValue = "indigo")
            val scope = rememberCoroutineScope()

            LaunchedEffect(settingsStore) {
                settingsStore.migrateLegacyDefaults()
            }

            TgWsProxyTheme(themeMode = themeMode, dynamicColor = isDynamicColor, themePalette = themePalette) {
                androidx.compose.runtime.CompositionLocalProvider(
                    androidx.compose.ui.platform.LocalDensity provides androidx.compose.ui.unit.Density(
                        density = androidx.compose.ui.platform.LocalDensity.current.density,
                        fontScale = 1f
                    )
                ) {
                    Box(modifier = Modifier.fillMaxSize()) {
                        AppBackdrop(modifier = Modifier.matchParentSize())

                        Surface(
                            modifier = Modifier.fillMaxSize(),
                            color = Color.Transparent
                        ) {
                            Box {
                                MainContent(settingsStore)

                                FloatingToolbar(
                                    currentTheme = themeMode,
                                    onThemeChange = { mode ->
                                        scope.launch { settingsStore.saveThemeMode(mode) }
                                    },
                                    isDynamicColor = isDynamicColor,
                                    onDynamicColorChange = { dc ->
                                        scope.launch { settingsStore.saveDynamicColor(dc) }
                                    },
                                    currentPalette = themePalette,
                                    onPaletteChange = { pal ->
                                        scope.launch { settingsStore.saveThemePalette(pal) }
                                    }
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

private data class NavItem(
    val label: String,
    val iconRes: androidx.compose.ui.graphics.vector.ImageVector
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainContent(settingsStore: SettingsStore) {
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var dragTargetIndex by remember { mutableIntStateOf(-1) }
    var dragProgress by remember { mutableFloatStateOf(0f) }
    val context = LocalContext.current
    val density = LocalDensity.current
    val scope = rememberCoroutineScope()
    val updatePostponeUntil by settingsStore.updatePostponeUntil.collectAsStateWithLifecycle(initialValue = 0L)
    val updatePostponeVersion by settingsStore.updatePostponeVersion.collectAsStateWithLifecycle(initialValue = "")
    val updateCheckIntervalHours by settingsStore.updateCheckIntervalHours.collectAsStateWithLifecycle(
        initialValue = UPDATE_CHECK_NEVER
    )
    val updateLastCheckAt by settingsStore.updateLastCheckAt.collectAsStateWithLifecycle(initialValue = 0L)
    var pendingRelease by remember { mutableStateOf<AppReleaseInfo?>(null) }
    val currentVersion = remember { "v${BuildConfig.VERSION_NAME.removePrefix("v")}" }
    val currentUpdatePostponeUntil by rememberUpdatedState(updatePostponeUntil)
    val currentUpdatePostponeVersion by rememberUpdatedState(updatePostponeVersion)
    val navItems = listOf(
        NavItem(stringResource(R.string.nav_proxy), Icons.Default.PowerSettingsNew),
        NavItem(stringResource(R.string.settings), Icons.Default.Settings),
        NavItem(stringResource(R.string.nav_logs), Icons.Default.Terminal),
        NavItem(stringResource(R.string.info), Icons.Default.Info)
    )
    val safeBottomInset = with(density) { WindowInsets.safeDrawing.getBottom(density).toDp() }
    val navOverlayReserve = safeBottomInset + 96.dp


    LaunchedEffect(updateCheckIntervalHours, updateLastCheckAt) {
        if (updateCheckIntervalHours == UPDATE_CHECK_NEVER) return@LaunchedEffect

        val intervalMillis = updateIntervalHoursToMillis(updateCheckIntervalHours)
            ?: updateIntervalHoursToMillis(DEFAULT_UPDATE_CHECK_INTERVAL_HOURS)
            ?: 12L * 60L * 60L * 1000L

        if (updateLastCheckAt > 0L) {
            val nextCheckAt = updateLastCheckAt + intervalMillis
            val now = System.currentTimeMillis()
            if (nextCheckAt > now) {
                delay(nextCheckAt - now)
            }
        }

        if (!isActive) return@LaunchedEffect

        val checkedAt = System.currentTimeMillis()
        val release = fetchLatestReleaseInfo(currentVersion)
        settingsStore.saveUpdateState(
            lastCheckAt = checkedAt,
            latestVersion = release?.versionTag ?: "",
            error = if (release == null) context.getString(R.string.update_check_failed_short) else ""
        )

        if (release == null) {
            Log.w("TgWsProxy", "[WARN] Update check: no release info, local=$currentVersion")
        } else {
            val hasUpdate = isNewerVersion(currentVersion, release.versionTag)
            val isPostponed =
                currentUpdatePostponeVersion == release.versionTag && checkedAt < currentUpdatePostponeUntil
            Log.i(
                "TgWsProxy",
                "Update check: local=$currentVersion remote=${release.versionTag} newer=$hasUpdate postponed=$isPostponed"
            )

            if (hasUpdate && !isPostponed) {
                settingsStore.saveUpdateDialogShown(release.versionTag, checkedAt)
                pendingRelease = release
            }
        }
    }

    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Top),
        containerColor = Color.Transparent,
    ) { padding ->
        Box(modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .consumeWindowInsets(padding)
            .pointerInput(selectedTab) {
                var totalDrag = 0f
                detectHorizontalDragGestures(
                    onDragStart = {
                        totalDrag = 0f
                        dragTargetIndex = -1
                        dragProgress = 0f
                    },
                    onDragCancel = {
                        dragTargetIndex = -1
                        dragProgress = 0f
                    },
                    onDragEnd = {
                        if (dragTargetIndex in navItems.indices && dragProgress >= 0.5f) {
                            selectedTab = dragTargetIndex
                        }
                        dragTargetIndex = -1
                        dragProgress = 0f
                    }
                ) { change, dragAmount ->
                    change.consume()
                    totalDrag += dragAmount
                    if (abs(totalDrag) < 12f) {
                        dragTargetIndex = -1
                        dragProgress = 0f
                        return@detectHorizontalDragGestures
                    }

                    val candidate = if (totalDrag < 0f) selectedTab + 1 else selectedTab - 1
                    if (candidate !in navItems.indices) {
                        dragTargetIndex = -1
                        dragProgress = 0f
                        return@detectHorizontalDragGestures
                    }

                    dragTargetIndex = candidate
                    dragProgress = (abs(totalDrag) / 180f).coerceIn(0f, 1f)
                }
            }
        ) {
            AnimatedContent(
                targetState = selectedTab,
                transitionSpec = {
                    fadeIn(tween(300)) togetherWith fadeOut(tween(225))
                },
                modifier = Modifier
                    .fillMaxSize()
                    .padding(bottom = navOverlayReserve),
                label = "tab_content"
            ) { page ->
                when (page) {
                    0 -> ConnectionTab(settingsStore)
                    1 -> SettingsTab(settingsStore)
                    2 -> LogsTab(settingsStore)
                    3 -> InfoTab(settingsStore)
                }
            }

            ProxyNavigationBar(
                navItems = navItems,
                selectedTab = selectedTab,
                dragTargetIndex = dragTargetIndex,
                dragProgress = dragProgress,
                onTabSelected = { index ->
                    selectedTab = index
                    dragTargetIndex = -1
                    dragProgress = 0f
                },
                modifier = Modifier.align(Alignment.BottomCenter)
            )
        }
    }

    pendingRelease?.let { release ->
        AppUpdateDialog(
            release = release,
            onPostpone = {
                pendingRelease = null
                Toast.makeText(context, context.getString(R.string.update_postponed_24h), Toast.LENGTH_SHORT).show()
                scope.launch {
                    val now = System.currentTimeMillis()
                    settingsStore.saveUpdatePostpone(
                        version = release.versionTag,
                        until = now + 24L * 60L * 60L * 1000L
                    )
                    settingsStore.saveUpdateDialogAction(
                        version = release.versionTag,
                        action = UPDATE_DIALOG_ACTION_POSTPONED,
                        actedAt = now
                    )
                }
            },
            onUpdate = {
                pendingRelease = null
                scope.launch {
                    settingsStore.saveUpdateDialogAction(
                        version = release.versionTag,
                        action = UPDATE_DIALOG_ACTION_UPDATE,
                        actedAt = System.currentTimeMillis()
                    )
                    openUrlInBrowser(context, release.releaseUrl)
                }
            }
        )
    }
}

@Composable
private fun ProxyNavigationBar(
    navItems: List<NavItem>,
    selectedTab: Int,
    dragTargetIndex: Int,
    dragProgress: Float,
    onTabSelected: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f
    val selectedColor = colors.primary
    val unselectedColor = colors.onSurfaceVariant.copy(alpha = 0.55f)
    val shellColor = if (isDark) {
        colors.surface.copy(alpha = 0.78f)
    } else {
        lerp(colors.surface, colors.surfaceVariant, 0.48f).copy(alpha = 0.95f)
    }
    val shellBorder = if (isDark) {
        colors.outlineVariant.copy(alpha = 0.42f)
    } else {
        colors.outline.copy(alpha = 0.16f)
    }
    val indicatorColor = if (isDark) {
        colors.primaryContainer.copy(alpha = 0.84f)
    } else {
        lerp(colors.primaryContainer, colors.surface, 0.18f).copy(alpha = 0.97f)
    }
    val indicatorIndex = remember { Animatable(selectedTab.toFloat()) }
    val dragVisualIndex = indicatorIndex.value

    LaunchedEffect(selectedTab) {
        if (dragTargetIndex !in navItems.indices) {
            indicatorIndex.animateTo(
                targetValue = selectedTab.toFloat(),
                animationSpec = tween(
                    durationMillis = 720,
                    easing = CubicBezierEasing(0.2f, 0.9f, 0.24f, 1f)
                )
            )
        }
    }

    LaunchedEffect(selectedTab, dragTargetIndex, dragProgress) {
        if (dragTargetIndex in navItems.indices) {
            val target = selectedTab.toFloat() + (dragTargetIndex - selectedTab) * dragProgress
            indicatorIndex.snapTo(target)
        }
    }

    BoxWithConstraints(
        modifier = modifier
            .fillMaxWidth()
            .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom))
            .padding(horizontal = 22.dp, vertical = 12.dp)
    ) {
        val trackPadding = 8.dp
        val itemWidth = (maxWidth - trackPadding * 2) / navItems.size
        val indicatorOffset = trackPadding + itemWidth * dragVisualIndex

        Surface(
            shape = RoundedCornerShape(28.dp),
            color = shellColor,
            border = BorderStroke(1.dp, shellBorder),
            tonalElevation = 0.dp,
            shadowElevation = if (isDark) 10.dp else 8.dp,
            modifier = Modifier.fillMaxWidth()
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(72.dp)
            ) {
                Surface(
                    shape = RoundedCornerShape(22.dp),
                    color = indicatorColor,
                    modifier = Modifier
                        .offset(x = indicatorOffset)
                        .padding(vertical = 6.dp)
                        .width(itemWidth)
                        .fillMaxHeight()
                ) {}

                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = trackPadding, vertical = 6.dp)
                ) {
                    navItems.forEachIndexed { index, item ->
                        val emphasis = (1f - abs(index - dragVisualIndex)).coerceIn(0f, 1f)
                        val iconColor = lerp(unselectedColor, selectedColor, emphasis)

                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxHeight()
                                .clip(RoundedCornerShape(22.dp))
                                .clickable { onTabSelected(index) },
                            verticalArrangement = Arrangement.Center,
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Icon(
                                imageVector = item.iconRes,
                                contentDescription = item.label,
                                modifier = Modifier.size(22.dp),
                                tint = iconColor
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = item.label,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = if (emphasis > 0.55f) FontWeight.SemiBold else FontWeight.Medium,
                                color = iconColor,
                                maxLines = 1
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun android16OrbShape(points: Int, innerRatio: Float): Shape = GenericShape { size, _ ->
    val centerX = size.width / 2f
    val centerY = size.height / 2f
    val outerRadius = min(size.width, size.height) / 2f
    val innerRadius = outerRadius * innerRatio

    for (i in 0 until points * 2) {
        val angle = (-PI / 2.0) + (i * PI / points)
        val radius = if (i % 2 == 0) outerRadius else innerRadius
        val x = centerX + (radius * cos(angle)).toFloat()
        val y = centerY + (radius * sin(angle)).toFloat()
        if (i == 0) moveTo(x, y) else lineTo(x, y)
    }
    close()
}

private val Android16OrbLarge: Shape = android16OrbShape(points = 18, innerRatio = 0.90f)
private val Android16OrbMedium: Shape = android16OrbShape(points = 20, innerRatio = 0.92f)
private val Android16OrbSmall: Shape = android16OrbShape(points = 16, innerRatio = 0.88f)

@Composable
private fun AppBackdrop(modifier: Modifier = Modifier) {
    val colors = MaterialTheme.colorScheme
    val isDark = colors.background.luminance() < 0.22f
    val baseBrush = remember(colors.background, colors.surface, colors.surfaceVariant) {
        Brush.verticalGradient(
            colors = if (isDark) {
                listOf(
                    lerp(colors.background, colors.surface, 0.42f),
                    colors.background,
                    lerp(colors.surfaceVariant, colors.background, 0.35f)
                )
            } else {
                listOf(
                    lerp(colors.background, colors.surface, 0.78f),
                    colors.background,
                    lerp(colors.surfaceVariant, colors.background, 0.30f)
                )
            }
        )
    }
    val topGlow = colors.primary.copy(alpha = if (isDark) 0.16f else 0.09f)
    val leftGlow = if (isDark) {
        colors.tertiary.copy(alpha = 0.11f)
    } else {
        lerp(colors.tertiary, colors.secondaryContainer, 0.74f).copy(alpha = 0.24f)
    }
    val bottomGlow = if (isDark) {
        colors.primary.copy(alpha = 0.10f)
    } else {
        lerp(colors.secondary, colors.primaryContainer, 0.70f).copy(alpha = 0.22f)
    }
    val lightOrbOutline = colors.outlineVariant.copy(alpha = 0.26f)
    val topOrbGlow = if (isDark) {
        topGlow
    } else {
        lerp(colors.primary, colors.primaryContainer, 0.72f).copy(alpha = 0.32f)
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(baseBrush)
    ) {
        Box(
            modifier = Modifier
                .align(Alignment.TopStart)
                .offset(x = (-86).dp, y = (-126).dp)
                .size(258.dp)
                .clip(Android16OrbLarge)
                .background(topOrbGlow)
                .then(
                    if (isDark) Modifier else Modifier.border(1.dp, lightOrbOutline, Android16OrbLarge)
                )
        )
        Box(
            modifier = Modifier
                .align(Alignment.CenterStart)
                .offset(x = (-44).dp, y = 28.dp)
                .size(146.dp)
                .clip(Android16OrbSmall)
                .background(leftGlow)
                .then(
                    if (isDark) Modifier else Modifier.border(1.dp, lightOrbOutline.copy(alpha = 0.22f), Android16OrbSmall)
                )
        )
        Box(
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .offset(x = 62.dp, y = (-208).dp)
                .size(198.dp)
                .clip(Android16OrbMedium)
                .background(bottomGlow)
                .then(
                    if (isDark) Modifier else Modifier.border(1.dp, lightOrbOutline.copy(alpha = 0.20f), Android16OrbMedium)
                )
        )
    }
}
