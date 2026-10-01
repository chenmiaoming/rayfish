package xyz.rayfish.android.ui

import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import xyz.rayfish.android.NodeHolder
import xyz.rayfish.android.R
import xyz.rayfish.android.RayfishVpnService
import xyz.rayfish.android.ui.components.SectionCard
import xyz.rayfish.android.ui.screens.*
import xyz.rayfish.android.ui.theme.Chakra
import xyz.rayfish.android.ui.theme.Rf

enum class Tab(val labelRes: Int, val icon: ImageVector) {
    NETWORKS(R.string.tab_networks, Icons.Filled.Hub),
    HOME(R.string.tab_home, Icons.Filled.Home),
    YOU(R.string.tab_you, Icons.Filled.AccountCircle),
}

@Composable
fun RayfishApp(initialLinkUri: String?, alreadyHandled: (String) -> Boolean, markHandled: (String) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val lifecycleOwner = LocalLifecycleOwner.current

    val screenState = rememberSaveableStateHolder()
    var tab by rememberSaveable { mutableStateOf(Tab.HOME) }
    var detailName by rememberSaveable { mutableStateOf<String?>(null) }
    BackHandler(enabled = detailName != null) { detailName = null }
    var restoringTunnel by remember { mutableStateOf(true) }

    // Null until the check completes, and everything below is composed only once
    // it is true. That ordering is the whole point: every path out of this
    // function starts the node, and the first start mints an identity, so a
    // first-run restore has to be offered in front of all of it. Null rather
    // than a default of false so an existing install never flashes the welcome
    // screen while a file is stat'ed.
    var hasIdentity by remember { mutableStateOf<Boolean?>(null) }
    LaunchedEffect(Unit) {
        hasIdentity = withContext(Dispatchers.IO) {
            // Treating a failure as "has one" keeps a reader that cannot answer
            // from offering to overwrite a key that may well be there.
            runCatching { NodeHolder.get(context).hasIdentity() }.getOrDefault(true)
        }
    }
    if (hasIdentity != true) {
        if (hasIdentity == false) WelcomeScreen(onDone = { hasIdentity = true })
        return
    }

    // Construct the observer only after the identity gate. A first-run restore
    // must remain in front of any operation that could create a new identity.
    val model: RayfishViewModel = viewModel()
    val snapshot by model.state.collectAsStateWithLifecycle()
    val status = snapshot.status
    val starting = restoringTunnel || !snapshot.loaded

    // On launch restore the tunnel only if the user left it enabled; otherwise
    // stay offline. Then poll every 2s while foregrounded; suspend in background.
    LaunchedEffect(Unit) {
        try {
            if (NodeHolder.isEnabled(context)) {
                if (VpnService.prepare(context) == null) {
                    ContextCompat.startForegroundService(
                        context, Intent(context, RayfishVpnService::class.java),
                    )
                } else {
                    // Another app (Tailscale, say) holds the single VpnService slot, so
                    // our saved enable intent is stale: it was set true when we still
                    // had the tunnel, but we can no longer get it back. Clear it now,
                    // the same reasoning onRevoke already uses, so the toggle stops
                    // reading "on" for a tunnel that will never come up, and the You
                    // screen's go-fully-offline control sees the real state instead of
                    // this leftover intent.
                    NodeHolder.setEnabled(context, false)
                    if (!NodeHolder.isGoOfflineWhenDisabled(context)) {
                        ContextCompat.startForegroundService(
                            context,
                            Intent(context, RayfishVpnService::class.java).apply {
                                action = RayfishVpnService.ACTION_STANDBY
                            },
                        )
                    }
                }
            } else if (!NodeHolder.isGoOfflineWhenDisabled(context)) {
                // The VPN is not being restored, and the user has not asked to go
                // fully offline when disabled, so standby is the default: files
                // should keep working. Nothing else brings the control plane up
                // after a process death; bring it up now via standby.
                ContextCompat.startForegroundService(
                    context,
                    Intent(context, RayfishVpnService::class.java).apply {
                        action = RayfishVpnService.ACTION_STANDBY
                    },
                )
            }
            model.refresh()
        } catch (t: Throwable) { snackbar.showSnackbar(context.getString(R.string.error_failed_to_start, t.message.orEmpty())) }
        finally { restoringTunnel = false }
    }
    LaunchedEffect(lifecycleOwner) {
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            while (true) {
                model.refresh()
                delay(2000)
            }
        }
    }

    LaunchedEffect(status?.networks, detailName) {
        if (status != null && detailName != null && status?.networks?.none { it.name == detailName } == true) {
            detailName = null
        }
    }

    fun toast(msg: String) { scope.launch { snackbar.showSnackbar(msg) } }
    fun refreshNow() { model.refresh() }

    // Deep links: unchanged behavior, route to the joined/paired result.
    fun followLink(uri: String) {
        scope.launch {
            try {
                NodeHolder.ensureStarted(context)
                val action = withContext(Dispatchers.IO) { NodeHolder.get(context).handleLink(uri) }
                refreshNow()
                toast(context.messageForLinkAction(action, R.string.toast_paired))
            } catch (t: Throwable) { toast(context.getString(R.string.error_link_failed, t.message.orEmpty())) }
        }
    }
    LaunchedEffect(initialLinkUri) {
        val uri = initialLinkUri
        if (uri != null && !alreadyHandled(uri)) { markHandled(uri); followLink(uri) }
    }
    val pending = xyz.rayfish.android.MainActivity.pendingLinkUri.value
    LaunchedEffect(pending) {
        if (pending != null) { followLink(pending); xyz.rayfish.android.MainActivity.pendingLinkUri.value = null }
    }

    Scaffold(
        containerColor = Rf.Bg,
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            if (detailName == null) {
                NavigationBar(containerColor = Rf.Bg) {
                    Tab.entries.forEach { t ->
                        val label = stringResource(t.labelRes)
                        NavigationBarItem(
                            selected = tab == t,
                            onClick = { tab = t },
                            icon = { Icon(t.icon, contentDescription = label) },
                            label = { Text(label) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = Rf.Rose400, selectedTextColor = Rf.Rose400,
                                unselectedIconColor = Rf.Faint, unselectedTextColor = Rf.Faint,
                                indicatorColor = Rf.Card,
                            ),
                        )
                    }
                }
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding)) {
            if (snapshot.refreshFailed) {
                SectionCard(Modifier.padding(horizontal = 20.dp, vertical = 8.dp)) {
                    Text(stringResource(R.string.error_status_refresh), fontFamily = Chakra, color = Rf.Muted)
                    TextButton(onClick = ::refreshNow) { Text(stringResource(R.string.action_retry)) }
                }
            }
            Box(Modifier.weight(1f)) {
                val d = status?.networks?.firstOrNull { it.name == detailName }
                screenState.SaveableStateProvider(detailName?.let { "network:$it" } ?: "tab:${tab.name}") {
                    when {
                        d != null -> NetworkDetailScreen(
                            detail = d,
                            onBack = { detailName = null }, onToast = ::toast, onChanged = ::refreshNow,
                            onLeft = { screenState.removeState("network:${d.name}"); detailName = null; refreshNow() },
                        )
                        tab == Tab.HOME -> HomeScreen(snapshot = snapshot, starting = starting, onToast = ::toast, onOpenNetworks = { tab = Tab.NETWORKS }, onRefresh = ::refreshNow)
                        tab == Tab.NETWORKS -> NetworksScreen(
                            status = status, starting = starting, onToast = ::toast,
                            onChanged = ::refreshNow, onOpen = { detailName = it.name },
                        )
                        tab == Tab.YOU -> YouScreen(status = status, onToast = ::toast, onChanged = ::refreshNow)
                    }
                }
            }
        }
    }
}
