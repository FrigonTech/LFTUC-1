package com.frigontech.myapplication

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.frigontech.lftuc_1.lftuc_main_lib.*
import com.frigontech.myapplication.ui.theme.MyApplicationTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Greeting(
                        name = "Android",
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val activity = context as? Activity
    val permissionGranted = remember { mutableStateOf(false) }

    // Permission launcher for READ_EXTERNAL_STORAGE (used on Android 10 and below)
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        permissionGranted.value = isGranted
        if (!isGranted) {
            activity?.finishAffinity()
        }
    }

    


    val messages = remember{mutableStateListOf<String>()}
    // Continuously check the Java list and update every 2 seconds
    LaunchedEffect(Unit) {

        withContext(Dispatchers.IO) {
            // Start network services in background
            startLFTUCMulticastListener(context, "239.255.255.250", 8080)
            startLFTUCMulticastEcho(1, "VIVO", lftuc_getLinkLocalIPv6Address(), 8080, 1, "239.255.255.250")
            startLFTUCServer(context)
            lftuc_receivedMessages.add("***server Status before delay: "+serverRunning.get())
            // Wait a moment for server to initialize
            delay(3500)
            lftuc_receivedMessages.add("***server Status after delay: "+serverRunning.get())
            // Now call requestFile, also in background thread
            LFTUCRequestSharedFolder(lftuc_getLinkLocalIPv6Address(), 8080, "stress test/[FILE]Adobe Premiere Pro 2021 v15.4.1.6 (x64) Multilingual.7z",
                object : LFTUCFolderCallback {
                    override fun onResult(files: List<String>) {
                        //lftuc_receivedMessages.add("success requesting...")
                    }

                    override fun onError(errorMessage: String) {
                        lftuc_receivedMessages.add("failed request...")
                    }

                    override fun onProgress(progress: Int) {
                        val progress = "$progress"
                        if(!lftuc_receivedMessages.contains(progress)){
                            lftuc_receivedMessages.add("$progress")
                        }
                    }

                    override fun onGotFileSize(fileSize: String) {
                        lftuc_receivedMessages.add("File Size: $fileSize")
                    }

                    override fun onDownloadComplete(downloadCompleteMessage: String?) {
                        lftuc_receivedMessages.add(downloadCompleteMessage)
                    }
                }
            )

            delay(1000)
            cancelFileDownload()
            // used like as in this name, because inclusion in the module but right now being tested
            lftuc_receivedMessages.add("***server Status after request: "+serverRunning.get())
        }

        while (true) {
            synchronized(lftuc_receivedMessages) {
                // Find new messages that are not already in the Compose list
                val newMessages = lftuc_receivedMessages.filterNot { messages.contains(it) }
                messages.addAll(newMessages) // Add only new messages
            }
            delay(500) // Wait for 0.5 seconds
        }

    }

    Column(modifier = Modifier.fillMaxSize()) {
        Box(
            modifier = Modifier
                .weight(1f) // This makes the Box take all remaining space
                .fillMaxWidth()
                .padding(9.dp)
        ) {
            Box(
                modifier = Modifier
                    .fillMaxSize() // Fill the parent Box
                    .padding(top = 25.dp, bottom=39.dp)
                    .clip(RoundedCornerShape(17.dp))
                    .background(color = Color.Black)

            ) {
                LazyColumn(Modifier.fillMaxSize()) {
                    items(messages.size) { index ->
                        Row {
                            Text(
                                text = messages[index],
                                modifier = Modifier.padding(5.dp),
                                color = Color.Green
                            )
                        }
                    }
                }
            }
        }
    }
}