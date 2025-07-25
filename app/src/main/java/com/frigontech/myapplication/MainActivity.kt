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
        val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
        activity?.startActivityForResult(intent, 1)

        startLFTUCServer(context)
        startLFTUCMulticastEcho(1, "lambda", lftuc_getLinkLocalIPv6Address(), 8080, 1)
        println("Started server and echo")
        println("delaying 2 seconds")
        delay(2000) //2 seconds
        println("Started listening; delaying 5 seconds")
        startLFTUCMulticastListener(context, 8080)

        delay(5000) // 5 seconds
        println("printing current found servers")
        println(lftuc_currentServers)

        while (true) {
            val newMessages = lftuc_getReceivedMessages().filterNot { messages.contains(it) }
            messages.addAll(newMessages) // Add only new messages
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