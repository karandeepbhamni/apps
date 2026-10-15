package com.zakariya.dola

import android.app.DownloadManager
import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.util.Base64
import android.webkit.*
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : AppCompatActivity() {

    private lateinit var web: WebView
    @Volatile private var curHost = ""
    private val startUrl = "https://www.dola.com/"
    private val allowedOrigins = setOf(
        "https://www.dola.com", "https://dola.com",
        "https://www.doubao.com", "https://doubao.com"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this)
        setContentView(web)

        val s = web.settings
        s.javaScriptEnabled = true
        s.domStorageEnabled = true
        s.mediaPlaybackRequiresUserGesture = false
        s.userAgentString = s.userAgentString.replace("; wv", "")
        CookieManager.getInstance().setAcceptCookie(true)
        CookieManager.getInstance().setAcceptThirdPartyCookies(web, true)

        web.addJavascriptInterface(Bridge(), "AndroidZK")

        val js = assets.open("zk-page.js").bufferedReader().use { it.readText() }
        if (WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            WebViewCompat.addDocumentStartJavaScript(web, js, allowedOrigins)
        }

        web.webViewClient = object : WebViewClient() {
            override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                curHost = Uri.parse(url ?: "").host ?: ""
            }
        }
        web.webChromeClient = WebChromeClient()

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (web.canGoBack()) web.goBack() else finish()
            }
        })

        if (savedInstanceState == null) web.loadUrl(startUrl) else web.restoreState(savedInstanceState)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        web.saveState(outState)
    }

    private fun hostOk(): Boolean = curHost.endsWith("dola.com") || curHost.endsWith("doubao.com")

    private fun reply(id: Int, ok: Boolean, data: String) {
        runOnUiThread {
            web.evaluateJavascript("window.__zkCb($id,$ok,${JSONObject.quote(data)})", null)
        }
    }

    inner class Bridge {
        @JavascriptInterface
        fun fetchText(id: Int, url: String) {
            if (!hostOk()) { reply(id, false, "blocked"); return }
            Thread {
                try {
                    val c = URL(url).openConnection() as HttpURLConnection
                    c.setRequestProperty("Cookie", CookieManager.getInstance().getCookie(url) ?: "")
                    c.setRequestProperty("User-Agent", web.settings.userAgentString)
                    c.setRequestProperty("Referer", startUrl)
                    c.connectTimeout = 15000
                    c.readTimeout = 20000
                    if (c.responseCode !in 200..299) throw Exception("HTTP ${c.responseCode}")
                    val body = c.inputStream.readBytes()
                    reply(id, true, Base64.encodeToString(body, Base64.NO_WRAP))
                } catch (e: Exception) {
                    reply(id, false, e.message ?: "error")
                }
            }.start()
        }

        @JavascriptInterface
        fun download(id: Int, json: String) {
            if (!hostOk()) { reply(id, false, "blocked"); return }
            try {
                val o = JSONObject(json)
                val url = o.getString("url")
                val name = o.getString("filename").replace(Regex("[/\\\\]"), "_")
                val req = DownloadManager.Request(Uri.parse(url))
                    .setTitle(name)
                    .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                    .setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, "Zakariya_Dola_Videos/$name")
                CookieManager.getInstance().getCookie(url)?.let { req.addRequestHeader("Cookie", it) }
                req.addRequestHeader("User-Agent", web.settings.userAgentString)
                req.addRequestHeader("Referer", startUrl)
                (getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager).enqueue(req)
                reply(id, true, "{\"ok\":true}")
            } catch (e: Exception) {
                reply(id, true, "{\"ok\":false,\"error\":${JSONObject.quote(e.message ?: "error")}}")
            }
        }
    }
}
