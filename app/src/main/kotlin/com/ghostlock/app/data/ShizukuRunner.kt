package com.ghostlock.app.data

import android.content.Context
import android.content.pm.PackageManager
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ShizukuStatus
import rikka.shizuku.Shizuku
import rikka.shizuku.ShizukuRemoteProcess
import java.io.File
import java.io.IOException
import java.lang.reflect.Method
import java.util.concurrent.TimeUnit

/**
 * Runs the exploit binary as shell uid through Shizuku. Shell uid cannot read
 * /data/app, so the binary, ksud and offsets.json travel through the shizuku
 * process stdin into /data/local/tmp.
 */
object ShizukuRunner {
    private const val Home = "/data/local/tmp"
    private const val RemoteBinary = "$Home/.ghostlock"
    private const val RemoteKsud = "$Home/ksud"
    private const val RemoteOffsets = "$Home/offsets.json"
    private const val RemoteKsuLog = "$Home/.ghostlock_ksu.log"
    private const val ShizukuPackage = "moe.shizuku.privileged.api"
    private const val StageTimeoutSeconds = 60L
    private const val RunTimeoutSeconds = 300L

    fun status(context: Context): ShizukuStatus = runCatching {
        when {
            !Shizuku.pingBinder() ->
                if (installed(context)) ShizukuStatus.NOT_RUNNING else ShizukuStatus.NOT_INSTALLED

            Shizuku.isPreV11() -> ShizukuStatus.TOO_OLD
            Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED ->
                ShizukuStatus.NO_PERMISSION

            else -> ShizukuStatus.READY
        }
    }.getOrDefault(ShizukuStatus.NOT_RUNNING)

    /** Opens the shizuku grant dialog. Each run re-reads the grant, so the result is not tracked. */
    fun requestPermission() {
        runCatching {
            if (!Shizuku.pingBinder() || Shizuku.isPreV11()) return
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) return
            Shizuku.requestPermission(0)
        }
    }

    fun run(
        binary: File,
        ksud: File?,
        offsets: File,
        pair: CpuPair,
        safeMode: Boolean,
        forcedRoute: String?,
        onLog: (String) -> Unit,
    ): Int {
        try {
            stage(binary, RemoteBinary, onLog)
            ksud?.takeIf { it.isFile }?.let { stage(it, RemoteKsud, onLog) }
            if (offsets.isFile) {
                stage(offsets, RemoteOffsets, onLog)
            } else {
                sh("rm -f $RemoteOffsets")
            }
            // the remote log name is fixed, so a stale one would read as this run's
            sh("rm -f $RemoteKsuLog")
            onLog("[*] launching $RemoteBinary")
            return drainAndWait(newProcess(arrayOf("sh", "-c", command(pair, safeMode, forcedRoute))), onLog)
        } finally {
            runCatching { sh("rm -f $RemoteBinary $RemoteKsud") }
            fetchKsuLog(onLog)
        }
    }

    /**
     * env(1) carries the run variables. An exec envp would replace the whole
     * remote environment and strip PATH from the shell. exec replaces sh, so
     * destroy() kills the binary rather than the wrapper.
     */
    private fun command(pair: CpuPair, safeMode: Boolean, forcedRoute: String?): String {
        val env = buildList {
            if (pair.primary != 0 || pair.consumer != 1) {
                add("GHOSTLOCK_CORE=${pair.primary}")
                add("GHOSTLOCK_CONSUMER_CORE=${pair.consumer}")
            }
            if (safeMode) add("GHOSTLOCK_DISABLE_MODULES=1")
            // env restricts the native eligible set, never enables it
            if (forcedRoute == "pselect") add("GHOSTLOCK_TCP_ROUTE=0")
            else if (forcedRoute != null) add("GHOSTLOCK_ROUTE=$forcedRoute")
        }
        return buildString {
            append("exec")
            if (env.isNotEmpty()) append(" env ").append(env.joinToString(" "))
            append(" $RemoteBinary </dev/null 2>&1")
        }
    }

    /**
     * Streams output while waiting. A leak child can hold stdout past the
     * binary's death, so completion comes from the timeout, not from EOF.
     */
    private fun drainAndWait(process: ShizukuRemoteProcess, onLog: (String) -> Unit): Int {
        val input = process.inputStream
        val reader = Thread {
            runCatching {
                input.bufferedReader().useLines { lines -> lines.forEach(onLog) }
            }
        }.apply {
            name = "ghostlock-shizuku-reader"
            isDaemon = true
            start()
        }
        val exited = process.waitForTimeout(RunTimeoutSeconds, TimeUnit.SECONDS)
        if (!exited) {
            onLog("[!] shizuku run timed out; killing")
            process.destroy()
            process.waitForTimeout(5, TimeUnit.SECONDS)
        }
        // force-unblock the reader: an inherited pipe can outlive the binary
        runCatching { input.close() }
        reader.join(3000)
        return if (exited) process.exitValue() else -1
    }

    /** Shell uid cannot read /data/app, so file bytes travel through stdin. wc -c catches truncation. */
    private fun stage(src: File, dest: String, onLog: (String) -> Unit) {
        val want = src.length()
        if (remoteSize(dest) == want) {
            onLog("[*] ${src.name} already staged ($want bytes)")
            return
        }
        onLog("[*] staging ${src.name} ($want bytes) -> $dest")
        val process = newProcess(
            arrayOf("sh", "-c", "rm -f $dest && cat > $dest && chmod 755 $dest && wc -c < $dest")
        )
        src.inputStream().use { input -> process.outputStream.use { input.copyTo(it) } }
        val exited = process.waitForTimeout(StageTimeoutSeconds, TimeUnit.SECONDS)
        val written = if (exited) process.inputStream.bufferedReader().readLine()?.trim()?.toLongOrNull() else null
        if (!exited || written != want) {
            process.destroy()
            throw IOException("staging $dest: wrote $written want $want")
        }
        onLog("[+] staged ok")
    }

    private fun remoteSize(dest: String): Long {
        val process = newProcess(arrayOf("sh", "-c", "wc -c < $dest 2>/dev/null"))
        if (!process.waitForTimeout(StageTimeoutSeconds, TimeUnit.SECONDS)) {
            process.destroy()
            return -1
        }
        return process.inputStream.bufferedReader().readLine()?.trim()?.toLongOrNull() ?: -1
    }

    private fun sh(command: String) {
        val process = newProcess(arrayOf("sh", "-c", command))
        if (process.waitForTimeout(StageTimeoutSeconds, TimeUnit.SECONDS)) {
            runCatching { process.inputStream.close() }
        } else {
            process.destroy()
        }
    }

    /** Pulls the root-script log, which lands in shell-owned tmp the app cannot read. */
    private fun fetchKsuLog(onLog: (String) -> Unit) {
        val process = runCatching { newProcess(arrayOf("sh", "-c", "cat $RemoteKsuLog 2>/dev/null")) }
            .getOrNull() ?: return
        val input = process.inputStream
        val text = StringBuilder()
        val reader = Thread {
            runCatching {
                input.bufferedReader().useLines { lines -> lines.forEach { text.append(it).append('\n') } }
            }
        }.apply {
            name = "ghostlock-shizuku-ksulog"
            isDaemon = true
            start()
        }
        process.waitForTimeout(10, TimeUnit.SECONDS)
        process.destroy()
        reader.join(1000)
        text.toString().lineSequence().filter { it.isNotEmpty() }.forEach(onLog)
    }

    private fun installed(context: Context): Boolean = runCatching {
        context.packageManager.getApplicationInfo(ShizukuPackage, PackageManager.ApplicationInfoFlags.of(0))
    }.isSuccess

    /** newProcess is private since api 13.1.1 but still present. proguard-rules.pro keeps R8 off it. */
    private val newProcessMethod: Method by lazy {
        Shizuku::class.java
            .getDeclaredMethod("newProcess", Array<String>::class.java, Array<String>::class.java, String::class.java)
            .apply { isAccessible = true }
    }

    private fun newProcess(command: Array<String>): ShizukuRemoteProcess =
        newProcessMethod.invoke(null, command, null, Home) as ShizukuRemoteProcess
}
