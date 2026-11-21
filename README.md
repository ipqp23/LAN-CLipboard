<html>
<body>
<!--StartFragment--><html><head></head><body><h1>📋 LAN Clipboard</h1>
<p><strong>Copy on one PC. Paste on the other. Files <em>and</em> text. Built for TightVNC.</strong></p>
<p><a href="https://img.shields.io/badge/platform-Windows-0078D6">Platform</a>
<a href="https://img.shields.io/badge/python-3.8%2B-3776AB">Python</a>
<a href="https://img.shields.io/badge/works%20with-TightVNC-0ea5e9">Works with</a>
<a href="https://img.shields.io/badge/network-LAN%20%7C%20Tailscale%20%7C%20VPN-34d399">Network</a></p>

<img width="582" height="502" alt="1" src="https://github.com/user-attachments/assets/872c84c2-05e3-4dc5-a7e0-52afc6100a7c" />
<img width="582" height="506" alt="3" src="https://github.com/user-attachments/assets/81a60974-578a-47ef-9d59-3b37f7ff5d5a" />

<p><code>#tightvnc</code> <code>#vnc</code> <code>#clipboard</code> <code>#filetransfer</code> <code>#lan</code> <code>#tailscale</code> <code>#remotedesktop</code> <code>#windows</code> <code>#python</code> <code>#tkinter</code> <code>#clipboardsync</code> <code>#productivity</code></p>
<hr>
<h2>🤔 What is this?</h2>
<p>When you control another computer with <strong>TightVNC</strong>, you often need to move a file from the remote PC to your own PC (or the other way around). Normally that means a USB drive, a shared folder, a cloud upload, or opening a separate file-transfer window.</p>
<p><strong>LAN Clipboard</strong> removes all of that. Run it on both computers, connect with TightVNC like you always do, then:</p>
<ol>
<li>Press <strong>Ctrl + C</strong> on files (or text) on one PC</li>
<li>Press <strong>Ctrl + V</strong> on the other PC</li>
</ol>
<p>That's it. The files travel straight from PC to PC over your network. No cloud, no server, no accounts.</p>
<h2>💡 Why was it made?</h2>
<p>TightVNC shares the <strong>text</strong> clipboard, but copying <strong>files</strong> in the remote PC does not show up on your own PC when you paste. Moving files meant extra steps every single time, and sometimes even the text clipboard did not work.</p>
<p>LAN Clipboard was made to make remote work feel like you are sitting at both computers at once: <strong>one shared clipboard for files and text</strong>, working in both directions, over your home LAN or over Tailscale.</p>
<hr>
<h2>✨ Features</h2>
<ul>
<li>📁 <strong>File and folder clipboard</strong>: copy files or whole folders (subfolders and empty folders included) in Explorer</li>
<li>📝 <strong>Text clipboard sync</strong>: works even when TightVNC's own clipboard sharing is off or acting up</li>
<li>🔁 <strong>Two-way</strong>: copy on the remote PC and paste on yours, or copy on yours and paste on the remote PC</li>
<li>🌐 <strong>Works on LAN, Tailscale, VPN, or any routed network</strong>: it uses whatever IP your VNC viewer connects to</li>
<li>🔎 <strong>Automatic</strong>: it detects the active TightVNC session by itself, no IP typing, no pairing</li>
<li>📊 <strong>Progress bar with speed</strong> for larger transfers</li>
<li>🧹 <strong>No clutter</strong>: received files go to a temporary folder and are deleted once they are no longer on the clipboard (and when the app closes)</li>
<li>🔒 <strong>Safer by design</strong>: only accepts files from the PC you have an active TightVNC session with, blocks unsafe file paths, checks free disk space, size limit of 10 GB per transfer</li>
<li>🔑 <strong>Respects private clipboard content</strong>: text that apps mark as private (for example, from many password managers) is not synced</li>
<li>🛡️ <strong>One-click firewall setup</strong>: asks once on first run to open the needed ports, plus a <strong>Fix firewall</strong> button</li>
<li>🖥️ <strong>Compact dark UI</strong> with a tray icon, <strong>Start with Windows</strong> option, and a color-coded activity log</li>
</ul>
<hr>
<h2>🎯 Scope: what it does and doesn't do</h2>

✅ Does | ❌ Doesn't
-- | --
Sync copied files, folders and text between two Windows PCs during a TightVNC session | Replace TightVNC itself (you still use TightVNC to see and control the remote PC)
Work on LAN, Tailscale and other IP networks | Sync images or other clipboard formats (only files and text)
Send in both directions | Move files on cut (Ctrl + X is treated like copy; the original stays)
Run quietly in the tray | Work on Linux or macOS (Windows only)
Delete received temporary files automatically | Encrypt traffic on its own (see Security)


<hr>
<h2>🛠️ Troubleshooting</h2>
<p><strong>"Transfer failed: timed out"</strong>
The other PC is blocking the port. On the receiving PC, click <strong>Fix firewall</strong>, or test from the sending PC:</p>
<pre><code class="language-powershell">Test-NetConnection &lt;other-pc-ip&gt; -Port 50555
</code></pre>
<p><code>TcpTestSucceeded : True</code> means the port is open. <code>False</code> means a firewall (Windows, antivirus, or Tailscale settings) is blocking it.</p>
<p><strong>Partner not detected</strong></p>
<ul>
<li>Make sure LAN Clipboard is running on <strong>both</strong> PCs, on the same version</li>
<li>Make sure the TightVNC session is actually connected</li>
<li>Allow TCP 50555 in the firewall on both PCs</li>
</ul>
<p><strong>Using Tailscale</strong></p>
<ul>
<li>Turn off <strong>Shields Up</strong> on the receiving PC</li>
<li>If you use ACLs, allow TCP 50555 between the two PCs</li>
</ul>
<p><strong>Files can't be pasted anymore</strong>
Received files are temporary. They are removed shortly after you copy something else, and when the app closes. Copy them again from the source PC.</p>
<hr>
<h2>🔐 Security notes</h2>
<ul>
<li>Traffic is <strong>not encrypted by LAN Clipboard</strong>. On a plain LAN, use it only on networks you trust. Over <strong>Tailscale</strong>, the traffic is already encrypted by Tailscale.</li>
<li>Only a PC with an <strong>active TightVNC session</strong> to your PC can send you files.</li>
<li>Turn off <strong>Sync copied text</strong> before copying passwords or other secrets.</li>
</ul>
<hr>
<h2>🧱 How it works (for the curious)</h2>
<ol>
<li>The app reads the active TCP connections and spots a TightVNC session (ports 5900–5909).</li>
<li>It checks the other side on TCP 50555 to confirm LAN Clipboard is running there.</li>
<li>It watches the Windows clipboard for copied <strong>files</strong> (<code>CF_HDROP</code>) and <strong>text</strong> (<code>CF_UNICODETEXT</code>).</li>
<li>Copied items are streamed directly to the partner over TCP (a small JSON header, then raw file bytes).</li>
<li>The receiver saves them to a temporary folder and places them on its own clipboard exactly like Explorer's copy, so <strong>Ctrl + V</strong> just works.</li>
</ol>
<hr>
<h2>📦 Build a standalone .exe (optional)</h2>
<pre><code class="language-powershell">pip install pyinstaller
py -m PyInstaller LANClipboard.spec
</code></pre>
<p>Adjust the script path inside <code>LANClipboard.spec</code> if needed. The <code>.exe</code> appears in the <code>dist</code> folder.</p>
<hr>
<h2>🗺️ Ideas for later</h2>
<ul>
<li>Optional <strong>move on cut</strong> (delete the original after a successful transfer)</li>
<li>Optional encryption for plain LAN use</li>
<li>Image clipboard support</li>
</ul>
<p>Contributions, issues and ideas are welcome!</p>
<hr>
<h2>📄 License</h2>
<p>Add the license of your choice (for example, MIT).</p>
<hr>
<h2>🇵🇭 Sa madaling salita (Tagalog)</h2>
<p>Kapag nire-remote mo ang isang PC gamit ang <strong>TightVNC</strong>, hindi mo basta-basta makokopya ang <strong>files</strong> papunta sa sarili mong PC. Ang <strong>LAN Clipboard</strong> ang sagot dito: patakbuhin ito sa <strong>dalawang PC</strong>, mag-connect gamit ang TightVNC, tapos <strong>Ctrl + C</strong> sa isang PC at <strong>Ctrl + V</strong> sa kabila. Gumagana ito sa files, folders at text, sa dalawang direksyon, sa LAN man o sa <strong>Tailscale</strong>. Walang cloud at walang kailangang i-setup na IP. Pansamantala lang ang mga natanggap na files at kusa silang nabubura, kaya hindi nag-iipon sa disk.</p>
<hr>
<p><code>#tightvnc</code> <code>#vnc</code> <code>#clipboard</code> <code>#filetransfer</code> <code>#lan</code> <code>#tailscale</code> <code>#remotedesktop</code> <code>#windows</code> <code>#python</code> <code>#tkinter</code> <code>#clipboardsync</code> <code>#productivity</code></p></body></html><!--EndFragment-->
</body>
</html>
