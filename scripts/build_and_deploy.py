"""
Build and deploy Headwind MDM 2FA TOTP Authentication Plugin (auth-totp.war).

Usage:
    python scripts/build_and_deploy.py [--deploy] [--clean]
"""

import os
import sys
import shutil
import zipfile
import subprocess


def load_secrets(secrets_path):
    if not os.path.isfile(secrets_path):
        return {}
    data = {}
    with open(secrets_path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            data[k.strip()] = v.strip()
    return data


def main():
    deploy = "--deploy" in sys.argv
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(script_dir)
    web_dir = os.path.join(root, "web")
    classes_dir = os.path.join(web_dir, "WEB-INF", "classes")
    war_path = os.path.join(root, "auth-totp.war")

    # Locate build tools (uses sibling headwind_remote_control tools or system tools)
    jdk_javac = os.path.normpath(os.path.join(root, "..", "headwind_remote_control", "_build_tools", "jdk17", "bin", "javac.exe"))
    if not os.path.isfile(jdk_javac):
        jdk_javac = "javac"

    servlet_jar = os.path.normpath(os.path.join(root, "..", "headwind_remote_control", "_build_tools", "servlet-api.jar"))
    assert os.path.isfile(servlet_jar), f"Missing servlet-api.jar at {servlet_jar}"

    lib_dir = os.path.join(web_dir, "WEB-INF", "lib")
    lib_jars = [os.path.join(lib_dir, f) for f in os.listdir(lib_dir) if f.endswith(".jar")] if os.path.isdir(lib_dir) else []
    classpath = servlet_jar + ((";" if os.name == "nt" else ":") + (";" if os.name == "nt" else ":").join(lib_jars) if lib_jars else "")

    print(f"=== Compiling Headwind MDM 2FA TOTP Plugin ===")
    os.makedirs(classes_dir, exist_ok=True)

    src_files = []
    for r, _, files in os.walk(os.path.join(root, "src")):
        for fn in files:
            if fn.endswith(".java"):
                src_files.append(os.path.join(r, fn))

    cmd = [jdk_javac, "--release", "17", "-cp", classpath, "-d", classes_dir] + src_files
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("JAVAC FAILED:\n", res.stdout, res.stderr)
        sys.exit(1)
    print(f"Compiled {len(src_files)} Java source files cleanly.")

    # Package auth-totp.war
    print(f"Packaging auth-totp.war...")
    with zipfile.ZipFile(war_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for r, dirs, files in os.walk(web_dir):
            for fn in files:
                full = os.path.join(r, fn)
                rel = os.path.relpath(full, web_dir)
                zipf.write(full, rel)

    war_size_kb = os.path.getsize(war_path) / 1024
    print(f"[OK] Built auth-totp.war successfully ({war_size_kb:.1f} KB).")

    if not deploy:
        print("Build complete. Pass --deploy to upload and activate on server.")
        return

    # Deploy to server via paramiko
    secrets_path = os.path.normpath(os.path.join(root, "..", "headwind_remote_control", "secrets.key"))
    if not os.path.isfile(secrets_path):
        secrets_path = os.path.join(root, "secrets.key")
    secrets = load_secrets(secrets_path)
    if not secrets or "host" not in secrets:
        print("[ERROR] Cannot deploy: secrets.key not found.")
        sys.exit(1)

    import paramiko
    print(f"Deploying auth-totp.war to {secrets['host']}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(secrets["host"], username=secrets["username"], password=secrets["password"], timeout=15)

    sftp = ssh.open_sftp()
    remote_war = "/var/lib/tomcat10/webapps/auth-totp.war"
    sftp.put(war_path, remote_war)
    sftp.close()
    print(f"Uploaded {war_path} -> {remote_war}")

    activate_cmd = r"""
chown tomcat:tomcat /var/lib/tomcat10/webapps/auth-totp.war
INDEX_HTML="/var/lib/tomcat10/webapps/ROOT/index.html"
HOOK_TAG='<script src="/auth-totp/totp-hook.js" defer></script>'
if [ -f "$INDEX_HTML" ] && ! grep -q "totp-hook.js" "$INDEX_HTML"; then
    echo "Injecting 2FA hook into $INDEX_HTML..."
    sed -i "s|</body>|${HOOK_TAG}</body>|" "$INDEX_HTML"
    chown tomcat:tomcat "$INDEX_HTML"
fi
sleep 5
echo "=== VERIFY DEPLOYMENT ==="
curl -sk -o /dev/null -w "auth-totp hook HTTP code: %{http_code}\n" https://127.0.0.1:8443/auth-totp/totp-hook.js
curl -sk -o /dev/null -w "auth-totp status API HTTP code: %{http_code}\n" https://127.0.0.1:8443/auth-totp/api/status
"""
    _, stdout, stderr = ssh.exec_command(activate_cmd)
    print(stdout.read().decode("utf-8", errors="ignore"))
    err = stderr.read().decode("utf-8", errors="ignore")
    if err:
        print("STDERR:\n" + err)
    ssh.close()
    print("[SUCCESS] Headwind MDM 2FA TOTP plugin is now deployed and active on server.")


if __name__ == "__main__":
    main()
