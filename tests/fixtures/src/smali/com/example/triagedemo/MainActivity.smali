.class public Lcom/example/triagedemo/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"


# Benign test fixture. The strings below are FAKE, planted so the triage
# pipeline has deterministic secrets/indicators to detect. The method wires up
# DexClassLoader, SmsManager and Runtime.exec so androguard sees real xrefs.

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method public static collect()V
    .registers 11

    const-string v0, "AIzaSyB1cD3fG5hJ7kL9mN1pQ3rS5tU7vW9xY0z"

    const-string v1, "http://198.51.100.23/gate.php"

    # dynamic code loading via DexClassLoader
    new-instance v2, Ldalvik/system/DexClassLoader;

    const-string v3, "/data/local/tmp/payload.dex"

    const-string v4, "/data/local/tmp"

    const/4 v9, 0x0

    invoke-direct {v2, v3, v4, v9, v9}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V

    # SmsManager.sendTextMessage needs the /range opcode (6 registers)
    invoke-static {}, Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;

    move-result-object v5

    move-object v6, v0

    const/4 v7, 0x0

    move-object v8, v1

    const/4 v10, 0x0

    invoke-virtual/range {v5 .. v10}, Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V

    # Runtime.exec shell-out
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v2

    invoke-virtual {v2, v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;

    return-void
.end method
