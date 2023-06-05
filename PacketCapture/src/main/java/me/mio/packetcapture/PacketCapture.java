package me.mio.packetcapture;

import com.sun.tools.jdi.Packet;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.server.PluginDisableEvent;
import org.bukkit.scheduler.BukkitRunnable;
import org.bukkit.scheduler.BukkitTask;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class PacketCapture extends JavaPlugin implements Listener {
    private Map<String, ByteArrayOutputStream> capturedPackets;
    private Map<String, BukkitTask> captureTasks;

    @Override
    public void onEnable() {
        capturedPackets = new HashMap<>();
        captureTasks = new HashMap<>();

        getServer().getPluginManager().registerEvents(this, this);
    }

    @Override
    public void onDisable() {
        for (BukkitTask task : captureTasks.values()) {
            task.cancel();
        }
        capturedPackets.clear();
        captureTasks.clear();
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        String playerName = event.getPlayer().getName();
        startCaptureTask(playerName);
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        String playerName = event.getPlayer().getName();
        stopCaptureTask(playerName);
    }

    @EventHandler
    public void onPluginDisable(PluginDisableEvent event) {
        for (String playerName : captureTasks.keySet()) {
            stopCaptureTask(playerName);
        }
    }

    private void startCaptureTask(String playerName) {
        BukkitTask task = new BukkitRunnable() {
            private int suspiciousPacketCount;

            @Override
            public void run() {
                ByteArrayOutputStream packetData = new ByteArrayOutputStream();
                try {
                    DataOutputStream dataOutputStream = new DataOutputStream(packetData);
                    dataOutputStream.writeUTF("Packet capture task");
                    
                    if (isSuspiciousPacket(packet)) {
                        suspiciousPacketCount++;
                        if (suspiciousPacketCount > 10) {
                            kickPlayer(playerName, "You were detected sending suspicious packets.");
                            stopCaptureTask(playerName);
                        }
                    }

                    if (shouldFilterPacket(packet)) {
                        return;
                    }

                    if (isConditionMet(packet)) {
                        performAction();
                    }

                    storeCapturedPacket(playerName, packetData);

                } catch (IOException e) {
                    getLogger().severe("Failed to capture packet for player: " + playerName);
                }
            }

            private boolean isSuspiciousPacket(Packet packet) {
                byte[] payload = packet.getPayload();
                String payloadString = new String(payload, StandardCharsets.UTF_8);
                return payloadString.contains("suspicious keyword");
            }

            private boolean shouldFilterPacket(Packet packet) {
                String ipAddress = packet.getIpAddress();
                return ipAddress.equals("127.0.0.1");
            }

            private boolean isConditionMet(Packet packet) {
                byte[] payload = packet.getPayload();
                return payload.length > 1000;
            }

            private void performAction() {
                getLogger().info("Suspicious packet detected!");
            }

            private void storeCapturedPacket(String playerName, ByteArrayOutputStream packetData) {
                capturedPackets.put(playerName, packetData);
            }

            private void kickPlayer(String playerName, String reason) {
                getServer().getPlayer(playerName).kickPlayer(reason);
            }
        }.runTaskTimer(this, 0, 1);

        captureTasks.put(playerName, task);
    }

    private void stopCaptureTask(String playerName) {
        BukkitTask task = captureTasks.remove(playerName);
        if (task != null) {
            task.cancel();
        }
        capturedPackets.remove(playerName);
    }
}
