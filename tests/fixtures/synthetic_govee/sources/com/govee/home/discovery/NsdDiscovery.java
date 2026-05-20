package com.govee.home.discovery;

import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;

/** Zeroconf / mDNS discovery for Govee LAN devices. */
public class NsdDiscovery {

    private static final String SERVICE_TYPE = "_govee._tcp.";
    private NsdManager nsdManager;

    public void startDiscovery(Context context) {
        nsdManager = (NsdManager) context.getSystemService(Context.NSD_SERVICE);
        nsdManager.discoverServices(
            SERVICE_TYPE,
            NsdManager.PROTOCOL_DNS_SD,
            discoveryListener
        );
    }

    private final NsdManager.DiscoveryListener discoveryListener =
        new NsdManager.DiscoveryListener() {
            @Override
            public void onServiceFound(NsdServiceInfo serviceInfo) {
                nsdManager.resolveService(serviceInfo, resolveListener);
            }

            @Override public void onDiscoveryStarted(String type) {}
            @Override public void onDiscoveryStopped(String type) {}
            @Override public void onServiceLost(NsdServiceInfo info) {}
            @Override public void onStartDiscoveryFailed(String type, int code) {}
            @Override public void onStopDiscoveryFailed(String type, int code) {}
        };

    private final NsdManager.ResolveListener resolveListener =
        new NsdManager.ResolveListener() {
            @Override
            public void onServiceResolved(NsdServiceInfo info) {
                String host = info.getHost().getHostAddress();
                int port = info.getPort();
            }

            @Override public void onResolveFailed(NsdServiceInfo info, int code) {}
        };
}
