/**
 * HACS Integration Engine — Frida dynamic protocol oracle agent.
 *
 * Hooks:
 *   1. javax.crypto.Mac.doFinal()         — HMAC signing inputs + output
 *   2. javax.crypto.spec.SecretKeySpec    — key bytes
 *   3. okhttp3.OkHttpClient / Call        — HTTP requests + responses
 *   4. okhttp3 WebSocket                  — WS send + receive frames
 *   5. java.net.HttpURLConnection         — fallback HTTP
 *
 * All events are sent to the Python host via send({type, ...}).
 */

"use strict";

// ── utilities ────────────────────────────────────────────────────────────────

function bytesToHex(bytes) {
    if (!bytes) return "";
    const arr = Array.from(new Uint8Array(bytes.buffer || bytes));
    return arr.map(b => b.toString(16).padStart(2, "0")).join("");
}

function now() {
    return Date.now();
}

// ── 1. HMAC hooks ─────────────────────────────────────────────────────────────

Java.perform(function () {
    // Track active Mac instances: objectId → {algorithm, keyHex}
    const macState = new Map();

    const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    const Mac = Java.use("javax.crypto.Mac");

    // Capture key bytes when SecretKeySpec is constructed
    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (keyBytes, algorithm) {
        this.$init(keyBytes, algorithm);
        // Store on a thread-local via Mac.init hook below
        SecretKeySpec._lastKey = bytesToHex(keyBytes);
        SecretKeySpec._lastAlgo = algorithm;
    };

    // Also handle the 3-arg variant with offset/length
    SecretKeySpec.$init.overload("[B", "int", "int", "java.lang.String").implementation = function (key, offset, len, alg) {
        this.$init(key, offset, len, alg);
        SecretKeySpec._lastKey = bytesToHex(key.slice(offset, offset + len));
        SecretKeySpec._lastAlgo = alg;
    };

    Mac.init.overload("java.security.Key").implementation = function (key) {
        this.init(key);
        const id = this.hashCode();
        const algo = this.getAlgorithm();
        const keyHex = SecretKeySpec._lastKey || "";
        macState.set(id, { algorithm: algo, keyHex: keyHex });
    };

    // doFinal([B) — primary: takes pre-assembled message bytes
    Mac.doFinal.overload("[B").implementation = function (input) {
        const output = this.doFinal(input);
        const id = this.hashCode();
        const state = macState.get(id) || { algorithm: "unknown", keyHex: "" };
        send({
            type: "hmac_call",
            algorithm: state.algorithm,
            key_hex: state.keyHex,
            input_hex: bytesToHex(input),
            output_hex: bytesToHex(output),
            ts: now(),
        });
        return output;
    };

    // doFinal() — no-arg: used with mac.update() pattern
    Mac.doFinal.overload().implementation = function () {
        const output = this.doFinal();
        const id = this.hashCode();
        const state = macState.get(id) || { algorithm: "unknown", keyHex: "" };
        send({
            type: "hmac_call",
            algorithm: state.algorithm,
            key_hex: state.keyHex,
            input_hex: "",          // input fed via update() — not captured here
            output_hex: bytesToHex(output),
            ts: now(),
        });
        return output;
    };

    // ── 2. OkHttp3 HTTP hooks ─────────────────────────────────────────────────

    try {
        const RealCall = Java.use("okhttp3.internal.connection.RealCall");

        RealCall.execute.implementation = function () {
            const request = this.request();
            const method = request.method();
            const url = request.url().toString();

            // Capture request body (text only, skip binary)
            let reqBody = null;
            const body = request.body();
            if (body !== null) {
                try {
                    const Buffer = Java.use("okio.Buffer");
                    const buf = Buffer.$new();
                    body.writeTo(buf);
                    reqBody = buf.readUtf8();
                } catch (_) { /* binary body */ }
            }

            // Capture headers
            const headers = {};
            const hdrNames = request.headers().names().toArray();
            for (let i = 0; i < hdrNames.length; i++) {
                const n = hdrNames[i].toString();
                headers[n] = request.headers().get(n).toString();
            }

            const response = this.execute();
            let respBody = null;
            try {
                const rb = response.peekBody(1024 * 64);
                if (rb !== null) respBody = rb.string();
            } catch (_) { }

            send({
                type: "http_call",
                method: method,
                url: url,
                request_headers: headers,
                request_body: reqBody,
                response_code: response.code(),
                response_body: respBody,
                ts: now(),
            });

            return response;
        };
    } catch (_) {
        // OkHttp3 not present or different version — skip
    }

    // ── 3. OkHttp WebSocket hooks ─────────────────────────────────────────────

    try {
        const RealWebSocket = Java.use("okhttp3.internal.ws.RealWebSocket");

        RealWebSocket.send.overload("java.lang.String").implementation = function (text) {
            send({ type: "ws_send", frame: text, ts: now() });
            return this.send(text);
        };

        // Incoming messages via listener callback
        const WsReader = Java.use("okhttp3.internal.ws.WebSocketReader");
        WsReader.processNextFrame.implementation = function () {
            this.processNextFrame();
            // Message delivered via listener; hook the listener instead
        };
    } catch (_) { }

    // Hook the WebSocketListener that the app registers
    try {
        const WebSocket = Java.use("okhttp3.WebSocket$DefaultImpls") ||
                          Java.use("okhttp3.WebSocket");
        // Hook onMessage on any registered listener class at runtime
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                if (className.indexOf("WebSocketListener") >= 0 ||
                    className.indexOf("WebSocketCallback") >= 0) {
                    try {
                        const cls = Java.use(className);
                        if (cls.onMessage) {
                            cls.onMessage.overload("okhttp3.WebSocket", "java.lang.String").implementation = function (ws, text) {
                                send({ type: "ws_recv", frame: text, ts: now() });
                                return this.onMessage(ws, text);
                            };
                        }
                    } catch (_) { }
                }
            },
            onComplete: function () { },
        });
    } catch (_) { }

    // ── 4. HttpURLConnection fallback ─────────────────────────────────────────

    try {
        const HttpURLConn = Java.use("java.net.HttpURLConnection");

        HttpURLConn.getResponseCode.implementation = function () {
            const code = this.getResponseCode();
            send({
                type: "http_call",
                method: this.getRequestMethod(),
                url: this.getURL().toString(),
                request_headers: {},
                request_body: null,
                response_code: code,
                response_body: null,
                ts: now(),
            });
            return code;
        };
    } catch (_) { }

    // ── 5. Update pattern: capture accumulated mac.update() inputs ────────────

    const updateAccum = new Map();

    Mac.update.overload("[B").implementation = function (input) {
        this.update(input);
        const id = this.hashCode();
        if (!updateAccum.has(id)) updateAccum.set(id, []);
        updateAccum.get(id).push(bytesToHex(input));
    };

    // Override no-arg doFinal to include accumulated update bytes
    const origDoFinal = Mac.doFinal.overload();
    origDoFinal.implementation = function () {
        const output = this.doFinal();
        const id = this.hashCode();
        const state = macState.get(id) || { algorithm: "unknown", keyHex: "" };
        const accumulated = updateAccum.get(id) || [];
        send({
            type: "hmac_call",
            algorithm: state.algorithm,
            key_hex: state.keyHex,
            input_hex: accumulated.join(""),  // concatenated update bytes
            output_hex: bytesToHex(output),
            ts: now(),
        });
        updateAccum.delete(id);
        return output;
    };

    send({ type: "agent_ready", ts: now() });
});
