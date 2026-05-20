package com.govee.home.model;

import com.google.gson.annotations.SerializedName;

/** Govee device state — parsed from /govee/v1/dev/devState response. */
public class DeviceState {

    @SerializedName("online")
    boolean online;

    @SerializedName("powerState")
    String powerState;

    @SerializedName("brightness")
    int brightness;

    @SerializedName("color")
    ColorState color;

    @SerializedName("colorTemInKelvin")
    int colorTemInKelvin;

    public static class ColorState {
        @SerializedName("r")
        int r;
        @SerializedName("g")
        int g;
        @SerializedName("b")
        int b;
    }
}
