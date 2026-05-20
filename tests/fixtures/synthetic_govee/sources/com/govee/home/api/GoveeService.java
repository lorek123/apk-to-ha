package com.govee.home.api;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.Header;
import retrofit2.http.POST;
import retrofit2.http.PUT;
import retrofit2.http.Path;

/** Retrofit service interface for the Govee LAN API. */
public interface GoveeService {

    @GET("/govee/v1/dev/devList")
    Call<DeviceListResponse> getDeviceList(
        @Header("Govee-API-Key") String apiKey
    );

    @GET("/govee/v1/dev/devDetail")
    Call<DeviceDetailResponse> getDeviceDetail(
        @Header("Govee-API-Key") String apiKey,
        @Header("device") String deviceId
    );

    @PUT("/govee/v1/dev/control")
    Call<CommandResponse> sendCommand(
        @Header("Govee-API-Key") String apiKey,
        @Body ControlRequest request
    );

    @GET("/govee/v1/dev/devState")
    Call<DeviceStateResponse> getDeviceState(
        @Header("Govee-API-Key") String apiKey,
        @Header("device") String deviceId
    );
}
