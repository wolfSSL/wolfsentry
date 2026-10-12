# STM32H563 M33MU example runtime

This fixture boots the STM32 lwIP examples on an emulated Cortex-M33. Each
firmware image starts the FreeRTOS scheduler and lwIP TCP/IP task before it
runs the example initialization and wolfSentry allow/deny policy checks.

The test requires the M33MU emulator, the Arm GNU toolchain, FreeRTOS V10.5.1,
patched lwIP 2.1.3 with lwIP contrib, and wolfSSL for the TLS variant. Run both
images with:

```sh
make run FREERTOS_TOP=/workspace/freertos LWIP_TOP=/workspace/lwip \
    WOLFSSL_TOP=/workspace/wolfssl
```

M33MU is emulator evidence. This fixture does not replace testing on an
STM32H563 board.
