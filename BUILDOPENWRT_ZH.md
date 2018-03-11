更新feeds

    ./scripts/feeds update -a
    ./scripts/feeds install -a

在menuconfig选中libuhttpd，然后重新编译固件。

    Libraries  --->
        Networking  --->
            <*> libuhttpd-mbedtls.................................... libuhttpd (mbedtls)
            < > libuhttpd-nossl....................................... libuhttpd (NO SSL)
            < > libuhttpd-openssl.................................... libuhttpd (openssl)
            < > libuhttpd-wolfssl.................................... libuhttpd (wolfssl)
