# Data Broker vendor module definition

PRODUCT_PACKAGES += \
    db_daemon

# Note: db_daemon.rc is included via Android.bp init_rc property

BOARD_VENDOR_SEPOLICY_DIRS += \
    vendor/db/sepolicy
