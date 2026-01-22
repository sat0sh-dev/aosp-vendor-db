# Data Broker vendor module definition

PRODUCT_PACKAGES += \
    db_daemon

PRODUCT_COPY_FILES += \
    vendor/db/db_daemon.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/db_daemon.rc

BOARD_VENDOR_SEPOLICY_DIRS += \
    vendor/db/sepolicy
