# Data Broker module definition (product partition)

PRODUCT_PACKAGES += \
    db_daemon

# Note: db_daemon.rc is included via Android.bp init_rc property

# SELinux policy for product partition
PRODUCT_PRIVATE_SEPOLICY_DIRS += \
    vendor/db/sepolicy
