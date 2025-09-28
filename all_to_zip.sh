#!/usr/bin/env bash
set -euo pipefail
OUT="idf-config-pack-$(date +%Y%m%d-%H%M%S).zip"
mkdir -p _cfgpack

# Metadati ambiente
idf.py --version            > _cfgpack/idf_version.txt || true
idf.py get-target          > _cfgpack/target.txt       || true
git rev-parse --short HEAD > _cfgpack/git_commit.txt   2>/dev/null || true
python3 -V                 > _cfgpack/python_version.txt 2>/dev/null || true

# File di configurazione progetto
cp -v sdkconfig                _cfgpack/ 2>/dev/null || true
cp -v sdkconfig.old            _cfgpack/ 2>/dev/null || true
cp -v sdkconfig.defaults*      _cfgpack/ 2>/dev/null || true
[ -f main/Kconfig.projbuild ] && cp -v main/Kconfig.projbuild _cfgpack/

# Header generati (config effettive)
cp -v build/config/sdkconfig.h                         _cfgpack/ 2>/dev/null || true
cp -v build/bootloader/config/sdkconfig.h              _cfgpack/bootloader_sdkconfig.h 2>/dev/null || true

# CMake & partizioni
cp -v build/CMakeCache.txt     _cfgpack/ 2>/dev/null || true
[ -f CMakeLists.txt ]  && cp -v CMakeLists.txt  _cfgpack/project.CMakeLists.txt
[ -f project.cmake ]   && cp -v project.cmake   _cfgpack/
[ -f partitions.csv ]  && cp -v partitions.csv  _cfgpack/
[ -d partition_table ] && cp -v partition_table/* _cfgpack/ 2>/dev/null || true

# Diagnostica ambiente
idf.py doctor > _cfgpack/idf_doctor.txt || true

zip -r "$OUT" _cfgpack
echo "Creato: $OUT"

