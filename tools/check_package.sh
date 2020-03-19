#!/bin/bash
set -e

ver="$1"
imgs="$2"
rels="$3"

if [ "$ver" == "" ]; then
    # some OS like CentOS/Fedora use only 6 hexadecimal
    # digits as the abbreviated object name
    ver=$(git describe --abbrev=6 | sed 's#-#.#g')
fi

if [ "$imgs" == "" ]; then
    for dist in 14.04 16.04 18.04 19.04 19.10 ; do imgs="$imgs ubuntu:$dist" ; done
    for dist in jessie stretch buster ; do imgs="$imgs debian:$dist" ; done
    for dist in 6 7 8 ; do imgs="$imgs centos:$dist" ; done
    for dist in 28 29 30 31 ; do imgs="$imgs fedora:$dist" ; done
fi

imgs=$(echo $imgs | sed "s#el:#centos:#g")

if [ "$rels" == "" ]; then
    rels="1.10 2.1 2.2 2.3 2.4"
fi

cwd=`dirname $0`

run_docker () {
    VER=$1
    IMG=$2
    REL=$3

    PKG_TOOL=yum
    if [[ $IMG =~ .*ubuntu.* || $IMG =~ .*debian.* ]]; then
        PKG_TOOL=apt
    fi
    echo "Testing $REL Tarantool on $IMG image ..."
    newimg="check-s3_"`echo $IMG | sed 's#:#-#g'`"_$REL"
    # repository update command must always be rerun to be able
    # to get the new available versions of the Tarantool, so the
    # flag "--no-cache" must be set
    docker build \
        --network=host \
        --no-cache \
        --build-arg PKG_TOOL=$PKG_TOOL \
        --build-arg REL=$REL \
        --build-arg IMG=$IMG \
        --build-arg TNT_VER=$VER \
        -f $cwd/Dockerfile.s3 -t $newimg .
}

for rel in $rels ; do
    for img in $imgs ; do
        run_docker $ver $img $rel
    done
done
