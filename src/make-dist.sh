#!/bin/sh

VERSION=0.1

tar -zcvf cryptoki-capi-$VERSION.tar.gz \
	--exclude=*.tar.gz --exclude=.svn --exclude=sandbox \
	--exclude=Debug --exclude=Release \
	--exclude=*.plg --exclude=*.ncb --exclude=*.opt \
	*
