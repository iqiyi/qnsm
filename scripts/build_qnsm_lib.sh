#!/bin/sh

#header files
export QNSM_PATH=`pwd`/..

function build_qnsm_lib {
	SDK=$1
	TARGET=$2
	
	echo "build qnsm lib"
	rm -rf $SDK/$TARGET/build/lib/libqnsm_service
	rm -f $SDK/$TARGET/lib/libqnsm_service.a
	rm -rf ${SDK}/lib/libqnsm_service
	cp -rf $QNSM_PATH/libqnsm_service ${SDK}/lib

	#modify config file
	sed -i '/QNSM/d' ${SDK}/config/common_base
	echo 'CONFIG_QNSM_LIBQNSM_SERVICE=y' >> ${SDK}/config/common_base

	#modify lib makfile
	sed -i '/CONFIG_QNSM_LIBQNSM_SERVICE/d' ${SDK}/lib/Makefile
	sed -i '/DIRS-$(CONFIG_RTE_LIBRTE_PDUMP) /aDIRS-$(CONFIG_QNSM_LIBQNSM_SERVICE) += libqnsm_service' ${SDK}/lib/Makefile

	#modify ld sequence
	sed -i '/CONFIG_QNSM_LIBQNSM_SERVICE/d' ${SDK}/mk/rte.app.mk 
	sed -i '/_LDLIBS-$(CONFIG_RTE_LIBRTE_PIPELINE) /a_LDLIBS-$(CONFIG_QNSM_LIBQNSM_SERVICE)      += -lqnsm_service' ${SDK}/mk/rte.app.mk 

	cd $SDK

	# build.
	make install T=${TARGET}
}

if [ "" == "$RTE_SDK" ] ; then
	echo "RTE_SDK not exist"
	exit 1
fi

if [ "" == "$RTE_TARGET" ] ; then
	echo "RTE_TARGET not exist"
	exit 1
fi

#build qnsm lib
build_qnsm_lib $RTE_SDK $RTE_TARGET