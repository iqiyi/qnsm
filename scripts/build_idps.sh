# IDS, build static library
SURICATA_URL=https://github.com/OISF/suricata.git
LIBHTP_URL=https://github.com/OISF/libhtp
DEP_PATH=/opt/qnsm_deps
QNSM_SRC_PATH=`pwd`/../

function help_info {
    echo "USAGE: $1"
}

#checkout code & apply patch
if [ `which git | wc -l` = 0 ] ; then
	yum install -y git
fi
if [ `git config -l | grep user.name | wc -l` = 0 ] ; then
	echo "ERR: git usr.name not configured"
	echo "git config --global user.name xxx"
	echo "git config --global user.email xxx"
	exit 1
fi
if [ ! -d $DEP_PATH ] ; then
	mkdir -p $DEP_PATH
fi
if [ ! -d $DEP_PATH/suricata ] ; then
	git clone $SURICATA_URL $DEP_PATH
fi
cd $DEP_PATH/suricata

# checkout 4.1.0
git checkout 787473ec64550a2448b81aa13064c1f613642c57
git am --whitespace=nowarn $QNSM_SRC_PATH/patch/suricata-4.1.0/0001-IDPS-make-as-a-lib-support-kafka.patch 
if [ ! -d $DEP_PATH/suricata/libhtp ] ; then
	git clone $LIBHTP_URL
fi
chmod +x libhtp/get-version.sh 

#configure
sh autogen.sh
./configure --enable-rust=no --enable-rdkafka --enable-gccmarch-native=no CPPFLAGS=-I/usr/include/ CFLAGS=-g

#add qnsm conf
sed -i '/HAVE_QNSM/d' config.h
sed -i '/DEBUG_VALIDATION/ a #define HAVE_QNSM 1' config.h
sed -i '/LOCAL_STATE_DIR/d' config.h
sed -i '/DEBUG_VALIDATION/ a #define LOCAL_STATE_DIR "/usr/local/var"' config.h

#compile
make
if [ ! -f src/.libs/libsuri.so ] ; then
	echo "ERR: not found libsuri"
	exit 1
else
	make install
fi

if [ `ldconfig -p | grep libsuri | wc -l` = 0 ] ; then
	echo /usr/local/lib >> /etc/ld.so.conf
	ldconfig
fi