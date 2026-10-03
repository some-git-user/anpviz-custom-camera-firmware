#/bin/sh


export COMPILETIME1=`date "+%Y-%m-%d %H:%M:%S"`
export FILENAME="/tmp/procinfo_$COMPILETIME1.txt"


echo "anjvision mi modules proc info on $COMPILETIME1" > $FILENAME
echo " " >> $FILENAME


echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/cmdline  "
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME

echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /sys/class/mstar/vif0/vif_ints "
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME

echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/mi_modules/mi_ipu/mi_ipu0 "
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME

echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/mi_modules/mi_sys_mma/mem_stat "
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME


echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/mi_modules/mi_sys_mma/mma_heap_name0 "
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME


echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/mi_modules/mi_sensor/mi_sensor0"
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME

echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /sys/class/mstar/isp0/isp_ints"
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME

echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /sys/class/mstar/isp0/isp_clk "
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME

echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /sys/devices/virtual/mstar/mscl/ints"
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME


echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/mi_modules/mi_vif/mi_vif0 "
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME

echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/mi_modules/mi_isp/mi_isp0 "
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME

echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/mi_modules/mi_scl/mi_scl0 "
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME

echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/mi_modules/mi_venc/mi_venc0"
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME

echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/mi_modules/mi_rgn/mi_rgn0 "
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME


echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/mi_modules/mi_ai/mi_ai0 "
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME



echo "######################################################################" >> $FILENAME
export SHELLCMD="cat /proc/cmdq/finalcmd"
echo $SHELLCMD >> $FILENAME
$SHELLCMD >> $FILENAME

