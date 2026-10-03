#!/bin/sh

destpath0=""
destpath1=""
destpath2=""
destpath3=""
destpath4=""

destpathcount=0

#数组在IPCAMERA上报命令失败，所以去掉数组
#var=${4//// } 
var=`echo $4 | awk '{gsub("/", " ", $0); printf("%s\n", $0);}'`

for element in $var
do
  if [ TEST$element  != "TEST" ];    then
 		let destpathcount+=1 	
  fi
  
  if [ $destpathcount -eq 1 ];then
  	destpath0=$element
  elif [ $destpathcount -eq 2 ];then
  	destpath1=$element
  elif [ $destpathcount -eq 3 ];then
  	destpath2=$element
  elif [ $destpathcount -eq 4 ];then
  	destpath3=$element
  elif [ $destpathcount -eq 5 ];then
  	destpath4=$element
  fi  
done

mkdircmd0=`echo -e "$destpath0" | awk '{if ($0 == "")next;print "mkdir " $0}'`
mkdircmd1=`echo -e "$destpath1" | awk '{if ($0 == "")next;print "mkdir " $0}'`
mkdircmd2=`echo -e "$destpath2" | awk '{if ($0 == "")next;print "mkdir " $0}'`
mkdircmd3=`echo -e "$destpath3" | awk '{if ($0 == "")next;print "mkdir " $0}'`
mkdircmd4=`echo -e "$destpath4" | awk '{if ($0 == "")next;print "mkdir " $0}'`



if [ -z "$destpath0" ]; 
then
	destpath0="." 
fi
if [ -z "$destpath1" ]; 
then 
	destpath1="."
fi
if [ -z "$destpath2" ]; 
then
	destpath2="."
fi
if [ -z "$destpath3" ]; 
then 
	destpath3="." 
fi
if [ -z "$destpath4" ]; 
then 
	destpath4="." 
fi

/bin/ftpclient -n <<!
prompt
open $1 $7
user $2 $3
binary
passive

$mkdircmd0
cd $destpath0

$mkdircmd1
cd $destpath1

$mkdircmd2
cd $destpath2

$mkdircmd3
cd $destpath3

$mkdircmd4
cd $destpath4

lcd $5
put $6 $8

close
bye
!


