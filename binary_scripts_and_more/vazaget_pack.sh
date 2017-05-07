#!/bin/bash

# This cript do:
#1. run make clean
#2. delete temporary files from eclipse workspace
#3. compress the workspace to be ready for backup.

#requires : apt-get install ccrypt expect

PROJ_PATH='/disk2/projects'
WORKSPACE_NAME='vazaget_workspace'
PROG_NAME='vazaget'

if [ `getconf LONG_BIT` = "64" ]
then
    VAZAGET_VER=$(grep "VAZAGET_VERSION" $PROJ_PATH/$WORKSPACE_NAME/vazaget/global.h | cut -d\" -f2)"_x64"
else
    VAZAGET_VER=$(grep "VAZAGET_VERSION" $PROJ_PATH/$WORKSPACE_NAME/vazaget/global.h | cut -d\" -f2)
fi



DATE=$(date +%Y.%m.%d)
TIME=$(date +%H.%M)
GZIP_FILE_NAME='vz.ver.'$VAZAGET_VER'_date_'$DATE'_time_'$TIME'.tgz'
ENC_FILE_NAME=$GZIP_FILE_NAME'.enc'

#copy Binary and clean
VAZA_PATH=$PROJ_PATH/$WORKSPACE_NAME/$PROG_NAME ;
echo "cd to:"$VAZA_PATH;
cd $PROJ_PATH/$WORKSPACE_NAME/$PROG_NAME ;
echo "make clean..." ; make clean ;
echo "make..." ; make ;
echo "Copy Binary..."
cp $PROG_NAME ./binary_scripts_and_more/
echo "make clean again..." ; make clean ;


#delete irrelevant files
rm -rf $PROJ_PATH/$WORKSPACE_NAME/.metadata/.plugins/org.eclipse.core.resources/.history ; echo "delete .history" ;
rm -rf $PROJ_PATH/$WORKSPACE_NAME/$PROG_NAME/tmp* ; echo "delete tmp* files" ;
rm -rf $PROJ_PATH/$WORKSPACE_NAME/$PROG_NAME/vazaget_log.txt ; echo "delete vazaget_log.txt" ;
rm -rf $PROJ_PATH/$WORKSPACE_NAME/$PROG_NAME/binary_scripts_and_more/vazaget_log.txt ; echo "delete 2nd vazaget_log.txt" ;
rm -rf $PROJ_PATH/$WORKSPACE_NAME/$PROG_NAME/unit_test/vazaget_log.txt ; echo "delete 3rd vazaget_log.txt" ;
rm -rf $PROJ_PATH/$WORKSPACE_NAME/$PROG_NAME/core* ; echo "delete core*" ;
rm -rf $PROJ_PATH/$WORKSPACE_NAME/$PROG_NAME/binary_scripts_and_more/core* ; echo "delete 2nd core*" ;
rm -rf $PROJ_PATH/$WORKSPACE_NAME/.metadata/.plugins/org.eclipse.cdt.core/*.pdom ; echo "delete *.pdom" ;

#gzip the directory
echo "Creating $GZ_FILE..." ;
cd $PROJ_PATH ;
rm -rf $GZ_FILE ;
tar czf $GZIP_FILE_NAME $WORKSPACE_NAME ;

echo "Encrypting $GZIP_FILE_NAME..." ;
ccencrypt $GZIP_FILE_NAME ;
#converting *.cpt to *.enc
mv $GZIP_FILE_NAME'.cpt' $ENC_FILE_NAME ;

FILE_SIZE=$(stat -c %s $ENC_FILE_NAME);
echo "$PROJ_PATH/$WORKSPACE_NAME/$ENC_FILE_NAME created, file size=$FILE_SIZE" ;

#Done
echo "vazaget_clean done!"
