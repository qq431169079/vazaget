#!/bin/bash

#This script runs unit test for part of the features vazaget gives.
#after finish will give you the success ratio - should be 100%
#in order to run this you should have the follows:
#1. Apache on your local machine, running php5 with vazaget index.php ("./vazaget -php"), support in cookies
#2. should listen on port 80 and 8080
#2.a support in SSL , port 443
#3. localhost should be resolved to 127.0.0.1
#4. ip6-localhost should be resolved to [::1]
#5. index.php should be located on your apache_home_dir/index.php
#6. another index.php should be located on : apache_home_dir/path_1/path_2/index.php
#7. squid proxy server on this local machine, listening on port 3128, IPv4 and IPv6
	
LOG_FILE=vazaget_log.txt
VAZAGET_PATH=../vazaget

USE_LOCAL_SERVER=0

if [ $USE_LOCAL_SERVER -eq 1 ]
#server on localhost
then
	SRV_IP4_ADDR=127.0.0.1
	SRV_IP4_NAME=localhost
	SRV_IP6_ADDR=::1
	SRV_IP6_NAME=ip6-localhost
	PROXY_IP4_ADDR=127.0.0.1
	PROXY_IP4_NAME=localhost
	PROXY_IP6_ADDR=::1
	PROXY_IP6_NAME=ip6-localhost
#server remote
else
	SRV_IP4_ADDR=1.0.0.1
	SRV_IP4_NAME=srv-1
	SRV_IP6_ADDR=2010::1
	SRV_IP6_NAME=ip6-srv-1
	PROXY_IP4_ADDR=127.0.0.1
	PROXY_IP4_NAME=localhost
	PROXY_IP6_ADDR=::1
	PROXY_IP6_NAME=ip6-localhost
fi

TEST_IPV4=1
TEST_IPV6=1
TEST_PROXY=1
	PROXY_V4_V4=1
	PROXY_V6_V6=1
	PROXY_V4_V6=1
	PROXY_V6_V4=1
TEST_POST_UPLOAD=1
TEST_RATE_LIMIT=1
TEST_GZIP=1
TEST_SSL_IPV4=1
TEST_SSL_IPV6=1

DL_VALIDATION_EN=1
DL_CHECKED_FILES=0
DL_CORRUPT_FILES=0
DL_VALID_FILES=0


#############
# clean_tmp_files
#############
function clean_tmp_files
{
	rm index.html*
	rm index.php*
}

#############
# validate_download_file
#for now will check only the beginning and end of the file
#############
function validate_download_file
{
	if [ $DL_VALIDATION_EN -eq 1 ]
	then 
		let DL_CHECKED_FILES+=1

		FILE=$(ls -t index.* | head -n 1)
		START=$(grep "<html>" $FILE | wc -l)
		END=$(grep "</html>" $FILE | wc -l)
	
		if [ $START -ne 1 ] || [ $END -ne 1 ]
		then
			let DL_CORRUPT_FILES+=1
			exit #temp TBR
		else
			let DL_VALID_FILES+=1
		fi
		rm -f $FILE
	fi
	
}

#############
# ipv4_test - IPv4
#############
function ipv4_test
{
	params=$1
	
	$VAZAGET_PATH $SRV_IP4_ADDR $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_ADDR/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_ADDR/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_ADDR/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH $SRV_IP4_ADDR:8080 $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_ADDR:8080/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_ADDR:8080/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_ADDR:8080/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH $SRV_IP4_NAME $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_NAME/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_NAME/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_NAME/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH $SRV_IP4_NAME:8080 $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_NAME:8080/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_NAME:8080/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_NAME:8080/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH http://$SRV_IP4_ADDR $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP4_ADDR/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP4_ADDR/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP4_ADDR/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH http://$SRV_IP4_ADDR:8080 $params
	validate_download_file 
	$VAZAGET_PATH http://$SRV_IP4_ADDR:8080/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP4_ADDR:8080/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP4_ADDR:8080/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH http://$SRV_IP4_NAME $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP4_NAME/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP4_NAME/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP4_NAME/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH http://$SRV_IP4_NAME:8080 $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP4_NAME:8080/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP4_NAME:8080/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP4_NAME:8080/path_1/path_2/index.php $params
	validate_download_file
		
}

#############
#IPv6
#############
function ipv6_test
{
	params=$1
	
	$VAZAGET_PATH [$SRV_IP6_ADDR] $params
	validate_download_file
	$VAZAGET_PATH [$SRV_IP6_ADDR]/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH [$SRV_IP6_ADDR]/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH [$SRV_IP6_ADDR]/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH [$SRV_IP6_ADDR]:8080 $params
	validate_download_file
	$VAZAGET_PATH [$SRV_IP6_ADDR]:8080/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH [$SRV_IP6_ADDR]:8080/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH [$SRV_IP6_ADDR]:8080/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH $SRV_IP6_NAME $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP6_NAME/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP6_NAME/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP6_NAME/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH $SRV_IP6_NAME:8080 $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP6_NAME:8080/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP6_NAME:8080/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH $SRV_IP6_NAME:8080/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH http://[$SRV_IP6_ADDR] $params
	validate_download_file
	$VAZAGET_PATH http://[$SRV_IP6_ADDR]/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH http://[$SRV_IP6_ADDR]/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH http://[$SRV_IP6_ADDR]/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH http://[$SRV_IP6_ADDR]:8080 $params
	validate_download_file
	$VAZAGET_PATH http://[$SRV_IP6_ADDR]:8080/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH http://[$SRV_IP6_ADDR]:8080/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH http://[$SRV_IP6_ADDR]:8080/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH http://$SRV_IP6_NAME $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP6_NAME/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP6_NAME/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP6_NAME/path_1/path_2/index.php $params
	validate_download_file

	$VAZAGET_PATH http://$SRV_IP6_NAME:8080 $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP6_NAME:8080/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP6_NAME:8080/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH http://$SRV_IP6_NAME:8080/path_1/path_2/index.php $params
	validate_download_file
	
}

#############
#Proxy cache
#############
function proxy_test
{
	if [ $PROXY_V4_V4 -eq 1 ]
	then
		ipv4_test "-pr $PROXY_IP4_ADDR:3128 -o proxy_test_1"
		ipv4_test "-pr $PROXY_IP4_NAME:3128 -o proxy_test_2"
		ipv4_test "-pr http://$PROXY_IP4_ADDR:3128 -o proxy_test_3"
		ipv4_test "-pr http://$PROXY_IP4_NAME:3128 -o proxy_test_4"
	fi
	
	if [ $PROXY_V6_V6 -eq 1 ]
	then
		ipv6_test "-pr [$PROXY_IP6_ADDR]:3128 -o proxy_test_5"
		ipv6_test "-pr $PROXY_IP6_NAME:3128 -o proxy_test_6"
		ipv6_test "-pr http://[$PROXY_IP6_ADDR]:3128 -o proxy_test_7"
		ipv6_test "-pr http://$PROXY_IP6_NAME:3128 -o proxy_test_8"
	fi
	
	if [ $PROXY_V4_V6 -eq 1 ]
	then
		ipv4_test "-pr [$PROXY_IP6_ADDR]:3128 -o proxy_test_9"
		ipv4_test "-pr $PROXY_IP6_NAME:3128 -o proxy_test_10"
		ipv4_test "-pr http://[$PROXY_IP6_ADDR]:3128 -o proxy_test_11"
		ipv4_test "-pr http://$PROXY_IP6_NAME:3128 -o proxy_test_12"
	fi
	
	if [ $PROXY_V6_V4 -eq 1 ]
	then
		ipv6_test "-pr $PROXY_IP4_ADDR:3128 -o proxy_test_13"
		ipv6_test "-pr $PROXY_IP4_NAME:3128 -o proxy_test_14"
		ipv6_test "-pr http://$PROXY_IP4_ADDR:3128 -o proxy_test_15"
		ipv6_test "-pr http://$PROXY_IP4_NAME:3128 -o proxy_test_16"
	fi
	
}

#############
#basic_ipv4_test
#############
function basic_ipv4_test
{
	ipv4_test "-o basic_ipv4_test_1"	
}

#############
#basic_ipv6_test
#############
function basic_ipv6_test
{
	ipv6_test "-o basic_ipv6_test_1"	
}

#############
#post_upload_test
#############
function post_upload_test
{
	ipv4_test "-up 1000 -o post_upload_test_1"
	ipv6_test "-up 1000 -o post_upload_test_2"
	ipv4_test "-pr http://$PROXY_IP4_NAME:3128 -up 1000 -o post_upload_test_3"
	ipv6_test "-pr http://$PROXY_IP6_NAME:3128 -up 1000 -o post_upload_test_4"

	if [ $TEST_SSL_IPV4 -eq 1 ] 
	then 
		ipv4_ssl_test "-up 1000 -o post_upload_test_5"
	fi	
}


#############
#upload
#############
function rate_limit
{
	$VAZAGET_PATH $SRV_IP4_ADDR -br 499 -bt 10 -o rate_limit_1
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_ADDR -br 243 -bt 33 -o rate_limit_2
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_ADDR -br 100 -bt 47 -o rate_limit_3
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_ADDR -br 62  -bt 60 -o rate_limit_4
	validate_download_file
	$VAZAGET_PATH $SRV_IP4_ADDR -br 10  -bt 78 -o rate_limit_5
	validate_download_file
	ipv4_test "-br 300 -bt 100 -o rate_limit_6"
	ipv6_test "-br 300 -bt 100 -o rate_limit_7"
#	ssl with rate_limit not works yet
#	if [ $TEST_SSL_IPV4 -eq 1 ] 
#	then 
#		ipv4_ssl_test "-br 250 -bt 200 -o rate_limit_8"
#	fi
}


#############
#gzip_decompression
#############
function gzip_decompression
{
	DL_VALIDATION_EN=0 #cannot validate compressed file
	
	$VAZAGET_PATH $SRV_IP4_ADDR -gz -br 122 -o gzip_decompression_1
	validate_download_file
	ipv4_test "-gz -o gzip_decompression_2"
	ipv6_test "-gz -o gzip_decompression_3"
	
	if [ $TEST_SSL_IPV4 -eq 1 ] 
	then 
		ipv4_ssl_test "-gz -o gzip_decompression_4"
	fi

	if [ $TEST_SSL_IPV6 -eq 1 ] 
	then 
		ipv6_ssl_test "-gz -o gzip_decompression_5"
	fi

	DL_VALIDATION_EN=1 #retuen to DL validation
	clean_tmp_files
}

#############
#ipv4_ssl_test
#############
function ipv4_ssl_test
{
	params=$1

	$VAZAGET_PATH https://$SRV_IP4_ADDR $params
	validate_download_file
	$VAZAGET_PATH https://$SRV_IP4_ADDR/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH https://$SRV_IP4_ADDR/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH https://$SRV_IP4_ADDR/path_1/path_2/index.php $params
	validate_download_file
	
	$VAZAGET_PATH https://$SRV_IP4_NAME $params
	validate_download_file
	$VAZAGET_PATH https://$SRV_IP4_NAME/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH https://$SRV_IP4_NAME/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH https://$SRV_IP4_NAME/path_1/path_2/index.php $params
	validate_download_file
}

#############
#basic_ssl_ipv4_test
#############
function basic_ssl_ipv4_test
{
	ipv4_ssl_test "-o basic_ssl_ipv4_test_1"	
}

#############
#ipv6_ssl_test
#############
function ipv6_ssl_test
{
	params=$1

	$VAZAGET_PATH https://[$SRV_IP6_ADDR] $params
	validate_download_file
	$VAZAGET_PATH https://[$SRV_IP6_ADDR]/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH https://[$SRV_IP6_ADDR]/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH https://[$SRV_IP6_ADDR]/path_1/path_2/index.php $params
	validate_download_file
	
	$VAZAGET_PATH https://$SRV_IP6_NAME $params
	validate_download_file
	$VAZAGET_PATH https://$SRV_IP6_NAME/path_1/path_2 $params
	validate_download_file
	$VAZAGET_PATH https://$SRV_IP6_NAME/path_1/path_2/ $params
	validate_download_file
	$VAZAGET_PATH https://$SRV_IP6_NAME/path_1/path_2/index.php $params
	validate_download_file
}

#############
#basic_ssl_ipv6_test
#############
function basic_ssl_ipv6_test
{
	ipv6_ssl_test "-o basic_ssl_ipv6_test_1"	
}

#############
#print_tests
#############
function print_tests
{
	echo "	IPv4=$TEST_IPV4"
	echo "	IPv6=$TEST_IPV6"
	echo "	Proxy=$TEST_PROXY (v4->v4=$PROXY_V4_V4 , v6->v6=$PROXY_V6_V6 , v4->v6=$PROXY_V4_V6 , v6->v4=$PROXY_V6_V4)"
	echo "	Post upload=$TEST_POST_UPLOAD"
	echo "	rate_limit=$TEST_RATE_LIMIT"
	echo "	gzip decompression=$TEST_GZIP"
	echo "	SSL_IPv4=$TEST_SSL_IPV4"
	echo "	SSL_IPv6=$TEST_SSL_IPV6"
}

#############
#analyze_log
#############
function analyze_log
{
	if [ -f $LOG_FILE ]
	then
		#2xx
		TOTAL_REQUESTS=$(grep "2xx"  $LOG_FILE | wc -l)
		TOTAL_SUCCESS_REQUESTS=$(grep "2xx=1\|2xx=2"  $LOG_FILE | wc -l) #2xx=2 --> for every post upload we have 2 * 200OK
		SUCCESS_RATIO=$(($TOTAL_SUCCESS_REQUESTS*100/$TOTAL_REQUESTS))
		echo "!!!FINISH!!!"		
		echo "Results:"
		echo "	Success ratio = $SUCCESS_RATIO % ($TOTAL_SUCCESS_REQUESTS/$TOTAL_REQUESTS)"	
		
		#3xx
		TOTAL_3XX_REPLIES=$(grep "3xx=1"  $LOG_FILE | wc -l)
		TOTAL_3XX_2XX_REPLIES=$(grep "3xx=1"  $LOG_FILE | grep "2xx=1\|2xx=2" | wc -l)
		if [ $TOTAL_3XX_REPLIES -gt 0 ]
		then
			SUCCESS_RATIO_3XX_2XX_REPLIES=$(($TOTAL_3XX_2XX_REPLIES*100/$TOTAL_3XX_REPLIES))
		fi
		echo "	301 and 200 Success ratio = $SUCCESS_RATIO_3XX_2XX_REPLIES % ($TOTAL_3XX_2XX_REPLIES/$TOTAL_3XX_REPLIES)"
		
		#Upload tests
		if [ $TEST_POST_UPLOAD -eq 1 ]
		then
			TOTAL_POST_REQUESTS=$(grep "Success="  $LOG_FILE | wc -l)
			TOTAL_SUCCESS_POST_REQUESTS=$(grep "Success=1"  $LOG_FILE | wc -l)
			#echo "!!!TMP!!!, POST upload success ratio =  ($TOTAL_SUCCESS_POST_REQUESTS : $TOTAL_POST_REQUESTS)"
			POST_SUCCESS_RATIO=$(($TOTAL_SUCCESS_POST_REQUESTS*100/$TOTAL_POST_REQUESTS))
			echo "	POST upload success ratio = $POST_SUCCESS_RATIO % ($TOTAL_SUCCESS_POST_REQUESTS/$TOTAL_POST_REQUESTS)"	
		fi
		
		#DOWNLOAD files
		if [ $DL_CHECKED_FILES -gt 0 ]
		then
			DL_SUCCESS_RATIO=$(($DL_VALID_FILES*100/$DL_CHECKED_FILES))
			echo "	Downloaded file validate = $DL_SUCCESS_RATIO % ($DL_VALID_FILES/$DL_CHECKED_FILES)"
		fi
		
		#VAZAGET server not found
		TOTAL_VAZAGET_NOT_FOUND=$(grep "Vazaget server values NOT found"  $LOG_FILE | wc -l)
		echo "	vazaget not found's=$TOTAL_VAZAGET_NOT_FOUND"
		
		#LOG file
		echo "Full results under $LOG_FILE"
				
		echo
		echo "Running tests:"
		print_tests		
		echo
	else
		echo "$LOG_FILE not exist (maybe all tests are disabled...)"
		echo "Running tests:"
		print_tests
	fi
	
}

#############
#run_test_modules
#############
function run_test_modules
{
	if [ $TEST_IPV4 -eq 1 ] 
	then 
		basic_ipv4_test 
	fi
	
	if [ $TEST_IPV6 -eq 1 ] 
	then 
		basic_ipv6_test 
	fi
	
	if [ $TEST_PROXY -eq 1 ] 
	then 
		proxy_test 
	fi
	
	if [ $TEST_POST_UPLOAD -eq 1 ] 
	then 
		post_upload_test 
	fi
	
	if [ $TEST_RATE_LIMIT -eq 1 ] 
	then 
		rate_limit 
	fi
	
	if [ $TEST_GZIP -eq 1 ] 
	then 
		gzip_decompression 
	fi

	if [ $TEST_SSL_IPV4 -eq 1 ] 
	then 
		basic_ssl_ipv4_test
	fi

	if [ $TEST_SSL_IPV6 -eq 1 ] 
	then 
		basic_ssl_ipv6_test 
	fi
}

#####################################
# print_run_time
#####################################
function print_run_time
{
	END_TIME=$(date +%s)
	DIFF_TIME=$(( $END_TIME - $START_TIME ))	
	((sec=DIFF_TIME%60, DIFF_TIME/=60, min=DIFF_TIME%60, hrs=DIFF_TIME/60))
	timestamp=$(printf "%d:%02d:%02d" $hrs $min $sec)	
	echo "Run time = $timestamp"
}

#####################################
# main - Start point
#####################################

#set the start time
START_TIME=$(date +%s)
#delete log file before start
rm -f $LOG_FILE
#run the tests
run_test_modules
#analyze results
analyze_log
#print_run_time
print_run_time

exit
