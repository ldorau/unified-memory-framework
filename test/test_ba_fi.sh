#/bin/bash

TEST=$1

UMF_BA_FI_MAX=$(UMF_BA_FI=99999999 $TEST 2>&1 | grep UMF_BA_FI | cut -d" " -f2 | sort -n -r | head -n1)
echo "UMF_BA_FI_MAX=$UMF_BA_FI_MAX"

UMF_BA_FI_N=$UMF_BA_FI_MIN
[ "$UMF_BA_FI_N" = "" ] && UMF_BA_FI_N=1

while [ $UMF_BA_FI_N -le $UMF_BA_FI_MAX ]; do
	echo "Running: UMF_BA_FI=$UMF_BA_FI_N $TEST"
	UMF_BA_FI=$UMF_BA_FI_N $TEST
	RV=$?
	echo RV=$RV
	if [ $RV -gt 100 ]; then
		echo "UMF_BA_FI_N=$UMF_BA_FI_N"
		echo RV=$RV
		break;
	fi
	UMF_BA_FI_N=$(($UMF_BA_FI_N + 1))
done
