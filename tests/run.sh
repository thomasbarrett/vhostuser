#!/bin/sh
failed=0
llvm_cov_objects=""
for test in $@
do
    if [ -f $test ] 
    then
        basename=${test%.*}
        export LLVM_PROFILE_FILE="profraw/${basename#bin/tests/}.profraw"
        output="$($test 2>&1)"
        if [ $? -eq "0" ]
        then
            printf "\033[0;32m[ PASS ]\033[0m $test\n"
        else
            printf "\033[0;31m[ FAIL ]\033[0m $test\n"
            printf "$output\n"
            failed=$((failed+1))
        fi
        llvm_cov_objects+=" --object $test"
    else
        printf "\033[0;33m[ NONE ]\033[0m $test\n"
    fi
done
llvm-profdata merge -sparse profraw/* -o default.profdata
llvm-cov report $llvm_cov_objects --instr-profile=default.profdata  --ignore-filename-regex="(tests/.*)|(.*\.h)"
echo ""
if [ $failed -eq "0" ]
then
    printf "\033[0;32mFailed $failed Tests\033[0m\n"
else
    printf "\033[0;31mFailed $failed Tests\033[0m\n"
fi
exit $failed
