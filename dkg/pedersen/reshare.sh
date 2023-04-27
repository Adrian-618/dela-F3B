
#!/bin/sh
for n in 8 16 32 64 128
do
    for nn in $(($n*1/4))
        do
            nc=${nc%.*}
            #echo $nc
            LLVL=warn go test -run TestResharingRecords -timeout 0 -args -nOld=$n -nCommon=$n -nNew=$nn
            sleep 10
        done
done

# for n in 8 16 32 64 128
# do
#     for nc in $n 
#         do
#             nc=${nc%.*}
#             #echo $nc
#             LLVL=warn go test -run TestResharingRecords -timeout 0 -args -nOld=$n -nCommon=$nc -nNew=1
#             sleep 30
#         done
# done

#echo "nOld,nCommon,nNew,setupTime,resharingTime" >> resharing_records.csv; \
# $(($n-1))  $(($n*3/4))