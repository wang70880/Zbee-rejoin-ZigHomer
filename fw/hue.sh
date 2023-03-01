atusb(){
	output=$(iwpan dev)
	output1=$(echo $output | awk -F' ' '{print $1}')   #    PHY#23, for example
	seq=$(echo $output1 | awk -F'#' '{print $2}')   # Get 23

	command1='sudo iwpan phy phy%s interface add attack0 type monitor'
	command1=$(printf "$command1" $seq)

	command2='sudo iwpan phy phy%s set channel 0 11'
	command2=$(printf "$command2" $seq)

	sudo iwpan dev wpan0 del
	eval $command1
	eval $command2
}

atusb_start(){
	sudo make clean
	sudo make dfu ATTACKID=1
	sleep 4
	atusb
	command1="sudo ip link set attack0 up"
	eval $command1
}

atusb_stop(){
	command1="sudo ip link set attack0 down"
	eval $command1
}

atusb_start
#atusb_stop

