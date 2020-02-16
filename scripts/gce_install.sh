#!/bin/sh -ex 
apt-get update
apt install git

apt-get -y install autotools-dev automake cmake build-essential doxygen \
    g++-multilib libgflags-dev libgoogle-perftools-dev pkg-config texinfo \
    libreadline-dev libtool vim software-properties-common gcc-8 g++-8

wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/cuda-ubuntu1804.pin
mv cuda-ubuntu1804.pin /etc/apt/preferences.d/cuda-repository-pin-600
apt-key adv --fetch-keys https://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/7fa2af80.pub
add-apt-repository "deb http://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/ /"
add-apt-repository "deb http://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/ /"
apt-get update
apt-get -y install cuda
apt-get update
systemctl set-default multi-user.target
sed --in-place=bak 's|^GRUB_CMDLINE_LINUX_DEFAULT.*|GRUB_CMDLINE_LINUX_DEFAULT="text"|;' /etc/default/grub
update-grub

update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 8
update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-8 8
update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 9
update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-9 9
update-alternatives --set gcc /usr/bin/gcc-8
update-alternatives --set g++ /usr/bin/g++-8
reboot
