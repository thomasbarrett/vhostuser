# vhostuser

# Testing
The easiest way to test the vhostuser library is with qemu.

The following command can be used to download an ubuntu 22.04 cloud image.
```
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
virt-customize -a jammy-server-cloudimg-amd64.img --root-password password:test
```

The following command can be used to start a qemu virtual machine with a vhostuser block device.
```
/usr/libexec/qemu-kvm \
-machine type=q35,accel=kvm \
-smp 4 -cpu host \
-m 4096 \
-object memory-backend-memfd,id=mem0,size=4G,share=on \
-numa node,memdev=mem0 \
-nographic -display none \
-drive file=jammy-server-cloudimg-amd64.img,format=qcow2 \
-netdev user,id=user.0,hostfwd=tcp::8888-:22 \
-device virtio-net,netdev=user.0 \
-chardev socket,id=char1,path=/tmp/vhost-blk.sock,reconnect=1 \
-device vhost-user-blk-pci,chardev=char1 \
-monitor none
```
