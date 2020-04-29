# -*- mode: ruby -*-
# vi: set ft=ruby :

#
# VMs created with this file is for educational purposes only
# They are insecure!!!
#


$script = <<-SCRIPT
yum check-update && sleep 5
yum install -y epel-release && sleep 5
yum install -y ansible git && sleep 5

echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config

sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
systemctl restart sshd

adduser devops
mkdir /home/devops/.ssh
echo "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAg51XuJIeEQvuZjyWtfygpaJ8jZ1YscGQrUivowZpX+weZTRn
V5ZRoxmKS0pFcjSn+gGVAE7g60VkwZmmtsBjcu+GkYKes6kD5RE4bxr25CHTQwD1
6MVQfs6KmFO79idyRJj3ZJzwaUBJxmofRZtQ5Vora2bGSASKsGsFAvD4QZc/2Tb5
Ns+UcZ2W3h0jp3siD3dTpbV9P+HUDHptjLEmc4EynPJTPO1p8OExGk64shR64U/m
WdWV5eTZP39FXXde4SqbAkGyoqhpol/YrXeIW5Ru2ZfrQq3iXWWRk55rWn3BibK5
zNa29M4jYv5mNPfX2RDpWJV5stM1euFTqXYoFwIBJQKCAQB48XMz++RHBAuAirQB
LVVZ70IFl4Hvc5mz/Zp6IZFDY1ozfENJkQy/Y5PWe5nC5EdUcCgOHvgyJBdly3aa
GJK8pMDYvTfjXQp/d5ukXfehM9bjoASQtVDjOlXYFZf289DJafgXRBswSOnY6+Vi
jrkKG4HYUJqHXh6URqqowcGIYB1WVIde6NKh+yk/wJChNDmSg6V1zYUi3YrKuvgX
LtnpQLwqoXOn1r0LEutM3dMIvy9O4qR8SEnAyJbzM6ydAZlbJWq07RTPKzWrE44q
8qEdMaSS+T0oKcwQRMOaX7vLgjiP508Vr6pL4ahtVLWQpkVfVF7VKcZ3upI2s7ht
FTM9AoGBAOq+CFra47/EoAblOciulyG9RbqH1LVOK2soMoqmSzFy7tYogGSH2D8Z
enKIlhlkIO5cVDdD9CVLvOWBnGW0CQ+qzhpe5gD2bvsB3OsGDATAApnV0n+2LidE
uvMGMdXzwKVzQZFJwv1YUDa0VjQiFxIkcsuPSgE87JdcTVWWBP+LAoGBAI+Ih1ZW
hQ2TTh9RoNuy39/JVwq0ROQ8tkLLbVxy0RbsJkRkK6WNfk4PHXM2iv1qFG+gFBo0
R3qxxiJL0El3Cq/as8jAWbGdmXf87aXD+hCDVEeRAXvRu6hSQauSmv29+rFbuTRU
455oCFsKgLfISfKuwk0sngJdBP8BKsRvjsslAoGBAL5U5C39lhEb91+JbR9Bc57Q
0MDBKQG1AJwSwTIl98c6mCNDbwVnObafCVXyNINKRDbjE9nIZRdSKnTloWc4B1jP
rgeLNwezDeBGsx9sr8yAAhvdzUT0lB/W3MUL8Q5W7zoKbIOjly5HmvvsKjgbpADf
SFIFekYxZeKCMN2cO2dpAoGAZNx6xwxdfyk90NGToU1DXvwvU6FFKsLg8Kqf4BlU
qFLqdT94ndkMpY4UsdNM6W0jHgHI79G1sCnlLNtUF/LJPU2TF3JoiqYY0Ns/Njav
uJOjAduEgIWKyU6PAvFl/mnSwdHAafZ2b1AF3xwjGVxPo51l8QqYjAoDgsKMwWMm
EjUCgYEAtiG8y8YzTZJCWdJJbao1i4AGB1BQ+mb66lUouFP0GzaWoU4KqN/vLiMh
+mlC84uvFxT9bhKzh0Go0l6iM2iVye7SAOgMnZbTExeHlXEIbF5rsifRRbfT9UsE
ocCwvEVA5D3GJBkQ3zVMogt20m1mh5ktDw4isGR9ZMs2rtW0yWM=
-----END RSA PRIVATE KEY-----
" > /home/devops/.ssh/id_rsa
openssl rsa -in /home/devops/.ssh/id_rsa -pubout > /home/devops/.ssh/id_rsa.pub
echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAg51XuJIeEQvuZjyWtfygpaJ8jZ1YscGQrUivowZpX+weZTRnV5ZRoxmKS0pFcjSn+gGVAE7g60VkwZmmtsBjcu+GkYKes6kD5RE4bxr25CHTQwD16MVQfs6KmFO79idyRJj3ZJzwaUBJxmofRZtQ5Vora2bGSASKsGsFAvD4QZc/2Tb5Ns+UcZ2W3h0jp3siD3dTpbV9P+HUDHptjLEmc4EynPJTPO1p8OExGk64shR64U/mWdWV5eTZP39FXXde4SqbAkGyoqhpol/YrXeIW5Ru2ZfrQq3iXWWRk55rWn3BibK5zNa29M4jYv5mNPfX2RDpWJV5stM1euFTqXYoFw== devop_privat" > /home/devops/.ssh/authorized_keys
chown -R devops:devops /home/devops
chmod 400 /home/devops/.ssh/id_rsa

echo "devops:password" | chpasswd

adduser ansible
mkdir /home/ansible/.ssh
echo "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAg51XuJIeEQvuZjyWtfygpaJ8jZ1YscGQrUivowZpX+weZTRn
V5ZRoxmKS0pFcjSn+gGVAE7g60VkwZmmtsBjcu+GkYKes6kD5RE4bxr25CHTQwD1
6MVQfs6KmFO79idyRJj3ZJzwaUBJxmofRZtQ5Vora2bGSASKsGsFAvD4QZc/2Tb5
Ns+UcZ2W3h0jp3siD3dTpbV9P+HUDHptjLEmc4EynPJTPO1p8OExGk64shR64U/m
WdWV5eTZP39FXXde4SqbAkGyoqhpol/YrXeIW5Ru2ZfrQq3iXWWRk55rWn3BibK5
zNa29M4jYv5mNPfX2RDpWJV5stM1euFTqXYoFwIBJQKCAQB48XMz++RHBAuAirQB
LVVZ70IFl4Hvc5mz/Zp6IZFDY1ozfENJkQy/Y5PWe5nC5EdUcCgOHvgyJBdly3aa
GJK8pMDYvTfjXQp/d5ukXfehM9bjoASQtVDjOlXYFZf289DJafgXRBswSOnY6+Vi
jrkKG4HYUJqHXh6URqqowcGIYB1WVIde6NKh+yk/wJChNDmSg6V1zYUi3YrKuvgX
LtnpQLwqoXOn1r0LEutM3dMIvy9O4qR8SEnAyJbzM6ydAZlbJWq07RTPKzWrE44q
8qEdMaSS+T0oKcwQRMOaX7vLgjiP508Vr6pL4ahtVLWQpkVfVF7VKcZ3upI2s7ht
FTM9AoGBAOq+CFra47/EoAblOciulyG9RbqH1LVOK2soMoqmSzFy7tYogGSH2D8Z
enKIlhlkIO5cVDdD9CVLvOWBnGW0CQ+qzhpe5gD2bvsB3OsGDATAApnV0n+2LidE
uvMGMdXzwKVzQZFJwv1YUDa0VjQiFxIkcsuPSgE87JdcTVWWBP+LAoGBAI+Ih1ZW
hQ2TTh9RoNuy39/JVwq0ROQ8tkLLbVxy0RbsJkRkK6WNfk4PHXM2iv1qFG+gFBo0
R3qxxiJL0El3Cq/as8jAWbGdmXf87aXD+hCDVEeRAXvRu6hSQauSmv29+rFbuTRU
455oCFsKgLfISfKuwk0sngJdBP8BKsRvjsslAoGBAL5U5C39lhEb91+JbR9Bc57Q
0MDBKQG1AJwSwTIl98c6mCNDbwVnObafCVXyNINKRDbjE9nIZRdSKnTloWc4B1jP
rgeLNwezDeBGsx9sr8yAAhvdzUT0lB/W3MUL8Q5W7zoKbIOjly5HmvvsKjgbpADf
SFIFekYxZeKCMN2cO2dpAoGAZNx6xwxdfyk90NGToU1DXvwvU6FFKsLg8Kqf4BlU
qFLqdT94ndkMpY4UsdNM6W0jHgHI79G1sCnlLNtUF/LJPU2TF3JoiqYY0Ns/Njav
uJOjAduEgIWKyU6PAvFl/mnSwdHAafZ2b1AF3xwjGVxPo51l8QqYjAoDgsKMwWMm
EjUCgYEAtiG8y8YzTZJCWdJJbao1i4AGB1BQ+mb66lUouFP0GzaWoU4KqN/vLiMh
+mlC84uvFxT9bhKzh0Go0l6iM2iVye7SAOgMnZbTExeHlXEIbF5rsifRRbfT9UsE
ocCwvEVA5D3GJBkQ3zVMogt20m1mh5ktDw4isGR9ZMs2rtW0yWM=
-----END RSA PRIVATE KEY-----
" > /home/ansible/.ssh/id_rsa
openssl rsa -in /home/ansible/.ssh/id_rsa -pubout > /home/ansible/.ssh/id_rsa.pub
echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAg51XuJIeEQvuZjyWtfygpaJ8jZ1YscGQrUivowZpX+weZTRnV5ZRoxmKS0pFcjSn+gGVAE7g60VkwZmmtsBjcu+GkYKes6kD5RE4bxr25CHTQwD16MVQfs6KmFO79idyRJj3ZJzwaUBJxmofRZtQ5Vora2bGSASKsGsFAvD4QZc/2Tb5Ns+UcZ2W3h0jp3siD3dTpbV9P+HUDHptjLEmc4EynPJTPO1p8OExGk64shR64U/mWdWV5eTZP39FXXde4SqbAkGyoqhpol/YrXeIW5Ru2ZfrQq3iXWWRk55rWn3BibK5zNa29M4jYv5mNPfX2RDpWJV5stM1euFTqXYoFw== devop_privat" > /home/ansible/.ssh/authorized_keys

cd /home/ansible/
git clone https://github.com/tothti/ansible.git

chown -R ansible:ansible /home/ansible
chmod 400 /home/ansible/.ssh/id_rsa

echo "ansible:password" | chpasswd


echo "192.168.56.10 ansible" >> /etc/hosts
echo "192.168.56.20 web1" >> /etc/hosts
echo "192.168.56.30 web2" >> /etc/hosts

SCRIPT

$script2 = <<-SCRIPT
adduser ansible
mkdir /home/ansible/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAg51XuJIeEQvuZjyWtfygpaJ8jZ1YscGQrUivowZpX+weZTRnV5ZRoxmKS0pFcjSn+gGVAE7g60VkwZmmtsBjcu+GkYKes6kD5RE4bxr25CHTQwD16MVQfs6KmFO79idyRJj3ZJzwaUBJxmofRZtQ5Vora2bGSASKsGsFAvD4QZc/2Tb5Ns+UcZ2W3h0jp3siD3dTpbV9P+HUDHptjLEmc4EynPJTPO1p8OExGk64shR64U/mWdWV5eTZP39FXXde4SqbAkGyoqhpol/YrXeIW5Ru2ZfrQq3iXWWRk55rWn3BibK5zNa29M4jYv5mNPfX2RDpWJV5stM1euFTqXYoFw== devop_privat" > /home/ansible/.ssh/authorized_keys
chown -R ansible:ansible /home/ansible

echo "ansible:password" | chpasswd

echo "ansible ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers.d/ansible

sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
systemctl restart sshd

SCRIPT


Vagrant.configure("2") do |config|
  config.vm.box = "centos/7"
  config.vbguest.auto_update = false
  config.vm.provider "virtualbox" do |vb|
    vb.cpus = "1"
	vb.customize ["modifyvm", :id, "--cpuexecutioncap", "50"]
    vb.memory = "512"
    vb.gui = false
  end

  config.vm.define "ans" do |ans|
    ans.vm.hostname = "ansible"
    ans.vm.network "private_network", ip: "192.168.56.10"
    ans.vm.provision "shell", "inline": $script
  end

  config.vm.define "web1" do |web1|
    web1.vm.hostname = "web1"
    web1.vm.network "private_network", ip: "192.168.56.20"
    web1.vm.provision "shell", "inline": $script2
  end

  config.vm.define "web2" do |web2|
    web2.vm.hostname = "web2"
    web2.vm.network "private_network", ip: "192.168.56.30"
    web2.vm.provision "shell", "inline": $script2
  end



end
