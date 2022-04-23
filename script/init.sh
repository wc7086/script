#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#       System Required: Debian/Ubuntu
#       Description: Proxy docker script
#       Version: 0.1.0
#       Author: wc7086
#       Github: https://github.com/wc7086
#=================================================

readonly RED='\e[91m'
readonly GREEN='\e[92m'
readonly YELLOW='\e[93m'
readonly BLUE='\e[94m'
readonly MAGENTA='\e[95m'
readonly CYAN='\e[96m'
readonly NONE='\e[0m'
read LOWERPORT UPPERPORT < /proc/sys/net/ipv4/ip_local_port_range
readonly LOWERPORT
readonly UPPERPORT

menu() {
  clear
  echo -e "1.安装shadowsocks-rust
2.安装shadowsocks-libev
3.安装mtg
4.开启ssh登录通知（发送到telegram）
5.开启BBR
6.将ss登录公钥改为GitHub账户上传的公钥"
while :; do
  read -erp "请输入数字：" option
  case $option in
    0)
      break
      ;;
    1)
  esac
done
}

pause() {
  read -rsp "$(echo -e "Press ${GREEN}Enter${NONE} to continue... or ${RED}Ctrl+C${NONE} to cancel.")" -d $'\n'
  echo
}

installpkg(){ apt-get install -y "$1" >/dev/null 2>&1 ;}

start_vnstat() {
  # Start vnstat
  if [[ ! "$(docker ps -q -f name=vnstat)" ]]; then
    echo -e "${GREEN}Start vnstat${NONE}"
    # cleanup
    [[ "$(docker ps -aq -f status=exited -f name=vnstat)" ]] && docker rm vnstat
    # run your container
    docker run -d --restart=unless-stopped --network=host -e HTTP_PORT=8685 -v "/etc/localtime:/etc/localtime:ro" -v "/etc/timezone:/etc/timezone:ro" -v "/opt/script/vnstat:/var/lib/vnstat" --name vnstat --label "io.containers.autoupdate=image" docker.io/vergoh/vnstat:latest
  fi 
}

ss_config() {
  echo -e "${BLUE}Set config for Shadowsocks${NONE}"
  read -erp "Shadowsocks password:" ss_passwd
  read -erp "Shadowsocks port:" ss_port
  read -erp "Shadowsocks method:(aes-256-gcm)" ss_method
  [[ -z $ss_method ]] && ss_method="aes-256-gcm"
}

ssh_login_alert_telegram_config() {
  echo -e "${BLUE}Set ssh-login-alert-telegram${NONE}"
  read -erp "Bot token:" bot_token
  read -erp "Chat id:" chat_id
}

enable_ssh_login_alert_telegram() {
  # Set ssh-login-alert-telegram
  get_ip
  sed -i "s/example.com/${domain}/g" /opt/script/ssh-login-alert-telegram/alert.sh
  sed -i "s/getip/${ip}/g" /opt/script/ssh-login-alert-telegram/alert.sh
  sed -i "s/chatid/${chat_id}/g" /opt/script/ssh-login-alert-telegram/credentials.config
  sed -i "s/none/${bot_token}/g" /opt/script/ssh-login-alert-telegram/credentials.config
  bash /opt/script/ssh-login-alert-telegram/deploy.sh
}

mtg_config() {
  echo -e "${BLUE}Set config for mtg${NONE}"
  read -erp "Fake TLS domain (default:azure.microsoft.com):" fake_tls_domain
  [[ -z $fake_tls_domain ]] && fake_tls_domain="azure.microsoft.com"
  read -erp "Secret:" mtg_secret
  [[ -z $mtg_secret ]] && mtg_secret=$(head -c 16 /dev/urandom | xxd -ps)
  domain_hex=$(echo -n "${fake_tls_domain}" | od -A n -t x1 | sed 's/ *//g' | tr -d '\n')
  [[ $mtg_secret != ee* ]] && mtg_ee_secret="ee${mtg_secret}${domain_hex}"
  read -erp "Port:" mtg_port
  [[ -z $mtg_port ]] && mtg_port=$(comm -23 <(seq $LOWERPORT $UPPERPORT | sort) <(ss -Htan | awk '{print $4}' | cut -d':' -f2 | sort -u) | shuf | head -n 1)
}

init_container() {
  docker compose -f /opt/script/${1}/docker-compose.yaml up -d
}

delete_container() {
  docker compose -f /opt/script/${1}/docker-compose.yaml down
}

start_container() {
  docker compose -f /opt/script/${1}/docker-compose.yaml start
}

stop_container() {
  docker compose -f /opt/script/${1}/docker-compose.yaml stop
}

restart_container() {
  docker compose -f /opt/script/${1}/docker-compose.yaml restart
}


enable_bbr() {
  # Enable bbr
  if [[ -z $(lsmod | grep bbr) ]]; then
    echo -e "${GREEN}Start bbr${NONE}"
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
  fi
}

install_docker() {
  # Install docker and Docker compose
  # Install docker
  if [[ ! -x $(command -v docker) ]]; then
    echo -e "${GREEN}Install docker${NONE}" >&2
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update >/dev/null 2>&1
    installpkg docker-ce docker-ce-cli containerd.io
  fi

  # Install docker-compose
  if [[ ! -x $(command -v docker-compose) ]]; then
    DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}
    mkdir -p $DOCKER_CONFIG/cli-plugins
    compose_version=`wget -qO- -t1 -T2 "https://api.github.com/repos/docker/compose/releases/latest" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g'`
    curl -SL https://github.com/docker/compose/releases/download/$compose_version/docker-compose-linux-x86_64 -o $DOCKER_CONFIG/cli-plugins/docker-compose
    chmod +x $DOCKER_CONFIG/cli-plugins/docker-compose
  fi
}

installnetfilter_full_cone_nat() {
  installpkg autoconf build-essential git libtool libgmp3-dev linux-image-$(uname -r) linux-headers-amd64 pkg-config -y
  cd ~
  mkdir fullcone
  cd fullcone
  git clone git://git.netfilter.org/libmnl.git --depth=1
  git clone git://git.netfilter.org/libnftnl.git --depth=1
  git clone git://git.netfilter.org/iptables.git --depth=1
  git clone https://github.com/Chion82/netfilter-full-cone-nat.git --depth=1
  cd ~/fullcone/libmnl && sh autogen.sh && ./configure && make && make install
  cd ~/fullcone/libnftnl && sh autogen.sh && ./configure && make && make install
  cd ~/fullcone/netfilter-full-cone-nat && make && modprobe nf_nat && insmod xt_FULLCONENAT.ko && mv ~/fullcone/netfilter-full-cone-nat/xt_FULLCONENAT.ko  /lib/modules/$(uname -r)/ && depmod && echo "xt_FULLCONENAT" > /etc/modules-load.d/fullconenat.conf
  cp ~/fullcone/netfilter-full-cone-nat/libipt_FULLCONENAT.c ~/fullcone/iptables/extensions/
  cd ~/fullcone/iptables && ./autogen.sh && ./configure && make && make install
}

get_ip() {
  ip=$(curl -s --connect-timeout 3 https://ipinfo.io/ip)
  [[ -z $ip ]] && ip=$(curl -s --connect-timeout 3 https://api.ip.sb/ip)
  [[ -z $ip ]] && ip=$(curl -s --connect-timeout 3 https://api.ipify.org)
  [[ -z $ip ]] && ip=$(curl -s --connect-timeout 3 https://ip.seeip.org)
  [[ -z $ip ]] && ip=$(curl -s --connect-timeout 3 https://ifconfig.co/ip)
  [[ -z $ip ]] && ip=$(curl -s --connect-timeout 3 https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
  [[ -z $ip ]] && ip=$(curl -s --connect-timeout 3 icanhazip.com)
  [[ -z $ip ]] && ip=$(curl -s --connect-timeout 3 myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
  [[ -z $ip ]] && echo -e "\n${RED}Failed to get IP! Fuck all!${NONE}\n" && exit
}

set_ssh_key() {
  # Set ssh key
  bash sshkey.sh -og $github_name -p $ssh_port -d
}

echo_config() {
  echo -e "${GREEN}shadowsocks config${NONE}
Port=${BLUE}${ss_port}${NONE}
Password:${BLUE}${ss_passwd}${NONE}
Method:${BLUE}${ss_method}${NONE}\n"

  [[ $mtg == true ]] && echo -e "${GREEN}mtg config${NONE}
Port=${BLUE}${mtg_port}${NONE}
Secret=${BLUE}$([[ -z $mtg_ee_secret ]] && echo ${mtg_secret} || echo $mtg_ee_secret)${NONE}
Fake TLS domain:${BLUE}${fake_tls_domain}${NONE}\n"

  [[ $init_ssh_login_alert_telegram == true ]] && echo -e "${GREEN}ssh-login-alert-telegram config${NONE}
Bot Token:${BLUE}${bot_token}${NONE}
chat ID:${BLUE}${chat_id}${NONE}\n"

  [[ $ssh_key == true ]] && echo -e "${GREEN}ssh key config${NONE}
Github Name:${BLUE}${github_name}${NONE}
SSH port:${BLUE}${ssh_port}${NONE}\n"

  echo -e "Install Shadowsocks-rust:${YELLOW}true${NONE}
Install mtg:${YELLOW}${mtg}${NONE}
Enable ssh-login-alert-telegram:${YELLOW}${init_ssh_login_alert_telegram}${NONE}"
}

encodeURIComponent() {
  echo -n "$@" | hexdump -v -e '/1 "%02x"' | sed 's/\(..\)/%\1/g'
}

decodeURIComponent() {
  echo -n "$@" | sed "s@+@ @g;s@%@\\\\x@g" | xargs -0 printf "%b"
}

write_config() {

  # Set config for Shadowsocks-rust
  sed -i "s/ss_port/${ss_port}/g" /opt/script/shadowsocks-rust/config.json
  sed -i "s/ss_passwd/${ss_passwd}/g" /opt/script/shadowsocks-rust/config.json
  sed -i "s/ss_method/${ss_method}/g" /opt/script/shadowsocks-rust/config.json
  echo -e "${MAGENTA}shadowsocks config${NONE}
Port=${BLUE}${ss_port}${NONE}
Password:${BLUE}${ss_passwd}${NONE}
Method:${BLUE}${ss_method}${NONE}
Sharing link:
${YELLOW}ss://$(echo -n "${ss_method}:${ss_passwd}@${domain}:${ss_port}" | base64 | tr -d '\n')#$(encodeURIComponent ss@${domain}${NONE})
" >> all.config

  if [[ $mtg == true ]]; then
    # Set config for mtg
    if [[ $mtg_secret == ee* ]]; then
      sed -i "s/mtgsecret/${mtg_secret}/g" /opt/script/mtg/mtg.toml
    else
      sed -i "s/mtgsecret/${mtg_ee_secret}/g" /opt/script/mtg/mtg.toml
    fi
    sed -i "s/5555/${mtg_port}/g" /opt/script/mtg/docker-compose.yaml
    echo -e "${MAGENTA}mtg config${NONE}
Port=${BLUE}${mtg_port}${NONE}
Secret=${BLUE}$([[ -z $mtg_ee_secret ]] && echo ${mtg_secret} || echo $mtg_ee_secret)${NONE}
Fake TLS domain:${BLUE}${fake_tls_domain}${NONE}
Sharing link:
${YELLOW}https://t.me/proxy?server=${domain}&port=${mtg_port}&secret=$([[ -z $mtg_ee_secret ]] && echo ${mtg_secret} || echo $mtg_ee_secret)${NONE}
" >> all.config
  fi
}

main() {
  [[ $(cat /etc/issue) != Debian* ]] && echo "Only Debian is supported!" && exit 0

  ss_config

  # Do you want to install Netfilter-Full-Cone-Nat?
#  while :; do
#    read -erp "Do you want to install common Netfilter-Full-Cone-Nat? [y/N] " input
#    [[ -z $input ]] && input="n"
#    case $input in
#      [yY][eE][sS]|[yY])
#        netfilter_full_cone_nat=true
#        break
#        ;;
#      [nN][oO]|[nN])
#        echo "No"
#        netfilter_full_cone_nat=false
#        break
#        ;;
#      *)
#        echo "Invalid input..."
#        ;;
#    esac
#  done

  # mtg
  while :; do
    read -erp "Do you want to install mtg? [Y/n] " input
    [[ -z $input ]] && input="y"
    case $input in
      [yY][eE][sS]|[yY])
        mtg_config
        mtg=true
        break
        ;;
      [nN][oO]|[nN])
        echo "No"
        mtg=false
        break
        ;;
      *)
        echo "Invalid input..."
        ;;
    esac
  done

  # ssh-login-alert-telegram
  while :; do
    read -erp "Do you want to enable ssh-login-alert-telegram? [Y/n] " input
    [[ -z $input ]] && input="y"
    case $input in
      [yY][eE][sS]|[yY])
        ssh_login_alert_telegram_config
        init_ssh_login_alert_telegram=true
        break
        ;;
      [nN][oO]|[nN])
        echo "No"
        init_ssh_login_alert_telegram=false
        break
        ;;
      *)
        echo "Invalid input..."
        ;;
    esac
  done

  # ssh key
  while :; do
    read -erp "Are you sure you want to change the SSH login key to the SSH key of your GitHub account? [y/N] " input
    [[ -z $input ]] && input="n"
    case $input in
      [yY][eE][sS]|[yY])
        echo -e "${BLUE}Set config for SSH key${NONE}"
        read -erp "Github Name:" github_name
        read -erp "Port:" ssh_port
        [[ -z $ssh_port ]] && ssh_port=$(comm -23 <(seq $LOWERPORT $UPPERPORT | sort) <(ss -Htan | awk '{print $4}' | cut -d':' -f2 | sort -u) | shuf | head -n 1)
        ssh_key=true
        break
        ;;
      [nN][oO]|[nN])
        echo "No"
        ssh_key=false
        break
        ;;
      *)
        echo "Invalid input..."
        ;;
    esac
  done

  echo_config

  pause

  timedatectl set-timezone Asia/Shanghai
  
  enable_bbr

  for x in lsb-release curl ca-certificates git ntp gnupg wget htop; do
	  echo -e "Installing \`$x\` which is required to install and configure other programs."
	  installpkg "$x"
  done

  git clone https://github.com/wc7086/script.git /opt/script

  echo -e '# Sync hwclock.\nSYNC_HWCLOCK=yes' >> /etc/ntp.conf
  systemctl enable --now ntpd

  #[[ $netfilter_full_cone_nat == true ]] && [[ -z $(lsmod | grep xt_FULLCONENAT) ]] && installnetfilter_full_cone_nat && cd /opt/script/script

  install_docker

  start_vnstat

  write_config

  init_container shadowsocks-rust

  # Set permissions for grpc.sock
  [[ $mtg == true ]] && init_container mtg
  [[ $init_ssh_login_alert_telegram == true ]] && enable_ssh_login_alert_telegram && echo -e "${MAGENTA}ssh-login-alert-telegram config${NONE}
Bot Token:${BLUE}${bot_token}${NONE}
chat ID:${BLUE}${chat_id}${NONE}
" >> all.config
  [[ $ssh_key == true ]] && set_ssh_key && echo -e "${MAGENTA}ssh key config${NONE}
Github Name:${BLUE}${github_name}${NONE}
SSH public key:${BLUE}$(curl -fsSL https://github.com/${github_name}.keys)${NONE}
SSH port:${BLUE}${ssh_port}${NONE}
" >> all.config
  cat all.config
}
main
