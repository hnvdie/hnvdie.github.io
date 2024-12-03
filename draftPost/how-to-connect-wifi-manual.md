DRAFT: cara connect wifi di linux secara manual menggunakan nmcli (NetworkManager CLI)



sudo systemctl status NetworkManager
sudo systemctl start NetworkManager


sudo nmcli # check status wifi connected or not 
sudo nmcli device wifi list (checking all AP nearby)
sudo nmcli devuce wifi connect "AP name" password "AP password"

