sudo cp ./deploy/vinescribe.service /etc/systemd/system/vinescribe.service
sudo cp ./deploy/vinescribe.timer /etc/systemd/system/vinescribe.timer

sudo systemctl daemon-reload
sudo systemctl enable vinescribe.timer
sudo systemctl start vinescribe.timer

sudo systemctl restart vinescribe.timer