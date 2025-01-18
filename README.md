# JunkDrawer

Static file server and backup storage app

```
mkdir /Volumes/YourBackupDrive/backups/you # app user folder
git clone https://github.com/ology/JunkDrawer.git
cd JunkDrawer
sqlite3 auth.db < auth.sql
perl user.pl you your.email@example.com # create app user
ln -s /Volumes/YourBackupDrive/backups JunkDrawer # symlink to your backups
morbo junkdrawer.pl # http://127.0.0.1:3000
```
