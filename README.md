# JunkDrawer

Static file server and backup storage app

```
git clone https://github.com/ology/JunkDrawer.git
cd JunkDrawer
cpanm --installdeps .
sqlite3 auth.db < auth.sql
perl user.pl you your.email@example.com # create app user
mkdir /Volumes/YourBackupDrive/backups/you # app user folder
ln -s /Volumes/YourBackupDrive/backups Backup # symlink to your backups
morbo junkdrawer.pl --verbose --listen http://127.0.0.1:3333 # for example
```
