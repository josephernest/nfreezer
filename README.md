# nFreezer

https://nfreezer.com

![](https://user-images.githubusercontent.com/6168083/100474871-f8825d00-30e1-11eb-8e74-6321aafe2151.png)

**nFreezer** (for *e<b>n</b>crypted freezer*) is an **encrypted-at-rest backup tool**, designed specifically for the case when the destination server is *untrusted*. With nFreezer, the data is safe on the destination server **even** if a malicious user gets root access to it.  
Use case: you can store your private data on a friend's computer, or on a remote server on which you never had physical access and that you don't fully trust.

## Features

* **encrypted-at-rest**: the data is encrypted locally (using AES), then transits encrypted, and *stays encrypted* on the destination server. The destination server never gets the encryption key, the data is never decrypted on the destination server.
        
* **incremental and resumable**: if the data is already there on the remote server, it won't be resent during the next sync. If the sync is interrupted in the middle, it will continue where it stopped (last non-fully-uploaded file). Deleted or modified files in the meantime will of course be detected.

* ![image](https://user-images.githubusercontent.com/6168083/100476609-4f8a3100-30e6-11eb-8d16-cc59b352576e.png) **graceful file moves/renames/data duplication handling**: if you move `/path/to/10GB_file` to `/anotherpath/subdir/10GB_file_renamed`, no data will be re-transferred over the network.

  This is supported by some other sync programs, but *very rarely* in encrypted-at-rest mode.

  Technical sidenote: the SHA256 hashes of the unencrypted files are stored *encrypted* on the destination (phew!). Thus, no SHA256 hash could be accessed (to get information about your data) in the event of a breach on the destination server.

* **stateless**: no local database of the files present on destination is kept. Drawback: this means that if the destination already contains 100,000 files, the local computer needs to download the remote filelist (~15MB) before starting a new sync; but this is acceptable for me.

* **does not need to be installed on remote**: no binary needs to be installed on remote, no SSH "execute commands" on the remote, only SFTP is used

* **single .py file project**: you can read and audit the full source code by looking at `nfreezer.py`, which is currently < 300 lines of code.

## Installation 

You need Python 3.6+, and to do:

    pip install nfreezer

and that's all.

(An alternative installation method is to install the requirements with `pip install pysftp pycryptodome` and just copy the single file `nfreezer.py` where you want to use it.)

## Usage

### Backup to a remote server

    import nfreezer
    nfreezer.backup(src='test/', dest='user@192.168.0.2:/test/', sftppwd='pwd', encryptionpwd='strongpassword')

or, from command-line:

    nfreezer backup test/ user@192.168.0.2:/test/          # Linux
    nfreezer backup "D:\My docs\" user@192.168.0.2:/test/  # Windows

### Restore from a backup

    import nfreezer
    nfreezer.restore(src='user@192.168.0.2:/test/', dest='restored/', sftppwd='pwd', encryptionpwd='strongpassword')

or, from command-line: 

    nfreezer restore user@192.168.0.2:/test/ restored/

Alternatively, if you prefer, you can also copy the remote backuped files (encrypted-at-rest) to a local directory `backup_copied/` and restore with nFreezer from this local directory:

    nfreezer restore backup_copied/ restored/

## Comparison

These are the key points that were important *for me*, and that's why I coded this tool, but I totally agree it's subjective, and one could easily make a similar table with all the boxes checked for another program and none for mine.

Not handling renames gracefully (and thus retransfer data over the network again and again) was a no-go for me because I often move or rename directories containing multimedia projects with gigabytes of data.

| - | nFreezer | Rsync | Rclone | Syncthing | Duplicity |
|:-:|:-:|:-:|:-:|:-:|:-:|
| encrypted-at-rest  | ⚫ |   | ⚫ <br>([Crypt](https://rclone.org/crypt/))  | ⚪ <br> (experimental) | ⚫ |
| no local database  | ⚫ | ⚫  | ⚫  |  | ?
| no install needed on remote  | ⚫ |  | ⚫  |   | ?
| [handles renames gracefully](#Features) | ⚫ | (surprisingly,<br>no) | (not with Crypt) | ⚫ | 

## Contribution

In order to keep the small-single-file requirement and because maintaining and merging code is a demanding task, this project currently does not accept pull requests.

However, Github issues, including snippets of code, are welcome.

## Development 

This software is in the early stages of its distribution, at the time of writing (Nov. 2020), so use it at your own risk, and please don't use it for data for which you don't have other backup.

## Author

Joseph Ernest

## License

MIT with free-of-charge-redistribution clause, see the LICENSE file.
