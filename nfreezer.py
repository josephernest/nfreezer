"""
nFreezer is an encrypted-at-rest backup tool.

Homepage and documentation: https://github.com/josephernest/nfreezer

Copyright (c) 2020, Joseph Ernest. See also LICENSE file.

==CHANGELOG==
* done: restore: if file already exists locally with same hash, skip the transfer
* done: restore: restore original mtime_ns
* done: PyPI ready
* done: command-line script
* done: encrypt/decrypt files bigger than RAM (work by blocks)
* done: restore also from SFTP
* later: use a DEK + KEK schreme (data encryption key + key encryption key)
* later: compact the destination file list database
==CHANGELOG==
"""

import pysftp, getpass, paramiko, glob, os, hashlib, io, Crypto.Random, Crypto.Protocol.KDF, Crypto.Cipher.AES, uuid, zlib, time, pprint, sys, contextlib, tqdm

NULL16BYTES, NULL32BYTES = b'\x00' * 16, b'\x00' * 32
BLOCKSIZE = 16*1024*1024  # 16 MB
larger_files_first = True

@contextlib.contextmanager  
def nullcontext():  # from contextlib import nullcontext for Python 3.7+
    yield None

def get_size(path):
    try: return os.stat(path).st_size
    except: return 0

def getsha256(f):
    sha256 = hashlib.sha256()
    with open(f, 'rb') as g:
        while True:
            block = g.read(BLOCKSIZE)
            if not block:
                break
            sha256.update(block)
    return sha256.digest()

_KEYCACHE = dict()

def KDF(pwd, salt=None):
    if salt is None:
        salt = Crypto.Random.new().read(16)
    key = Crypto.Protocol.KDF.PBKDF2(pwd, salt, count=100*1000)
    return key, salt

def encrypt(f=None, s=None, key=None, salt=None, out=None):
    if out is None:
        out = io.BytesIO()
    if f is None:
        f = io.BytesIO(s)
    nonce = Crypto.Random.new().read(16)
    out.write(salt)
    out.write(nonce)
    out.write(NULL16BYTES)  # placeholder for tag
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_GCM, nonce=nonce)
    while True:
        block = f.read(BLOCKSIZE)
        if not block:
            break
        out.write(cipher.encrypt(block))
    out.seek(32)
    out.write(cipher.digest())  # tag
    out.seek(0)
    return out

def decrypt(f=None, s=None, pwd=None, out=None):
    if out is None:
        out = io.BytesIO()
    if f is None:
        f = io.BytesIO(s)
    salt = f.read(16)
    nonce = f.read(16)
    tag = f.read(16)
    if salt not in _KEYCACHE:
        _KEYCACHE[salt] = KDF(pwd, salt)[0]
    cipher = Crypto.Cipher.AES.new(_KEYCACHE[salt], Crypto.Cipher.AES.MODE_GCM, nonce=nonce)    
    while True:
        block = f.read(BLOCKSIZE)
        if not block:
            break
        out.write(cipher.decrypt(block))
    try:
        cipher.verify(tag)
    except ValueError:
        print('Incorrect key or file corrupted.')
    out.seek(0)
    return out

def newdistantfileblock(chunkid, mtime, fsize, h, fn, key=None, salt=None):
    newdistantfile = zlib.compress(chunkid + mtime.to_bytes(8, byteorder='little', signed=False) + fsize.to_bytes(8, byteorder='little') + h + fn.encode())
    s = encrypt(s=newdistantfile, key=key, salt=salt).read()    
    return (len(s)).to_bytes(4, byteorder='little') + s

def readdistantfileblock(s, encryptionpwd):
    distantfile = zlib.decompress(decrypt(s=s, pwd=encryptionpwd).read())
    chunkid, mtime, fsize, h, fn = distantfile[:16], int.from_bytes(distantfile[16:24], byteorder='little', signed=False), int.from_bytes(distantfile[24:32], byteorder='little'), distantfile[32:64], distantfile[64:].decode()
    return chunkid, mtime, fsize, h, fn

def parseaddress(addr):
    if '@' in addr:
        user, r = addr.split('@', 1)  # split on first occurence
        if ':' in r and '/' not in user: # remote address. windows ok: impossible to have ':' after '@' in a path. linux: if a local dir is really named a@b.com:/hello/, use ./a@b.com:/hello/. what if '/' is in the username? technically possible with useradd, but not allowed by adduser, so evil corner case ignored here.
            host, path = r.split(':', 1)
            return True, user.strip(), host.strip(), path.strip()
    return False, None, None, addr       # not remote in all other cases

def backup(src=None, dest=None, sftppwd=None, encryptionpwd=None, exclusion_list=None):
    """Do a backup of `src` (local path) to `dest` (SFTP). The files are encrypted locally and are *never* decrypted on `dest`. Also, `dest` never gets the `encryptionpwd`."""
    if os.path.isdir(src):
        os.chdir(src)
    else:
        print('Source directory does not exist.')
        return    
    if exclusion_list == None or not isinstance(exclusion_list, list):
        exclusion_list = []
    remote, user, host, remotepath = parseaddress(dest)
    if host != "localhost":
        extra_arg = {}
    else:  # necessary argument for pysftp in case of local dest backup
        cnopts = pysftp.CnOpts()
        cnopts.hostkeys = None
        extra_arg = {"cnopts":cnopts}
    if not remote or not user or not host or not remotepath:  # either not remote (local), or remote with empty user, host or remotepath
        print('dest should use the following format: user@192.168.0.2:/path/to/backup/')
        return
    print('Starting backup...\nSource path: %s\nDestination host: %s\nDestination path: %s' % (src, host, remotepath))
    if sftppwd is None:
        sftppwd = getpass.getpass('Please enter the SFTP password for user %s: ' % user)
    if encryptionpwd is None:
        encryptionpwd = getpass.getpass('Please enter the encryption password: ')
        encryptionpwd_check = getpass.getpass('Confirm password: ')
        if encryptionpwd != encryptionpwd_check:
            print("Passwords are not identical!")
            return
    key, salt = KDF(encryptionpwd)        
    try:
        with pysftp.Connection(host, username=user, password=sftppwd, **extra_arg) as sftp:
            if sftp.isdir(remotepath):
                sftp.chdir(remotepath)
            else:    
                print('Destination directory does not exist.')
                return
            ######## GET DISTANT FILES INFO
            print('Distant files list: getting...')
            DELS = b''
            DISTANTFILES = dict()
            DISTANTHASHES = dict()
            distantfilenames = set(sftp.listdir())
            DISTANTCHUNKS = {bytes.fromhex(f) for f in distantfilenames if '.' not in f}  # discard .files and .tmp files
            for f in distantfilenames:    # remove old distant temp files
                if f.endswith('.tmp'):
                    sftp.remove(f)
            flist = io.BytesIO()
            if sftp.isfile('.files'):
                sftp.getfo('.files', flist)
                flist.seek(0)
                while True:
                    l = flist.read(4)
                    if not l:
                        break
                    length = int.from_bytes(l, byteorder='little')
                    s = flist.read(length)
                    if len(s) != length:
                        print('Item of .files is corrupt. Last sync interrupted?')
                        break                    
                    chunkid, mtime, fsize, h, fn = readdistantfileblock(s, encryptionpwd)
                    DISTANTFILES[fn] = [chunkid, mtime, fsize, h]
                    if DISTANTFILES[fn][0] == NULL16BYTES:  # deleted
                        del DISTANTFILES[fn]
                    if chunkid in DISTANTCHUNKS:
                        DISTANTHASHES[h] = chunkid      # DISTANTHASHES[sha256_noencryption] = chunkid ; even if deleted file keep the sha256, it might be useful for moved/renamed files
            for fn, distantfile in DISTANTFILES.items():
                if not os.path.exists(fn):
                    print('  %s no longer exists (deleted or moved/renamed).' % fn)
                    DELS += newdistantfileblock(chunkid=NULL16BYTES, mtime=0, fsize=0, h=NULL32BYTES, fn=fn, key=key, salt=salt)
            if len(DELS) > 0:
                with sftp.open('.files', 'a+') as flist:
                    flist.write(DELS)
            print('Distant files list: done.')
            ####### SEND FILES
            REQUIREDCHUNKS = set()
            with sftp.open('.files', 'a+') as flist:
                local_file_list = glob.glob('**/*', recursive=True)
                local_file_list = sorted(local_file_list, key=get_size, reverse=larger_files_first)
                print("\n\nThe following files will be ignored because they match the exclusion list:")
                for item in exclusion_list:
                    for fn in local_file_list:
                        if item in fn:
                            print(item + ": " + fn)
                            local_file_list.remove(fn)
                print("\n\n")
                total_size = sum([get_size(x) for x in local_file_list])
                with tqdm.tqdm(total=total_size, unit_scale=True, unit_divisor=1024, dynamic_ncols=True, unit="B", mininterval=1, desc="nFreezer") as pbar:
                    for fn in local_file_list:
                        if os.path.isdir(fn):
                            pbar.update(get_size(fn))
                            continue
                        try:
                            mtime = os.stat(fn).st_mtime_ns
                        except FileNotFoundError:
                            tqdm.tqdm.write("Not found error, skipped file %s" % fn)
                            pbar.update(get_size(fn))
                            continue
                        fsize = os.path.getsize(fn)
                        if fn in DISTANTFILES and DISTANTFILES[fn][1] >= mtime and DISTANTFILES[fn][2] == fsize:
                            tqdm.tqdm.write('Already on distant: unmodified (mtime + fsize). Skipping: %s' % fn)
                            REQUIREDCHUNKS.add(DISTANTFILES[fn][0])
                        else:
                            try:
                                h = getsha256(fn)
                            except OSError as e:
                                tqdm.tqdm.write(f"Skipping file, might be a UNIX special file: {e}, {fn}")
                                pbar.update(get_size(fn))
                                continue
                            if h in DISTANTHASHES:  # ex : chunk already there with same SHA256, but other filename  (case 1 : duplicate file, case 2 : renamed/moved file)
                                tqdm.tqdm.write('New, but already on distant (same sha256). Skipping: %s' % fn)
                                chunkid = DISTANTHASHES[h]
                                REQUIREDCHUNKS.add(chunkid) 
                            else:
                                tqdm.tqdm.write('New, sending file: %s' % fn)
                                chunkid = uuid.uuid4().bytes
                                with sftp.open(chunkid.hex() + '.tmp', 'wb') as f_enc, open(fn, 'rb') as f:
                                    encrypt(f, key=key, salt=salt, out=f_enc)
                                sftp.rename(chunkid.hex() + '.tmp', chunkid.hex())
                                REQUIREDCHUNKS.add(chunkid)
                                DISTANTHASHES[h] = chunkid
                            flist.write(newdistantfileblock(chunkid=chunkid, mtime=mtime, fsize=fsize, h=h, fn=fn, key=key, salt=salt))         # todo: accumulate in a buffer and do this every 10 seconds instead
                        pbar.update(get_size(fn))
                pbar.close()
            delchunks = DISTANTCHUNKS - REQUIREDCHUNKS
            if len(delchunks) > 0:
                print('Deleting %s no-longer-used distant chunks... ' % len(delchunks), end='')
                for chunkid in delchunks:
                    sftp.remove(chunkid.hex())
                print('done.')
        print('Backup finished.')
    except paramiko.ssh_exception.AuthenticationException:
        print('Authentication failed.')
    except paramiko.ssh_exception.SSHException as e:
        print(e, '\nPlease ssh your remote host at least once before, or add your remote to your known_hosts file.\n\n')  # todo: avoid ugly error messages after

def restore(src=None, dest=None, sftppwd=None, encryptionpwd=None):
    """Restore encrypted files from `src` (SFTP or local path) to `dest` (local path)."""
    if encryptionpwd is None:
        encryptionpwd = getpass.getpass('Please enter the encryption password: ')
        encryptionpwd_check = getpass.getpass('Confirm password: ')
        if encryptionpwd != encryptionpwd_check:
            print("Passwords are not identical!")
            raise SystemExit()
    remote, user, host, path = parseaddress(src)
    if remote:
        if sftppwd is None:
            sftppwd = getpass.getpass('Please enter the SFTP password for user %s: ' % user)
        if not user or not host or not path:
            print('src should be either a local directory, or a remote using the following format: user@192.168.0.2:/path/to/backup/')
            return
        src_cm = pysftp.Connection(host, username=user, password=sftppwd)
    else:
        src_cm = nullcontext()
        src_cm.open, src_cm.chdir, src_cm.isdir = open, os.chdir, os.path.isdir
    with src_cm:
        DISTANTFILES = dict()
        dest = os.path.abspath(dest)
        if src_cm.isdir(path):
            src_cm.chdir(path)
        else:    
            print('src path does not exist.')
            return
        print('Restoring backup from %s: %s\nDestination local path: %s' % ('remote' if remote else 'local path', src, dest))
        with src_cm.open('.files', 'rb') as flist:
            while True:
                l = flist.read(4)
                if not l:
                    break
                length = int.from_bytes(l, byteorder='little')
                s = flist.read(length)
                if len(s) != length:
                    print('An item of the remote file list (.files) is corrupt, ignored. Last sync interrupted?')
                    break
                chunkid, mtime, fsize, h, fn = readdistantfileblock(s, encryptionpwd)
                DISTANTFILES[fn] = [chunkid, mtime, fsize, h]
                if DISTANTFILES[fn][0] == NULL16BYTES:  # deleted
                    del DISTANTFILES[fn]
        for fn, [chunkid, mtime, fsize, h] in DISTANTFILES.items():
            f2 = os.path.join(dest, fn).replace('\\', '/')
            os.makedirs(os.path.dirname(f2), exist_ok=True)
            if os.path.exists(f2) and getsha256(f2) == h:
                print('Already present (same sha256). Skipping: %s' % fn)
                continue
            else:
                print('Restoring %s' % fn)
            with open(f2, 'wb') as f, src_cm.open(chunkid.hex(), 'rb') as g:
                decrypt(g, pwd=encryptionpwd, out=f)
            os.utime(f2, ns=(os.stat(f2).st_atime_ns, mtime))
        print('Restore finished.')

def console_script():
    """Command-line script"""
    if len(sys.argv) >= 4:
        if sys.argv[1] == 'backup':
            try:
                excl = sys.argv[4]
            except:
                excl = []
            backup(src=sys.argv[2], dest=sys.argv[3], exclusion_list=excl)
        elif sys.argv[1] == 'restore':
            restore(src=sys.argv[2], dest=sys.argv[3])
    else:
        print('Missing arguments.\nExamples:\n  nfreezer backup test/ user@192.168.0.2:/test/ \'["mkv", "avi"]\'\n  nfreezer restore user@192.168.0.2:/test/ restored/')

