# go seof: Simple Encrypted os.File

Encrypted drop-in replacement of golang' [`os.File`](https://golang.org/pkg/os/#File), the file stored will be encrypted
using three passes of AES256 (other ciphers/parameters to come). The resulting type can be used anywhere
an [`os.File`](https://golang.org/pkg/os/#File) could be used. i.e. it can be both sequentially and randomly read and
write, at any file position for any amount of bytes, can be truncate, seek, stats, etc.
i.e. [`Read`](https://golang.org/pkg/os/#File.Read),
[`ReadAt`](https://golang.org/pkg/os/#File.ReadAt),
[`WriteAt`](https://golang.org/pkg/os/#File.WriteAt),
[`Seek`](https://golang.org/pkg/os/#File.Seek),
[`Truncate`](https://golang.org/pkg/os/#File.Truncate), etc.

It derives a file-wide key using [scrypt](http://www.tarsnap.com/scrypt.html) with a provided string password, the file
is sliced into blocks of n bytes (decided at creation time.). Each block is encrypted and sealed using three AES256/CGM
envelops, one inside the other, achieving
both [confidentiality and authenticity](https://en.wikipedia.org/wiki/Authenticated_encryption). File wide integrity is
warrantied by signing blocks and avoiding empty sparse blocks.

Current Version: [v1.0.0](https://github.com/kuking/seof/tree/v1.0.0), changelog [here](CHANGELOG.md).

Example
-------

Snippet taken from [base_test.go](base_test.go). Check the test files for more examples, i.e. Seek, Truncate, Stats,
etc.

```
    password := "this is a very long password nobody should know about"
    BEBlockSize := 1024
    data := crypto.RandBytes(BEBlockSize*10)

    // create, write, close.
    f, err := seof.CreateExt("encrypted.seof", password, BEBlockSize, 1)
    assertNoErr(err, t)

    n, err := f.Write(data)
    assertNoErr(err, t)
    if n != len(data) {
        t.Fatal("did not write the whole buffer")
    }
    err = f.Close()
    assertNoErr(err, t)

    // open, read, close.
    f, err = seof.OpenExt("encrypted.seof", password, 1)
    assertNoErr(err, t)
    readBuf := make([]byte, BEBlockSize*15) // bigger, purposely
    n, err = f.Read(readBuf)
    if n != len(data) {
        t.Fatal("It did not read fully")
    }
    if !bytes.Equal(data, readBuf[0:n]) {
        t.Fatal("read error, does not equals to initial write")
    }
    err = f.Close()
    assertNoErr(err, t)

```

CLI
---

Usage, it can encrypt/decrypt/inspect files' metadata from CLI:

```$ ./seof                                                                                                                                                                                              ed@luxuriance
Usage of ./seof: seof file utility

  -e	encrypt (default: to decrypt)
  -h	Show usage
  -i	show seof encrypted file metadata
  -p string
    	password file
  -s uint
    	block size (default: 1024)
  -scrypt string
    	Encrypting Scrypt parameters: min, default, better, max (default "default")

NOTES:
  - Password must be provided in a file. Command line is not secure in a multi-user host.
  - When encrypting, contents have to be provided via stdin pipe, decrypted output will be via stdout.
  - Scrypt parameters target times in modern CPUs (2021): min>20ms, default>600ms, better>5s, max>9s

Examples:
  $ cat file | seof -e -p @password_file file.seof
  $ seof -p @password_file file.seof > file
  $ seof -i -p @password_file file.seof
```

Inspecting metadata for an encrypted file:

```
$ /seof -p password -i file.seof                                                                                                                                                                     ed@luxuriance
           File Name: file.seof
   Modification Time: 2021-01-03 13:53:55.698769333 +0000 GMT
           File Mode: -rw-r--r--
        Content Size: 247086468 bytes
   File Size On Disk: 268321756 bytes
 Encryption Overhead: 8.59%
  Content Block Size: 1024 bytes
Encrypted Block Size: 1112 bytes
 Total Blocks Writen: 241298 (= unique nonces)
       SCrypt Preset: Maximum (>9s)
   SCrypt Parameters: N=524288, R=64, P=1, keyLength=96, salt=
     e036b1c8443913266fa514404dc56fa2603e5215136dfe7b83cb2149eb924dc1
     40cc023e94fcde57b4ca095e81b3ab94331a9defbb03187b4a1761ee37179402
     f206d9f768034a9cb7d42e9355f55876c4ffb8710da32d56c6b384101a3d13f4
  ```

Performance
-----------
There is no performance overhead beyond the encryption primitives. Internally, `seof` holds multiple unencrypted blocks
in memory, unbuffered reading and writing should not incur in any extra encryption work, and the typical sequential
reads and writes should be performant independently of the access pattern.

Finally, encryption occurs in blocks, so changing just one byte would require encrypting and storing a whole block (i.e.
10kb). You want to tune the quantity of in-memory blocks when opening the file; and the block size when creating it.

### CLI sequential encryption/decryption performance

(MacBook Pro (13-inch, 2018, Four Thunderbolt 3 Ports), 2.7 GHz Quad-Core Intel Core i7)

```
$ cat ~/Downloads/debian-10.5.0-amd64-netinst.iso | pv | ./seof -p password -e debian-10.5.0-amd64-netinst.iso.seof 
 349MiB 0:00:06 [50.8MiB/s] [                            <=>                                                    ]

$ ./seof -p password debian-10.5.0-amd64-netinst.iso.seof | pv > debian-10.5.0-amd64-netinst.iso                                                                                                      ed@luxuriance
 349MiB 0:00:02 [ 132MiB/s] [            <=>                                                                    ]
```

File Structure
--------------

- Header: (128 bytes, 120 used)
    - uint64 Magic
    - [96]byte Script salt
    - uint32 Scrypt parameters: N, R, P.
    - uint32 Disk block size
    - [8]byte zeros (verified on open)
- A block:
    - [36]byte: nonce
    - uint32: cipherText length
    - [disk-block-size]byte: CGM stream
        - the additional data for the AEAD is an uint64 holding the block number (verified)
- Special block 0:
    - uint64: File size
    - uint32: Disk block size (must eq to the header)
    - uint32: un-encrypted block size
    - uint64: written blocks (as in number of unique nonces generated)
    - []byte: Further metadata expansion

Testing
-------
Code is extensively tested and there is a soak test suite that tests multiple access patterns (i.e. misaligned reads,
writes, multi-blocks ops, sub-block ops, concurrency, etc).

```
$ ./soaktest                                                                                                                                                                                          ed@luxuriance
soaktest: seof soak test, creates a native file and a seof encrypted file.
  applies many different IO operations equally to both files and verifies both behave similar. You want a fast disk (NVMe).

1. Creating 2 x 256MB files: native.soak, seof.soak
2. Writing 256MB of [0x00, 0x01, 0x02, ... 0xff] in: native.soak, seof.soak
.................................................. done
3.1. Fully comparing files, using read_chunk_size=1
.................................................. done
3.2. Fully comparing files, using read_chunk_size=2
.................................................. done
3.3. Fully comparing files, using read_chunk_size=3
.................................................. done
3.4. Fully comparing files, using read_chunk_size=4
.................................................. done

[...]

.................................................. done
3.16. Fully comparing files, using read_chunk_size=16
.................................................. done
3.17. Fully comparing files, using read_chunk_size=256
.................................................. done
3.18. Fully comparing files, using read_chunk_size=512
.................................................. done
3.19. Fully comparing files, using read_chunk_size=924
.................................................. done
3.20. Fully comparing files, using read_chunk_size=1023
.................................................. done
3.21. Fully comparing files, using read_chunk_size=1024
.................................................. done
3.22. Fully comparing files, using read_chunk_size=1025
.................................................. done
3.23. Fully comparing files, using read_chunk_size=1124
.................................................. done
3.24. Fully comparing files, using read_chunk_size=2048
.................................................. done
3.25. Fully comparing files, using read_chunk_size=3072
.................................................. done
3.26. Fully comparing files, using read_chunk_size=4096
.................................................. done
3.27. Fully comparing files, using read_chunk_size=4095
.................................................. done
3.28. Fully comparing files, using read_chunk_size=4097
.................................................. done
4.1.1. Rewriting wholy using chunk_size=1
.................................................. done
4.1.2. Verifying (fast, using chunk_size=1024)
.................................................. done
4.2.1. Rewriting wholy using chunk_size=2
.................................................. done
4.2.2. Verifying (fast, using chunk_size=1024)
.................................................. done
4.3.1. Rewriting wholy using chunk_size=3
.................................................. done

[...]

4.22.1. Rewriting wholy using chunk_size=1025
.................................................. done
4.22.2. Verifying (fast, using chunk_size=1024)
.................................................. done
4.23.1. Rewriting wholy using chunk_size=1124
.................................................. done
4.23.2. Verifying (fast, using chunk_size=1024)
.................................................. done
4.24.1. Rewriting wholy using chunk_size=2048
.................................................. done
4.24.2. Verifying (fast, using chunk_size=1024)
.................................................. done
4.25.1. Rewriting wholy using chunk_size=3072
.................................................. done
4.25.2. Verifying (fast, using chunk_size=1024)
.................................................. done
4.26.1. Rewriting wholy using chunk_size=4096
.................................................. done
4.26.2. Verifying (fast, using chunk_size=1024)
.................................................. done
4.27.1. Rewriting wholy using chunk_size=4095
.................................................. done
4.27.2. Verifying (fast, using chunk_size=1024)
.................................................. done
4.28.1. Rewriting wholy using chunk_size=4097
.................................................. done
4.28.2. Verifying (fast, using chunk_size=1024)
.................................................. done
5.1. Writing 262144 random chunks of miscelaneous sizes of up to 2048 bytes
................................................... done
5.2. Verifying (fast, using chunk_size=1024)
.................................................. done
6.1. Reading 262144 random chunks of miscelaneous sizes of up to 2048 bytes
................................................... done
7.1 Synchronisation: reading native, writing encrypted 1048576 chunks of up to 2048 bytes within 64 concurrent threads
.................................................. done
7.2. Verifying (fast, using chunk_size=1024)
.................................................. done
7.3. Synchronisation: reading encryptede 1048576 chunks of up to 2048 bytes within 64 concurrent threads
.................................................. done

SUCCESS!

```

Syncronisation
--------------
Concurrency safety is achieved with a global lock, do not expect optimal concurrent performance. It is safe to do
operations on the same seof File object from multiple concurrent goroutines.

Attack vectors
--------------

- Each time a new block is written, a new nonce is generated, less than 2^32 write operations should be done in one
  particular file (and key.). Internally the implementation uses buffers and will store to disk only when the buffer
  needs to be flushed to disk (i.e. file closed, sync or cache eviction.)
  if your application does a lots of random seeks and writes (constantly invalidating the blocks cache, forcing flushing
  blocks to disk, generating new nonces for the new encrypted block) you might hit this upper limit. Special block 0
  holds a counter with the number of unique nonces ever generated (which equals to the number of written and encrypted
  blocks). This value can be inspected using the `seof -i` CLI command.

- The weakest encryption-link is the password string used for generating the 768 bits (96 bytes) of key. A string in
  latin characters should have to be approx. 150 characters in order to hold 768 bits of entropy. You have to keep that
  in mind.

- Blocks within the same file can not be shuffled or moved to another block as the AEAD seals hold the block number in
  the signed plaintext. This is verified.

- Most filesystems can handle [sparse files](https://en.wikipedia.org/wiki/Sparse_file). seof supports sparse files, but
  read of never written/zeroed blocks is disabled by default to avoid a possible attack (see: XXX flag). User can create
  a new file and [`Seek`](https://golang.org/pkg/os/#File.Seek) to any part of it, write a byte, and later read it.
  Reading outside the block boundaries of the unique written byte will fail unless explicitly enabled. This is not a
  very typical user case.

  __Long explanation__: in order to keep track of blocks holding data, seof should keep a block-written-bitmap. So when
  a block is read from the disk and comes completely empty (zeroed, no AEAD seal present), but the block-written-bitmap
  accuses it was written previously, it is fair to assume the data has been lost, therefore deemed inconsistent, an IO
  error should be raised (it could have been zeroed by a malicious actor, too.). Without this block-written-bitmap, a
  zeroed block by a malicious actor and an honest empty blob in a sparse file are indistinguishable, potentially
  allowing a "selective block zero-ing attack." and failing the integrity assurances.

  If you really need this assurance, let me know, the block-written-bitmap can be done.

USAGE
-----

- Storing passwords and secrets using auto-generated system+app+user derived key
- Encrypting distributable assets and you need random access reads. (i.e. reading a ZIP File)
- Enhancing encryption in traditional file formats (i.e.
  golang' [zip reader](https://golang.org/pkg/archive/zip/#NewReader))
- Secure long-term storing of files (some people might want to use GPG as it is "proven" to work)
- Keeping usage data away from user's eyes
- Random access on *very* big files, seof supports 64bits files. i.e. efficient and fast random access of >4gb files.

- Any of the above and you really want to make it future proof, i.e. scenario where AES is degraded.

TODO
----

- Flag to allow reading empty holes in sparse files as no errors
- Crypto analysis
