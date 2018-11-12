#!/bin/env python3
import subprocess
import string
import logging
from multiprocessing import Process, Queue
"""
Script to call openssl enc -d on a .enc file using a list of ciphers and passwords
    to attempt to recover .enc file content

Author: Chimi <MindTheBox>
License: Don't sue me

This is a work in progress and might not work for you.
"""

NUM_PROCS = 10

logging.basicConfig(level=logging.INFO)


def proc_func(q):
    while True:
        (enc_file, word, cipher) = q.get()
        if enc_file == None:
            break
        do_attempt(enc_file, word, cipher)


def do_attempt(enc_file, word, cipher):
    try:
        word = word.replace("\"", "\\\"")
        # Change options manually to fit your needs
        cmd = ["openssl",
                "enc",
                "-d",
                #"-a",
                "-%s" % (cipher),
                #"-pbkdf2",
                "-nosalt",
                "-in",
                "%s" % (enc_file),
                "-k",
                "\"%s\"" % (word)]
        #print(cmd)
        p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        op, ep = p.communicate()
        #print(op)
        #exit()
        #print(ep)
        if ep != b'' and b'bad decrypt' not in ep and b'error' in ep.lower():
            logging.info("Error: %s" % ep)
        if b'bad decrypt' not in ep and all(chr(c) in string.printable for c in op):
            logging.info("Password: %s" % (word))
            logging.info("Data: \n%s" % (op))
            logging.info('-' * 40)
            return True
    except subprocess.CalledProcessError:
        pass
    return False


def work_iter(wordlist, ciphers):
    with open(ciphers, 'r', errors='ignore') as cf:
        for cipher in cf:
            cipher = cipher.replace('\n', '')
            if cipher == '' or cipher[0] == '#':
                continue
            logging.info("Trying %s" % (cipher))
            with open(wordlist, 'r', errors='ignore') as wf:
                for word in wf:
                    word = word.replace('\n', '')
                    if word == '' or word[0] == '#':
                        continue
                    yield (word, cipher)


def main(enc_file, wordlist, ciphers):
    q = Queue(NUM_PROCS * 3)
    procs = [Process(target=proc_func, args=(q,)) for i in range(NUM_PROCS)]
    for p in procs:
        p.start()

    for work in work_iter(wordlist, ciphers):
        q.put((enc_file, *work))

    for i in range(NUM_PROCS):
        q.put((None, None, None))
    
    for p in procs:
        p.join()

    logging.info("Done")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        logging.info("Usage: %s <enc_file> <wordlist> <ciphers>" % (sys.argv[0]))
        exit(-1)

    enc_file = sys.argv[1]
    wordlist = sys.argv[2]
    ciphers = sys.argv[3]
    main(enc_file, wordlist, ciphers)

