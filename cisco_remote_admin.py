from paramiko import SSHClient
from paramiko import AutoAddPolicy
import pexpect
import sys

h = {'10.194.143.1':'password',
     '10.194.142.1':'password',
     '10.194.141.1':'password',
     '10.194.140.1':'password',
     '10.194.139.1':'password',
     '10.194.138.1':'password',
     '10.194.137.1':'password',
     '10.194.136.1':'password',
     '10.194.135.1':'password',
     '10.194.134.1':'password',
     '10.194.133.1':'password', 
     '10.194.132.1':'password',
     '10.194.131.1':'password',
     '10.194.130.1':'password',
     '10.194.129.1':'password'}

class SSHDO(SSHClient):
    def __init__(self, chost, cpasswd):
        SSHClient.__init__(self)
        self.chost = chost
        self.cpassed = cpasswd
        self.set_missing_host_key_policy(AutoAddPolicy())
        self.connect(chost, port=22, username='admin', password=cpasswd) 

    def sendcmd(self,host,passwd,nline,allow):
        t = '.*#'
        c = pexpect.spawn('ssh admin@%s -1' % host)
        c.expect('admin@%s\'s password:' % host)
        c.sendline(passwd)
        c.expect(t)
        c.sendline('conf t')
        c.expect(t)
    def do_id(id): pass

class SSHADD(SSHDO):
    def conf170(self):
#        stdin, stdout, stderr = self.exec_command('sh access-list 170')
        result = stdout.readlines()
        accesslist = result[2:-5]
        num = []
        for i in accesslist:
            num.append(i.split()[0])
        for i in range(len(num)):
            if int(num[i]) % 10 == 0:
                if int(num[i+1]) % 10 == 0:
                    b = int(num[i]) + 1
                    break
        return b

    def sendcmd(self,host,passwd,nline,allow):
        d = host.split('.')[2]
    t = '.*#'
        c = pexpect.spawn('ssh admin@%s -1' % host)
        c.expect('admin@%s\'s password:' % host)
        c.sendline(passwd)
        c.expect(t)
        c.sendline('conf t')
        c.expect(t)
        c.sendline('ip access-list extended 170')
        c.expect(t)
        c.sendline('%s permit ip host %s 10.194.%s.0 0.0.0.63' % (nline,allow,d))
        c.expect(t)

class SSHDEL(SSHDO):
    def conf170_num(self):
        stdin, stdout, stderr = self.exec_command('sh access-list 170')
        result = stdout.readlines()
        accesslist = result[2:-5]
        global num
        num = []
        for i in accesslist:
            num.append(i.split()[0])
        return num

    def conf170_ip(self):
        stdin, stdout, stderr = self.exec_command('sh access-list 170')
        result = stdout.readlines()
        accesslist = result[2:-5]
        global ip
        ip = []
        for i in accesslist:
            ip.append(i.split()[4])
        return ip

    def find(self,find):
        if find in ip:
            for i in ip:
                if find == i:
                    h = ip.index(i)
                    break
        else: raise IndexError
        return h

    def sendcmd(self,host,passwd,nline):
        t = '.*#'
        c = pexpect.spawn('ssh admin@%s -1' % host)
        c.expect('admin@%s\'s password:' % host)
        c.sendline(passwd)
        c.expect(t)
        c.sendline('conf t')
        c.expect(t)
        c.sendline('ip access-list extended 170')
        c.expect(t)
        c.sendline('no %s' % (nline))
        c.expect(t)

def procOne(host,allow):

        try:
            z = SSHADD(host,h[host])
            m = z.conf170()
            z.sendcmd(host,h[host],m,allow)
        except:
            print 'Not connect %s' % host
        else:
            print '%s: good add %s' % (host,allow)

def delOne(host,deny):
        try:
            j = SSHDEL(host,h[host])
            m = j.conf170_num()
            p = SSHDEL(host,h[host])
            p.conf170_ip()
        except:
            print 'Not connect %s' % host
        try:
            l = p.find(deny)
            nline = m[l]
            p.sendcmd(host,h[host],nline)
        except IndexError:
            print 'No search ip'
        else:
            print '%s: good del %s ' % (host,deny)

def proc(allow):
        for i in h:
            try:
            j = SSHADD(i,h[i])
            m = j.conf170()
            j.sendcmd(i,h[i],m,allow)
            except:
            print 'Not connect %s' % i
            else:
            print '%s: good add %s' % (i,allow)

def procdel(deny):
        for i in h:
            try:
            j = SSHDEL(i,h[i])
            m = j.conf170_num()
            p = SSHDEL(i,h[i])
            p.conf170_ip()
            except:
            print 'Not connect %s' % i
            try:
                l = p.find(deny)
                nline = m[l]
                p.sendcmd(i,h[i],nline)
            except IndexError:
                print 'No search ip'
            else:
                print '%s: good del %s ' % (i,deny)

def cisco_do(arg1,arg2,arg3=None):
    if arg1 == '-add':
        proc(arg2)
    elif arg1 == '-del':
        procdel(arg2)
    elif arg1 == '-add-one':
        procOne(arg3,arg2) # arg3 is one host do
    elif arg1 == '-del-one':
        delOne(arg3,arg2)
    else:
        print 'no such option: %s\nUse ex: -add ipaddr\n-add-one ipaddr doip\n-del ipaddr\n-del-one ipaddr doip' % arg1

if __name__ == '__main__':
    if sys.argv[3]:
        cisco_do(sys.argv[1],sys.argv[2],sys.argv[3])
    else: 
        cisco_do(sys.argv[1],sys.argv[2])