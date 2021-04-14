#!/usr/bin/env python3

import sys, os, tty, pty, tempfile, socket, selectors, json
import signal, struct, fcntl, termios, time

STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO = range(3)

# Random sequence that shouldn't appear anywhere and should be ignored by all terminals:
SOP_OSC = 'LL;ZFheBKaFd'
START_OF_PROMPT = b'\033]' + SOP_OSC.encode() + b'\033\\'
assert len(START_OF_PROMPT) == 16

# code copied and adapted from this patch:
# https://bugs.python.org/issue41494

def _login_pty(parent_fd, child_fd):
    """Given a pty, makes the calling process a session leader, makes the pty child
    its controlling terminal, stdin, stdout, and stderr. Closes both pty ends."""
    # Establish a new session.
    os.setsid()
    os.close(parent_fd)

    try:
        fcntl.ioctl(child_fd, termios.TIOCSCTTY) # Make the pty child the controlling terminal.
    except:
        os.close(child_fd)
        raise

    # Child becomes stdin/stdout/stderr.
    os.dup2(child_fd, STDIN_FILENO)
    os.dup2(child_fd, STDOUT_FILENO)
    os.dup2(child_fd, STDERR_FILENO)
    if child_fd > STDERR_FILENO:
        os.close(child_fd)

def _winresz(child_pty):
    """Resize window."""
    w = struct.pack('HHHH', 0, 0, 0, 0)
    s = fcntl.ioctl(STDIN_FILENO, termios.TIOCGWINSZ, w)
    fcntl.ioctl(child_pty, termios.TIOCSWINSZ, s)

def _create_hwinch(child_pty):
    """Creates SIGWINCH handler."""
    def _hwinch(signum, frame):
        try: _winresz(child_pty)
        except: pass
    return _hwinch

def _cleanup(parent_fd, child_fd, tty_mode):
    """Performs cleanup in wspawn."""
    # Close both pty ends.
    os.close(parent_fd)
    os.close(child_fd)

    # Restore original tty attributes.
    if tty_mode != None:
        tty.tcsetattr(STDIN_FILENO, tty.TCSAFLUSH, tty_mode)

# end copy


def wait_and_kill(pid, sig=signal.SIGTERM, timeout=2.0):
  xpid, status = os.waitpid(pid, os.WNOHANG)
  if xpid > 0: return status

  try: os.kill(pid, sig)
  except: pass

  for _ in range(int(timeout * 10)):
    time.sleep(0.1)
    xpid, status = os.waitpid(pid, os.WNOHANG)
    if xpid > 0: return status

  try: os.kill(pid, signal.SIGKILL)
  except: pass

  _, status = os.waitpid(pid, 0)
  return status


def writeall(fd, b):
  while b:
    n = os.write(fd, b)
    b = b[n:]


class SigExc(Exception): pass

# some parts copied from pty.py:spawn and wspawn from that patch
def start(args):
  if not all(os.isatty(fd) for fd in range(3)):
    raise Exception("not a tty")

  runtimedir = os.getenv('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')
  lldir = os.path.join(runtimedir, 'LL')
  os.makedirs(lldir, mode=0o700, exist_ok=True)

  skname = tempfile.mktemp(prefix='sock-', dir=lldir)

  parent_fd, child_fd = os.openpty()
  try:
    _winresz(child_fd)
    signal.signal(signal.SIGWINCH, _create_hwinch(child_fd))
  except:     # User should handle exception and try spawn instead.
    _cleanup(parent_fd, child_fd, None)
    raise

  pid = os.fork()
  if pid == 0:
    _login_pty(parent_fd, child_fd)
    # put some stuff in the environment so processes in the shell can find us
    os.environ['_LL_SOCK'] = skname
    if not args:
      args = [os.getenv('SHELL', '/bin/sh')]
    os.execvp(args[0], args)

  try:
    mode = tty.tcgetattr(STDIN_FILENO)
    tty.setraw(STDIN_FILENO)
  except tty.error:    # This is the same as termios.error
    mode = None

  try:
    # This will only exit with an exception.
    server(parent_fd, skname)
    assert False, "not reached"
  except SigExc as s:
    killsig = s.args[0]
  except:
    killsig = signal.SIGTERM

  status = wait_and_kill(pid, killsig)
  _cleanup(parent_fd, child_fd, mode)
  os.remove(skname)
  os._exit(status >> 8)


class Buf:
  def __init__(self):
    # TODO: circular buffer
    self.buf = b''

  def add(self, b):
    self.buf += b
    if len(self.buf) > 128*1024:
      self.buf = self.buf[-64*1024:]

  def lines(self, n):
    # end of buffer will be end of current prompt. first jump back to before
    # current prompt was printed.
    end = self.buf.rfind(START_OF_PROMPT)
    if end < 0: return ''

    # then jump back line by line
    idx = end
    while n >= 0 and idx >= 0:
      idx = self.buf.rfind(b'\n', 0, idx)
      n -= 1
    # grab a bunch of lines
    out = self.buf[idx+1:end]
    # look for another prompt
    start = out.rfind(START_OF_PROMPT)
    if start >= 0:
      out = out[start:]
      # we don't know where the prompt ends and output starts. guess that it's
      # after the first newline.
      start = out.find(b'\n')
      if start >= 0:
        out = out[start+1:]
    # user probably doesn't want CRs
    out = out.replace(b'\r\n', b'\n')
    if not out.endswith(b'\n'):
      out += b'\n'
    # use latin-1 to "encode" binary in a unicode string for json
    out = out.decode('latin-1')
    return out

  def grep(self, pat):
    raise Exception("FIXME")


def runcmd(peer, buf, cmd):
  if 'get' in cmd:
    get = cmd['get']
    if 'lines' in get:
      return buf.lines(get['lines'])
    elif 'grep' in get:
      return buf.grep(get['grep'])
  raise Exception("unknown command")


def server(ptyfd, skname):
  sel = selectors.DefaultSelector()
  sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
  sock.bind(skname)

  handle = [signal.SIGCHLD, signal.SIGTERM, signal.SIGHUP]
  for sig in handle:
    signal.signal(sig, lambda *args: None)
  sigr, sigw = os.pipe()
  os.set_blocking(sigw, False)
  signal.set_wakeup_fd(sigw)

  buf = Buf()

  def onpty():
    b = os.read(ptyfd, 4096)
    if not b:
      sel.unregister(ptyfd)
      return
    writeall(STDOUT_FILENO, b)
    buf.add(b)

  def onsock():
    data, peer = sock.recvfrom(64*1024)
    try:
      result = runcmd(peer, buf, json.loads(data))
      out = {"result": result}
    except Exception as e:
      out = {"error": str(e)}
    sock.sendto(json.dumps(out).encode(), peer)

  def onstdin():
    b = os.read(STDIN_FILENO, 4096)
    if not b:
      sel.unregister(STDIN_FILENO)
      return
    writeall(ptyfd, b)

  def onsignal():
    sig = os.read(sigr, 1)[0]
    if sig in handle:
      raise SigExc(sig)

  sel.register(ptyfd, selectors.EVENT_READ, onpty)
  sel.register(sock, selectors.EVENT_READ, onsock)
  sel.register(STDIN_FILENO, selectors.EVENT_READ, onstdin)
  sel.register(sigr, selectors.EVENT_READ, onsignal)

  while True:
    for key, mask in sel.select():
      key.data()


def print_bashrc():
  print(f"""\
if [[ -n $PS1 ]]; then
  PS1="\\[\\e]{SOP_OSC}\\e\\\\\\\\\\]$PS1"
  alias LL="{__file__} get lines"
  alias LLg="{__file__} get grep"
  LLreexec() {{
    if [[ -t 0 && -t 1 && -t 2 && -z $_LL_SOCK ]]; then
      exec {__file__} start
    fi
  }}
else
  LLreexec() {{ :; }}
fi
""", end='')


def get(args):
  skname = os.getenv('_LL_SOCK')
  assert skname, "Missing _LL_SOCK env var"
  if args[0] == 'lines':
    lines = int(args[1]) if len(args) >= 2 else 1
    cmd = {'get': {'lines': lines}}
  elif args[0] == 'grep':
    cmd = {'get': {'grep': args[1]}}
  else:
    raise Exception("unknown command")

  sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
  sock.bind('')
  sock.connect(skname)
  sock.send(json.dumps(cmd).encode())
  ret = json.loads(sock.recv(64*1024))
  if 'error' in ret:
    raise Exception(ret['error'])
  if 'result' in ret:
    out = ret['result'].encode('latin-1')
    sys.stdout.buffer.write(out)


def main():
  args = sys.argv[1:]

  cmd = args[0]
  if cmd == 'bashrc':
    print_bashrc()
  elif cmd == 'start':
    start(args[1:])
  elif cmd == 'get':
    get(args[1:])
  else:
    raise Exception("unknown command")


if __name__ == '__main__':
  main()
