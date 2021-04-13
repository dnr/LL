#!/usr/bin/env python3

import sys, os, tempfile, socket, selectors, json


def start():
  if not all(os.isatty(fd) for fd in range(3)):
    raise Exception("not a tty")

  runtimedir = os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')
  lldir = os.path.join(runtimedir, 'LL')
  os.makedirs(lldir, mode=0o700, exist_ok=True)

  skname = tempfile.mktemp(prefix='sock-', dir=lldir)
  pipename = tempfile.mktemp(prefix='pipe-', dir=lldir)
  os.mkfifo(pipename)

  pid = os.fork()
  if pid == 0:
    # put some stuff in the environment so processes in the shell can find us
    os.environ['_LL_SOCK'] = skname
    os.environ['_LL_SCRIPT_PID'] = str(os.getpid())
    os.execvp('script', ['script', '-e', '-q', pipename])
  else:
    try:
      sys.exit(server(pipename, skname))
    # except Exception as e:
    #   print("SERVER ERROR", e)
    #   sys.exit(2)
    finally:
      _, status = os.waitpid(pid, 0)
      os.remove(pipename)
      os.remove(skname)
      os._exit(status >> 8)
  assert "not reached"


class Buf:
  def __init__(self):
    # TODO: circular buffer
    self.buf = b''

  def add(self, b):
    self.buf += b
    if len(self.buf) > 128*1024:
      self.buf = self.buf[-64*1024:]

  def lines(self, n):
    LF = 10
    idx = len(self.buf)
    while n >= 0 and idx >= 0:
      idx = self.buf.rfind(LF, 0, idx)
      n -= 1
    # if we're really unlucky we might split a utf-8 codepoint
    return self.buf[idx+1:].decode(errors='ignore').replace('\r\n', '\n').strip('\n')

  def grep(self, pat):
    raise Exception("FIXME")

def server(pipename, skname):
  sel = selectors.DefaultSelector()
  #print("SERVER OPENING PIPE")
  pipe = open(pipename, 'rb', buffering=0)
  #print("SERVER OPENING SOCKET")
  sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
  sock.bind(skname)

  buf = Buf()

  def onpipe():
    #print("READING FROM PIPE\r\n")
    b = pipe.read(4096)
    #print("PIPE DATA", len(b), "\r\n")
    if not b:
      sys.exit()
    buf.add(b)

  def runcmd(cli, cmd):
    if 'get' in cmd:
      get = cmd['get']
      if 'lines' in get:
        return buf.lines(get['lines'])
      elif 'grep' in get:
        return buf.grep(get['grep'])
    raise Exception("unknown command")

  def onsock():
    #print("READING FROM SOCK")
    data, cli = sock.recvfrom(64*1024)
    #print("DATA", data, cli)
    try:
      result = runcmd(cli, json.loads(data))
      out = {"result": str(result)}
    except Exception as e:
      out = {"error": str(e)}
    #print("OUT", out)
    sock.sendto(json.dumps(out).encode(), cli)

  sel.register(pipe, selectors.EVENT_READ, onpipe)
  sel.register(sock, selectors.EVENT_READ, onsock)
  while True:
    for key, mask in sel.select():
      key.data()


def print_bashrc():
  print(f"""\
_ll_flush () {{
  local previous_exit_status=$?
  if [[ -n $_LL_SCRIPT_PID ]]; then
    kill -s USR1 $_LL_SCRIPT_PID
  fi
  return $previous_exit_status
}}
PROMPT_COMMAND="${{PROMPT_COMMAND}}${{PROMPT_COMMAND:+;}}_ll_flush"
alias LL="{__file__} get lines"
alias LLg="{__file__} get grep"
""")

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
    print(ret['result'])


def main():
  args = sys.argv[1:]

  cmd = args[0]
  if cmd == 'bashrc':
    print_bashrc()
  elif cmd == 'start':
    start()
  elif cmd == 'get':
    get(args[1:])


if __name__ == '__main__':
  main()
