from pystyleclean import *
from random import shuffle
from tqdm import tqdm
import math

System.Clear()
Cursor.HideCursor()

bwtx = math.log
kinwx = math.floor

light = Col.light_gray
ghoul = Colors.StaticMIX((Col.blue, Col.red))
ewe = Colors.StaticMIX((Col.purple, Col.blue, Col.blue))

def stage(text: str, symbol: str = '...', col1 = light, col2 = None) -> str:
    if col2 is None:
        col2 = light if symbol == '...' else ghoul
    return f""" {Col.Symbol(symbol, col1, ewe)} {col2}{text}{Col.reset}"""

recursividad = 5 # Se vuelve ridiculamente mas lento, cuanto mayor sea este numero, pero sera mas "encriptado"
base = 512 # Debe ser un numero entero, 2 - inf (recomiendo que se mantenga en 1024 o 512)
indent = 0 # Cuantas sangrias se deben usar para espaciar el codigo real y el pase. Se utiliza para ocultar el codigo de un IDE
bytes_allowed = True # Si esta deshabilitado, la base no puede estar por encima de 93

magic = input(stage(f"Drag the file you want to obfuscate {ghoul}-> {Col.reset}", "?", col2 = ewe)).replace('"','').replace("'","")
code = open(magic, "rb").read().decode()

if bytes_allowed:
    key = characters = list(map(chr, range(94, 94+base)))
else:
    key = characters = list(map(chr, range(33, 34+base)))

ban = ["'", "`", "\\"]

for item in ban:
    if item in key:
        key.remove(item)
        base -= 1

shuffle(key)
highest = 0

def encode(x, base):
    global highest
    if not x:
        return key[0]
    
    log = kinwx(bwtx(x, base))

    st = [0]*(log+1)
    st[-1] = 1
    if log:
        x -= base**log

    while True:
        if x >= base:
            log = kinwx(bwtx(x, base))
            x -= base**log
            st[log] += 1 
        else:
            st[0] = x
            return ''.join([str(key[char] )for char in st[::-1]])

def decode(x, base):
    result = 0
    for count, char in enumerate(str(x)[::-1]):
        result += int(key.index(str(char)))*(base**count)
    return result

enc2 = ' '.join([ str(encode(ord(chr), base)) for chr in 'exec'])
enc3 = ' '.join([ str(encode(ord(chr), base)) for chr in 'compile'])

for n in tqdm(range(recursividad)):
    enc = '`'.join([ str(encode(ord(chr), base)) for chr in code])
    
    if n+1 == recursividad:
        message = f"pass{'  '*indent};"
    else:
        message = ''
    src = f"""{message}k='{''.join(key)}';(eval(eval(''.join([chr(sum([k.index(str(ch))*({base}**c) for c, ch in enumerate(str(x)[::-1])]))for x in('{enc3}'.split(' '))]))(''.join([chr(sum([k.index(str(ch))*({base}**c) for c, ch in enumerate(str(x)[::-1])]))for x in('{enc2}'.split(' '))]), "", "eval")))(eval(''.join([chr(sum([k.index(str(ch))*({base}**c) for c, ch in enumerate(str(x)[::-1])]))for x in('{enc3}'.split(' '))]))(''.join([chr(sum([k.index(str(ch))*({base}**c) for c, ch in enumerate(str(x)[::-1])]))for x in('{enc}'.split('`'))]), "", "exec"))"""
    code = src.replace('-.', '-1')

with open(f'{magic}', 'wb') as f:
    code = magic.split('\\')[-1]
    f.write(src.encode())
