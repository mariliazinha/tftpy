# . CET 21180
# . UFCD 5119, com o formador João Galamba
# .
# . PROJETO 3 - TFTPy
# . 
# . Resolvido por: Marília Pinho & Rodrigo Sequeira
# . 
# . 2022-06
# . 
"""
Usage: 
    client.py (get|put) [-p SERV_PORT] SERVER SOURCE_FILE [DEST_FILE]
    client.py [-p SERV_PORT] SERVER

Commands:
  get   Busca ficheiro
  put   Envia ficheiro
Arguments:
  SERVER        Servidor de TFTP
  SOURCE_FILE   Ficheiro Fonte
  DEST_FILE     Ficheiro Destino
Options:
  -h --help    mostra este ficheiro
  -p SERV_PORT --port==SERV_PORT  porta no servidor (por defeito é a 69)

TFTPy - Este módulo implementa um cliente de TFTP interactivo ou por linha de comando

Este cliente aceita as seguintes opções:
    $ python3 client.py (get|put) [-p serv_port] server source_file [dest_file] 
    $ python3 client.py [-p serv_port] server

(C) Marília Pinho & Rodrigo Sequeira, 2022-06-22
"""

from docopt import docopt
from os.path import isfile
import tftp
import sys

DEFAULT_PORT_FTP = 69

#def main():
#    argumentos = docopt(__doc__)
        
# analisa os argumentos
argumentos = docopt(__doc__)

if argumentos['SERVER']:
    servidor = argumentos['SERVER']
#:fi

if argumentos['--port']:
    s_porta = argumentos['--port']
else: 
    s_porta = DEFAULT_PORT_FTP
#:fi

try:
    #s_nome, s_ip = tftp.get_server_info(servidor)
    pass
except:
    print(f"Unknown server: {servidor}")
    exit(2)
#:yrt

#serv_addr = (s_nome, s_porta)
serv_addr = (servidor, s_porta)

sfile= ''
if argumentos['SOURCE_FILE']:
    sfile = argumentos['SOURCE_FILE']
#:fi

if argumentos['DEST_FILE']:
    dfile = argumentos['DEST_FILE']
else: 
    dfile = './'+sfile
#:fi

if argumentos['get']:

    try:
        tftp.get_file(serv_addr, sfile, dfile)
    except:
        ei = sys.exc_info()
        print(f"ERROR: {str(ei[1])}")
    #:yrt

elif argumentos['put']:

    if not isfile(sfile):
        print('ERROR: File\'' + sfile + '\' not found.')
        exit(2)
    #:fi

    try:
        tftp.put_file(serv_addr, sfile, dfile)
    except:
        ei = sys.exc_info()
        print(f"ERROR: {str(ei[1])}")
    #:yrt

else:
    # interacção com o utilizador em modo interactivo:
    #print(f"Exchaging files with server '{s_nome}' ({s_ip})")
    print(f"Exchaging files with server {servidor}")
    while True:
        comando = input("tftp client>").strip().split(' ')

        if comando[0].strip() == 'get': 
 
            if len(comando) == 1 or len(comando) > 3:
                print('Usage: get remotefile [localfile]')
                break

            elif len(comando) >= 2:
                ficheiro_remoto = comando[1].strip()

                if len(comando) == 3:
                    ficheiro_local = comando[2].strip()
                else:
                    ficheiro_local = ficheiro_remoto
                #:fi
            #:fi

            try:
                tamanho = tftp.get_file(serv_addr, ficheiro_remoto, ficheiro_local)
                print(f"Received file '{ficheiro_remoto}' {tamanho} bytes.")
            except:
                ei = sys.exc_info()
                print(f"Server not responding. Exiting.")
                break
            #:yrt

        elif comando[0].strip() == 'put':

            if len(comando) == 1 or len(comando) > 3:
                print('Usage: put localfile [remotefile]')
                break

            elif len(comando) >= 2:
                ficheiro_local = comando[1].strip()

                if not isfile(ficheiro_local):
                    print('File not found.')
                    break
                #:fi

                if len(comando) == 3:
                    ficheiro_remoto = comando[2].strip()
                else:
                    ficheiro_remoto = ficheiro_local
                #:fi
           #:fi

            try:
                tamanho = tftp.put_file(serv_addr, ficheiro_local, ficheiro_remoto)
                print(f"Sent file '{ficheiro_local}' {tamanho} bytes.")
            except:
                ei = sys.exc_info()
                print(f"Server not responding. Exiting.")
                break
            #:yrt

        elif comando[0] == 'quit':

            print("Exiting TFTP client.")
            print("Goodbye!")
            break

        elif comando[0] == 'help':

            print("Commands:")
            print("  get remote_file [local_file]   - get a file from server and save it as local_file")
            print("  put local_file [remote_file]   - send a file to server and store it as remote_file")
            print("  dir                            - obtain a listing of remote files")
            print("  quit                           - exit TFTP client")

            #sys.argv.append('-h')
            #sys.exit(main())

        elif comando[0] == 'dir':

            try:
                #tftp.get_dir(serv_addr)    
                tftp.get_dir_nova(serv_addr)                
            except:
                ei = sys.exc_info()
                print(f"Server not responding. Exiting.")
                break
            #:yrt

        else:
            print(f"Unknown command: '{comando[0]}'.")
            break
        #:fi
    #:elihw
#:fi
