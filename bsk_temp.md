
###### Jeden z parametrów połączenia HTTPS ma wartość TLS_ECDHE_ECDSA_WITH_AES256_GCM_SHA384. Oznacza to, że:

SUPER

**a)do szyfrowania szyfrowania wykorzystywany jest algorytm Diffie-Hellman**
b)do podpisywania wiadomości wykorzystuje się algorytm AES256
**c)do wygenerowania MAC wykorzystywana jest funkcja SHA384**
***d)do szyfrowania wiadomości wykorzystuje się algorytm DSA***
e)wymienione przez obie strony kucze należą do cryptosystemu RSA

ChatGPT: 

a) błędne - algorytm szyfrowania to ECDHE (Elliptic Curve Diffie-Hellman), a nie Diffie-Hellman
b) błędne - algorytm szyfrowania to AES256, a nie podpisywania
c) poprawne - funkcja SHA384 jest używana do wygenerowania MAC
d) błędne - algorytm podpisywania to ECDSA (Elliptic Curve Digital Signature Algorithm), a nie DSA
e) błędne - algorytmy ECDHE i ECDSA nie należą do cryptosystemu RSA


Odpowiedź: a) do szyfrowania wykorzystywany jest algorytm ECDHE (Elliptic Curve Diffie-Hellman Ephemeral), b) do podpisywania wiadomości wykorzystuje się algorytm ECDSA (Elliptic Curve Digital Signature Algorithm), c) do wygenerowania MAC (Message Authentication Code) wykorzystywana jest funkcja SHA384, d) do szyfrowania wiadomości wykorzystuje się algorytm AES256.


TLS_ECDHE_ECDSA_WITH_AES256_GCM_SHA384 oznacza, że połączenie jest zabezpieczone protokołem TLS, który korzysta z algorytmu ECDHE (Elliptic Curve Diffie-Hellman) do wymiany kluczy i algorytmu ECDSA (Elliptic Curve Digital Signature Algorithm) do podpisywania wiadomości. Wiadomości są szyfrowane przy użyciu AES256 i wygenerowano dla nich MAC (Message Authentication Code) za pomocą funkcji SHA384.


###### Droga do udanego ataku typu SQLInjection moze byc wprowadzona w panelu logowania, w polu „Nazwa uzytkownika" fraza:

a)alan" - a
**b)alan - and select password from passwords**
c)"alan-a
d)alan union select password for user alan
e)alan and sleep(3)

ChatGPT

b) "alan' OR 1=1--" - jest to przykład jednej z najprostszych form frazy, która może być wprowadzona w polu "Nazwa użytkownika" w celu wykonania ataku typu SQL Injection.


###### OpenSSL to: 
a) otwarty protokót komunikacyjny Secure Socket Layer
**b) zestaw narzedzi dla protokotów TLS i SSL**
c) standard kryptograficzny dla protokotu HTTPS i S-HTTP
***d) biblioteka kryptograficzna ogólnego przezanczenia***
e) Memorandum dotyczace podstaw bezpieczenstwa komunikacyinego


ChatGPT

b) zestaw narzędzi dla protokołów TLS i SSL - OpenSSL jest popularnym i wielokrotnie używanym zestawem narzędzi i bibliotek, które umożliwiają implementację i wdrożenie protokołów TLS i SSL do szyfrowania połączeń sieciowych.

###### Która z grup kodów odpowiedzi HTTP oznacza, ze cos poszto nie tak po stronie serwera?
SUPER

a) 200
b) 300
c) 400
**d) 500**

ChatGPT

d) 500 - Kod odpowiedzi HTTP 500 oznacza błąd serwera, co oznacza, że coś poszło nie tak na stronie serwera i nie jest w stanie przetworzyć żądania użytkownika. Inne kody odpowiedzi to: 200 - OK, 300 - przekierowanie, 400 - błąd klienta.

###### Ponizej przedstawiono fragment podrecznika systemowego da polecenia opessl.Szyfrowanie pliku data.txt algorytmem aes w trybie wiazania zaszyfrowanych bloków, z blokami o rozmiarze 256 bitów z hastem "as34Dw9P2lsH" przedstawia polecenie:

openssl enc -ciphername [-AadePp] [-base64] [-bufsize number] [-debug]
[-in file] [-iv IV] [-K key] [-k password] [-kfile file]
[-md digest] [-none] [-nopad] [-nosalt] [-out file] [-pass arg]
[-S salt] [-salt]

SUPER

**a) openssl enc-e-aes-256-cbc-in data.txt -out data.enc -k as34Dw9P2lsH**
b) openssl enc -e-aes-256-ebc -in data.txt -out data.enc -k as34Dw9P2lsH
c) openssl enc-d-aes-256-cbc-in data.txt -out data.enc -K as34Dw9P2lsH
d) openssl enc -aes-256-cbc-in data.txt -out data.enc -K as34Dw9P2lsH

ChatGPT

a) openssl enc -e -aes-256-cbc -in data.txt -out data.enc -k as34Dw9P2lsH

-e (or -encrypt): indicates that the input file will be encrypted
-aes-256-cbc: specifies the AES algorithm with a block size of 256 bits and CBC mode
-in data.txt: specifies the input file to be encrypted
-out data.enc: specifies the output file for the encrypted data
-K as34Dw9P2IsH: provides the key to be used for encryption.

This command would encrypt the file "data.txt" using the AES algorithm with a block size of 256 bits in CBC mode, with a key of "as34Dw9P2IsH".


###### Na podstawie ponizszego obrazka mozna powiedzieé, ze szczegótowe informacje o procesie xfce4-session mozna znalezc w katalogu:
SUPER

a) /dev/proc/828
**b) /proc/828/**
c) /proc/xfce4-session
d) /opt/828/xfce4-session
e) /var/log/xfce4-session
f) /var/log/828

ChatGPT

Na podstawie ponizszego obrazka można powiedzieć, że szczegółowe informacje o procesie xfce4-session można znaleźć w katalogu:

b) /proc/828/


###### Logi systemowe w systemach Linux przechowywane sa w najczesciei w folderze: 

SUPER

a) /tmp/log
b) /logs/
**c) /var/log**
d) /usr/cache/logs
e) /opt/usr/local/logs

ChatGPT

c) /var/log

###### Wykonanie polecenia "echo 'pasword' | shasum -a 256" spowoduie wygenerowanie ciagu:

SUPER

a) 398f71dGdfecdadbfafaSf638d87e4Qa6e604e1f8697C4e2bafBbcf772daff
**b) 398f71d9dfecdadbfafa5f638d87e40a6e604e1f8697c4e2baf8bcf772daff8b**
c) 398f71d9dfe7e25a17a322dcc80d77a23d40ebd20ec
d) 0000000 39 8f 71 d9 6f 72 64 0a 3a 23 45 a1 ec 20

ChatGPT

b) 398f71d9dfecdadbfafa5f638d87e40a6e604e1f8697c4e2baf8bcf772daff8b

###### Podatnosc SQL Injection moze pozwalac na: 

**a) nieautoryzowanym dostepem w trybie odczytu lub zapisu do catej bazy danych**
**b) ominiecie mechanizmu uwierzytelnienia**
c) mozliwoscia wykonania kodu w systemie operacyjnym
d) mozliwoscia odczytania wybranych plików.

ChatGPT



###### Wykorzystanie algorytmu PBKDF2 podczas szyfrowania pozwala na:

SUPER

a) zmniejszenie rozmiaru pliku po zaszyfrowaniu
b) wykorzystanie silniejszego algorytmu szyfrującego
***c) zabezpieczenie przed atakiem mającym na celu złamanie algorytmu szyfrującego***
***d) zwiększeniu kosztów obliczeniowych w celu redukcji podatności na atak typu "brut force"***
e) redukcje kosztów obliczeniowych związanych z wyodrębnienim klucza szyfrującego z hasła

ChatGPT

d) zwiększeniu kosztów obliczeniowych w celu redukcji podatności na atak typu "brut force"
c) zabezpieczenie przed atakiem mającym na celu złamanie algorytmu szyfrującego


###### W kryptografii asymetrycznej: 

SUPER

a) wysylane wiadomosci szyfruie sie kluczami publicznymi nadawcy
b) wysylane wiadomosci szyfruje sie kluczami prywatnymi nadawcy
**c) wysylane wiadomosci szyfruje sie kluczami publicznymi odbiorcy**
d) wysylane wiadomosci szyfruje sie kluczami prywatnymi odbiorcy

ChatGPT

W kryptografii asymetrycznej wysyłane wiadomości szyfruje się kluczami publicznymi odbiorcy.

###### Którego adresu IP uzyjesz, zeby nasluchiwac na polaczenia z dowolnego adresu? *

SUPER

a) 1.1.1.1
**b) 0.0.0.0**
c) 127.0.0.1
d) 192.168.0.0

ChatGPT

b) 0.0.0.0

###### Ponizszy ciag znaków moze zostac wykorzystany w ataku o nazwie: *
\<img src="http://url.to.file.which/not.exist" onerror=alert(document.cookie);\>

SUPER

**a) Cross Site Scripting**
b) SQL Injection
c) Reflected JavaScript Attack
d) Improper HTML Data Validation

ChatGPT

a) Cross Site Scripting (XSS)

###### Aby zaszyfrowac plik data.txt, o rozmiarze 4 kB wykorzystujac klucz publiczny o rozmiarze 4 kb (zapisany w pliku pub.pem) nalezy:

SUPER

a) wykonad polecenie: openssl rsautl-encrypt-inkey pub.pem -pubin-in data:txt-out
b) wykonac polecenie: openssl rsautl-encrypt -inkey priv.pem -in data.txt -out
data.enc
**c) wygenerowac losowy klucz, zaszyfrowac podany plik za pomoca algorytmu
symetrycznego z wykorzystaniem wygenerowanego klucza, zaszyfrowac kluczem
publicznym klucz symetryczny, ewentualnie przeslac odbiorcy zaszyfrowany plik
wraz z zaszyfrowanym kluczem**
d) podpisac wskazany plik za pomoca klucza publicznego , zaszyfrowac podpisany
plik za pomoca algorytmu symetrycznego z wykorzystaniem klucza prywatnego
e) zaimportowac klucz do systemu gpg i wykonac polecenie: gpg --encrypt --key
pub.pem-in data.txt

ChatGPT

c) wygenerowac losowy klucz, zaszyfrowac podany plik za pomoca algorytmu symetrycznego z wykorzystaniem wygenerowanego klucza, zaszyfrowac kluczem publicznym klucz symetryczny, ewentualnie przeslac odbiorcy zaszyfrowany plik wraz z zaszyfrowanym kluczem


###### BASE64 to:

SUPER

a) struktura system plików
b) popularny format kodowania kluczy w kryptografii asymetrycznej
c) protokót warstwy transportowej modelu ISO
**d) rodzaj kodowania transportowego**
e) model architektury systemów 64 bitowych

ChatGPT

d) rodzaj kodowania transportowego

###### Odbiorca (B) w celu weryfikacji podpisanej prze nadawce (A) wiadomosci:

SUPER

a) wykorzysta klucz prywatny A
b) wykorzysta klucz prywatny B
**c) wykorzysta klucz publiczny A**
d) wykorzysta klucz publiczny B


ChatGPT

c) wykorzysta klucz publiczny A



###### Ciąg znaków "aasb763jjab został zapisany do pliku file.txt za pomocą polecenia"echo "aasb763jjab" > file.txt". Aby wygenerować skrót sha-256 dla ciągu "aasb763jjab" należy wykonać polecenie:

SUPER

a) echo "aasb763jjab" | sha256sum
b) cat file.txt | sha256sum
**c) echo-n "aasb763jjab" | sha256sum**
d) sha256sum file.txt
e) sha256sum <file.txt

ChatGPT


###### W kryptosystemie RSA:

SUPER

a) odbierane wiadomości deszyfruje się kluczami publicznymi nadawcy
b) odbierane wiadomości deszyfruje się kluczami publicznymi odbiorcy
**c) odbierane wiadomości deszyfruje się kluczami prywatnymi odbiorcy**
d) odbierane wiadomości deszyfruje się kluczami prywatnymi nadawcy

ChatGPT


###### W systemach Unix/Linux w celu zwiększenia bezpieczeństwa: 

SUPER

a) hasła użytkowników są wstępnie szyfrowane i zapisywane na dysku
**b) na dysku zapisywane są jedynie funkcje skrótu hasel**
c) hasta są zapisywane w jawnej postaci w pliku /etc/shadow
d) hasła są zapisywane w katalogu domowym użytkownika root
e) hasła użytkowników nie są nigdzie zapisywane

ChatGPT


###### W przedstawionej na poniższym rysunku sytuacji mamy do czynienia z: 

(kali-kali)-[/bin]
php8.1 /root/.bashrc
\#/.bashrc: executed by bash(1) for non-login shells.
\#see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
\# for examples
\# If not running interactively, don't do anything
case $- in
esac
return;;

Możliwe jest wybranie jednej lub kilku odpowiedzi

**a) eskalacją uprawnień użytkownika**
b) wykorzystaniem polecenia "sudo"
c) błędami w nadawaniu uprawnień programom
d) nieudaną próbą dostępu do plików w katalogu domowym użytkownika root
e) zmianą praw dostępu do pliku.bashrc

ChatGPT


###### Poniższy obrazek przedstawia fragment certyfikatu X509. Na jego podstawie


SUPER  
można powiedzieć, że:
(kali@kali)-[-/Downloads
openssl x509 -in mw-debian-org(1).pem -text
pat version: 3 (0-2)
Serial Number:
Certificate:
91:2b:08:4a:cf:0c:18:a7:53:f6:d6::2e:25:a7:5f:5a
Signature Algorithm: sha256WithRSAEncryption
Issuer: C = US, 0 = Internet Security Research Group, CN = ISRG Root X1
Validne Before: Sep 4 00:00:00 2020 GMT
Not After : Sep 15 16:00:00 2025 GMT
Subject: C = US, 0 = Let's Encrypt, CN = R3s
Subject Public Key Info:
Public Key Algorithm: rsaEncryption
Public-Key: (2048 bit)
Modulus:
00:bb:02:15:28:cc:f6:a8:94:d3:0f:12:c:8d:55:
92:c3:f8:82:f1:99:a6:7a:42:88:a7:5d:26:aa:b5:
2b:b9:c5:4c:b1:af:8e:6b:f9:75:c8:a3:d7:0f:47:

a) wystawcą certyfikatu jest "Let's Encrypt"
**b) wystawcą certyfikatu jest "Internet Security Research Group"**
c) wystawca certyfikatu jest " debian.org "
**d) klucz publiczny"Let's Encrypt" ma rozmiar 2048 bitów**
e) Klucz publiczny "internet Security Research Group" ma rozmiar 2048 bitów

ChatGPT

###### Poniżej przedstawiono: 
----------BEGIN PUBLIC KEY-------------
MIICIjANBgkqhkiG9w0BAQEFAAOCAgBAMIICCgKCAgEAzxXct0CjIrUoaUzrlk+9
Sqh4yFJHSqNTxtPbQuAhdcoP4sUEVelZaEzfFoHn3YajKVm03ps3gdSy3sqEM0mv
kw3Yal8Ul2nzfNGpnFw0gDYIrLqgFxnGGKNIufzUQBbit6DIDuCXF941Mok9FVah
2GrjfDe64NclalgwTnrxmtHkRqz1MfYxU+1wqYTchjk6GN9fgD188d+V5HZBE4bU
waGGr3fPeBTGCPRyRcksMarcjRG5QZ1j2rSM+HbaZyQKai3HQ3Zqptss9pm0TGCP
KwFzdNJW8Ym7e8aWGNOud6UwZcZiNGvP/M8Q+aw50jcki7a5jQ50HdeGEv3rsKPy
ApkiLSCAQ13Zwg0okRHOjMerFUPA1cBx0GsCTPbNOVhlJLcG/+nValaZfEqV6uQ5
RD0087p8UUFKped1F4tGz3S0U2oAyDQUcLBNojW5w+XeieHdnoGHYvzC6luIybly
90tLBrDerGdzw/s7QsoPkmt4mPBHHuWTwdGMWXl+9p91ulLgbgL8kztBWsLlgKG9
q3ADkmHxxFEwxvcXQMLXNfyU53g0qAQw3zEAfyTa+NRm9WaXIcW8p41T+BvwsffQ
ExvpzNf0d9dQYLRNZzB9ZMdSdgPlk1ljNV2viBUyDTQmy0d3aHHQMZZQMEVc9fnL
hRH7KvvCulkL8hPuoYOCWAMCAwEAAQ
-------------END PUBLIC KEY-------------


SUPER

**a) klucz publiczny w formacie pem**
b) klucz publiczny w formacie binarnym
c) jeden z pary kluczy zapisany z wykorzystaniem kodowania base64
d) klucz publiczny w postaci heksadecymalnej
e) klucz prywatny w formacie base64


ChatGPT



###### Na podstawie analizy zawartości katalogu fd dla pewnego procesu możemy stwierdzić, Że 

lr-x---- 1 kali kali 64 Jan 6 16:37 0 -> /dev/null
l-wx---- 1 kali kali 64 Jan 1 16:37 1 -> /home/kali/.xsession-errors
l-wx---- 1 kali kali 64 Jan 2 16:37 2 -> /home/kali/.xsession-errors
lrwx---- 1 kali kali 64 Jan 1 16:37 10 -> 'socket:[20450]'
lrwx---- 1 kali kali 64 Jan 2 16:37 3 -> 'socket:[13283]'
lrwx---- 1 kali kali 64 Jan 1 16:37 5 -> 'socket:[13285]'
lrwx---- 1 kali kali 64 Jan 2 16:37 8 -> 'socket:[22601]'


**a) Informacje diagnostyczne zapisywane sa w Odm xsession-ertots**
b) nie ma możliwości przekazana do procesu nic ze standardowego wejścia 
c) proces zapisuje informacje o biedach do pliku sockel 13283 
**d) proces do kumunikacp uzywa plików /dev/null**



ChatGPT



######


ChatGPT
