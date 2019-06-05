część C - opis

Skrócony opis:

Węzęł chcąc dodać pliki (od klienta lub lokalne przy uruchamianiu serwera) zaczyna ubiegać się o wejście do
sekcji krytycznej. Gdy tę zgodę otrzyma, wysyła zapytanie do pozostałych serwerów o listę ich plików
(tych dostępnych oraz obecnie przesyłanych). Po otrzymaniu listy ich plików serwer pozwala na dodanie tylko te pliki,
które nie występują na przesłanych listach. Po zdecydowaniu, które pliki mogą zostać dodane serwer oddaje sekcję
krytyczną. Ponieważ zawsze tylko jeden serwer na raz jest w sekcji krytycznej, to korzystając z pełnej listy plików
pozostałych serwerów jest w stanie stwierdzić, czy dodanie pliku jest dozwolone.


Pełny opis:

W rozwiązaniu użyję algorytmu Ricarta-Agrawali z algorytmem Lamporta synchronizacji zegarów logicznych. Serwer do
realizacji tego algorytmu będzie potrzebował przetrzymywać:
- zbiór serwerów aktualnie w grupie (in_group)
- zbiór serwerów od których otrzymał pozwolenie na wejście do sekcji krytycznej (permissions)
- lista plików otrzymana od pozostałych serwerów (file_list)
- zbiór serwerów od których otrzymał już pełną listę plików (have_list)
- kolejkę przetrzymującą serwery, które wysłały do serwera zapytanie o wejście do sekcji krytycznej i serwer
   im jeszcze nie odpowiedział (deferred)
- zegar logiczny (timer)
- unikatowy identyfikator serwera (server_id)
W nawiasach podałem skrótowe nazwy, które będę używał w dalszej części.


Protokół opisany w zadaniu rozszerzę o następujące komunikaty:
IM_NEW (SIMPLE) - serwer wysyła ten komunikat do wszystkich serwerów z grupy na początku swojego działania,
   aby poinformować je, że się właśnie podłączył

HI_NEW (SIMPLE) - odpowiedź serwerów na komunikat IM_NEW wysyłany na adres jednostkowy maszyny, która wysłała komunikat

CAN_I? (COMPLEX) - serwer wysyła ten komunikat do wszystkich serwerów z grupy, aby uzyskać zgodę na wejście do
   sekcji krytycznej (w cmd_seq przekazana jest aktualna wartość zegara logicznego serwera, w param id serwera)

OK (SIMPLE) - odpowiedź serwerów na komunikat CAN_I? wysyłany na adres jednostkowy maszyny, która wysłała komunikat

YOUR_LIST (SIMPLE) - serwer wysyła ten komunikat do wszystkich serwerów z grupy, aby dostać pełną listę ich plików

MY_LIST (COMPLEX) - odpowiedź serwerów na komunikat YOUR_LIST wysyłany na adres jednostkowy maszyny, która wysłała
   komunikat (ponieważ lista plików może przekraczać maksymalną długość pakietu, to w param podana jest
   wartość 1 lub 0, gdzie 0 oznacza, że wszytkie pliki zostały już wysłane, a 1 oznacza, że pojawi się jeszcze
   przynajmniej jeden komunikat z pozostałą listą plików)

IM_OUT - serwer wysyła ten komunikat do wszystkich serwerów z grupy, aby poinformować je, że chce się odłączyć


Opis wchodzenia do sekcji krytycznej i otrzymania listy wszystkich plików w grupie:
1. Serwer wysyła zapytanie CAN_I? z zamiarem wejścia do sekcji krytycznej. Po otrzymaniu komunikatu OK serwer dodaje
   adres nadawcy do permissions sprawdzając, czy uzyskał już wszystkie zgody.
2. Po otrzymaniu wszystkich zgód serwer zostaje wpuszczony do sekcji krytycznej.
3. Serwer wysyła zapytanie YOUR_LIST do pozostałych serwerów i czeka na odpowiedzi, zapisując listy plików w file_list.
4. Gdy serwer otrzyma odpowiedzi od wszystkich serwerów to file_list będzie zawierać listę wszystkich plików w grupie.

Pojawiania się nowego serwera w grupie (faza wstępna):
1. Serwer podłączając się do grupy wysyła zapytanie IM_NEW i czeka TIMEOUT czasu na odpowiedzi HI_NEW od serwerów z
   grupy. Zapisuje przy tym adresy serwerów w in_group.
2. Po upływie czasu, serwer uzyskuje dostęp do sekcji krytycznej i dostaje listę aktualnych plików (w sposób
   podany powyżej).
3. Na podstawie file_list decyduje, które z lokalnych plików są unikalne, a które nie, zostawiając jedynie te unikalne.
4. Serwer oddaje sekcję krytyczną wysyłająć do serwerów z deferred pozwolenie na wejście do sekcji krytycznej.


Działanie serwera po fazie wstępnej:
1. Serwer reaguje na komunikaty w sposób podany poniżej.

Schemat działania serwera przy obsłudze zapytania CAN_I?:
1. Serwer A odsyła komunikat OK do serwera B jeśli zachodzi przynajmniej jedno z poniższych
   a) serwer A nie jest zainteresowany wejściem do sekcji krytycznej
   b) serwer A ma mniejszy timer niż serwer B lub w przypadku równości serwer A ma mniejszy server_id od serwera B
2. W przeciwnym przypadku umieszczamy adres serwera B do kolejki deferred
3. Poprawiamy zegar logiczny serwera A ustawiając go na max(A.timer, B.timer) + 1

Schemat działania serwera przy obsłudze zapytania ADD:
1. Serwer uzyskuje dostęp do sekcji krytycznej i dostaje listę aktualnych plików (w sposób podany powyżej).
2. Decyduje czy podany plik jest unikatowy na podstawie file_list.
3. Oddaje sekcję krytyczną wysyłając serwerom z deferred pozwolenia.
4. Zaczyna dodawać plik, jeśli był unikatowy, w przeciwnym przypadku odrzuca plik.

Schemat działania serwera przy obsłudze zapytania IM_NEW:
1. Serwer dodaje do in_group nadawcę.
2. Serwer odpowiada nadawcy komunikatem HI_NEW.
3. Jeśli serwer ubiega się o sekcję krytyczą, to wysyła do nadawcy zapytanie CAN_I?
4. Jeśli serwer zbiera listy plików od serwerów to wysyła do nadawcy zapytanie YOUR_LIST

Schemat działania serwera przy obsłudze zapytania IM_OUT:
1. Serwer usuwa nadawcę z in_group (i ewentualnie z permissions i have_list)
2. Serwer usuwa listy plików odłączającego się serwera.
3. Serwer sprawdza, czy odłączenie się serwera nie powoduje dostępu do sekcji krytycznej albo zebranie pełnej
   listy plików od serwerów.

Schemat działania serwera przy obsłudze zapytania MY_LIST:
1. Serwer dodaje otrzymaną listę plików do file_list. Jeśli param = 0 to oznacza, że była to ostatnia wiadomość z
   listą plików od danego serwera, więc jego adres jest dodawany do have_list.
2. Jeśli serwer otrzymał pełną listę plików od wszystkich serwerów to może przejść do dodawania pliku.

Schemat działania serwera przy obsłudze zapytania YOUR_LIST:
1. Serwer wysyła listę dodanych i dodawanych plików w pakietach MY_LIST w formacie opisanym w opisie protokołu.
