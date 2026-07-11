#include "adSieve.h"
#include "utils.h"
#include <iostream>
#include <fstream> //fileStream
#include <unordered_set> // Für die Hash-Tabelle
#include <unordered_map> //std datenbank basierend auf hash für geschwindigkeit
#include <cstdint>
#include <cctype>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <sys/select.h>
    #include <netinet/in.h>
#endif


adSieve::adSieve() {
    
     std::ifstream file(filePath);

     //ist das File offen?
    if (file.is_open() == false) { 
        std::cout << "Fehler: Blacklist nicht gefunden" << std::endl;
        return;
    }

    std::string currentLine;

    //kürzt die DNS Blocker Einträge auf die gewollte Domain. Also keine Kommentare, keine IP, etc
    while (std::getline(file, currentLine)) {       

		if (currentLine.empty()) {			continue;  } //wenn leer überspringen
		
        // 2. Wo ist der allererste Buchstabe oder die erste Zahl?
        int firstLetterPos = -1;
        for (int i = 0; i < currentLine.length(); i++) {
            if (std::isalnum(currentLine[i])) {
                firstLetterPos = i;
                break;
            }
        }

        // 3. Wo ist das erste Kommentarzeichen?
        size_t commentPos = currentLine.find_first_of("!#");

        // Wenn ein Kommentarzeichen existiert UND es steht VOR dem ersten Buchstaben:
        if (commentPos != std::string::npos && (firstLetterPos == -1 || commentPos < firstLetterPos)) {
            continue; // Das ist ein echter Kommentar -> Zeile komplett überspringen!
        }
        
        size_t space = currentLine.find_first_of(" \t"); //size_t = riesiges 64 bit unsigned int

        std::string domain = currentLine;

        if (space != std::string::npos) {
            domain = currentLine.substr(space + 1);		//ip adresse ist immer mit space getrennt, daher wenn space ip adresse davor daher abschneiden

        }
        //for (int i = 1; i <= domain.length(); i++) {
        //    if (std::isalnum(domain[i-1])) { //es können kommentare oder auch syntax dass es eine wildcard ist, davorstehen. daher jedes zeichen weg
        //        domain = domain.substr(i - 1);
        //        break;
        //    }
        //}
        while (!domain.empty() && !std::isalnum(domain.front())) {
            domain.erase(0, 1); // Löscht das allererste Zeichen (Index 0, Länge 1)
        }

        //int domainLength = domain.length();
        //for (int i = 1; i <= domainLength; i++) {
        //    domainLength = domain.length();
        //    if (std::isalnum(domain[domainLength - i])) { //es können kommentare oder auch syntax dass es eine wildcard ist, davorstehen. daher jedes zeichen weg
        //        domain = domain.substr(0, domainLength - i + 1);
        //        break;
        //    }
        //}
        while (!domain.empty() && !std::isalnum(domain.back())) {
            domain.pop_back();
        }
        hashTable.insert(domain);
        
    }
}





void adSieve::startFilterEngine() {

    //dass überhaupt lauft
    int port53Socket = 0;       //socket nummer vom 53 port für kommunikation mit geräten
    int internetSocket = 0;     //socket nummer für komm mit dns
    sockaddr_in ipClient{}; //selbsterklärend, braucht man zum zurücksenden
    utils::postOffice::initSockets(port53Socket, internetSocket);       //initialisiert sockets

    //für multi personen use, statt threading
    int max_fd = (port53Socket > internetSocket) ? port53Socket : internetSocket;       // fäncy if abfrage, damit der compiler weiß, ab wann er aufhören kann nach sockets zu checken
    fd_set readFds;     //fd_set ist eine verdammt lange bit reihe 1024 glb ich.

    std::unordered_map<uint16_t, sockaddr_in> openQueries;    // Syntax: std::unordered_map<Key_Typ, Value_Typ> name; DB für offene anfragen


    //start der logikschleife. hier befindet sich der pi während dem betrieb
    while (true) {
        
        char queryBuffer[512];  //hier wird die anfrage reingeschrieben. query = anfrage, buffer = puffer (weil man nicht weiß wie lange, daher max länge 512)
        int byteCount = 0; //wie lang die anfrage ist, brauch man zum versenden, wird auch von cpp standardmäsiß in der synax verlangt
 


        FD_ZERO(&readFds);      //setzt alle bits wieder auf 0
        FD_SET(port53Socket, &readFds);     //setzt den port53Socket'en (int) bit auf 1
        FD_SET(internetSocket, &readFds);       //setzt den internetSocket'en (int) bit auf 1

        select(max_fd + 1, &readFds, NULL, NULL, NULL);     //wo was angekommen ist, der andre socket wird auf 0 gesetzt

        if (FD_ISSET(port53Socket, &readFds)) {     //ob der der auf 1 ist, wenn nicht ist beim andren was gekommen

            byteCount = utils::postOffice::receiveQuery(queryBuffer, ipClient, port53Socket, utils::postOffice::maxSize);
            if (checkBuffer(queryBuffer)) { //sowieso ein boolean, braucht kein vergleich 
                utils::postOffice::gaslightAppointeeStan(queryBuffer);
                utils::postOffice::send(queryBuffer, ipClient, port53Socket, byteCount);
                continue;

            }
            else {

                uint16_t queryID = static_cast<uint8_t>(queryBuffer[0]) << 8;
                queryID |= static_cast<uint8_t>(queryBuffer[1]);
                openQueries[queryID] = ipClient;
                utils::postOffice::forward(queryBuffer, utils::postOffice::upstreamDNS, byteCount, internetSocket);
            }

        }
        else {

            byteCount = utils::postOffice::receiveAnswer(queryBuffer, internetSocket, utils::postOffice::maxSize);

            uint16_t queryID = static_cast<uint8_t>(queryBuffer[0]) << 8;
            queryID |= static_cast<uint8_t>(queryBuffer[1]);

            auto eintrag = openQueries.find(queryID);
            
            if (eintrag != openQueries.end()) {
                ipClient = eintrag -> second;

                utils::postOffice::send(queryBuffer, ipClient, port53Socket, byteCount);
                openQueries.erase(eintrag);
            }


        }


        /*      KEIN BUTTON MONTIERT
        
        if (pause) [[unlikely]] {

            utils::postOffice::forward(queryBuffer, utils::postOffice::UPSTREAM_DNS, byteCount, outInternetSocket);
            byteCount = utils::postOffice::receiveAnswer(queryBuffer, outInternetSocket, utils::postOffice::maxSize);
            utils::postOffice::send(queryBuffer, ipClient, outPort53Socket, byteCount);

            continue;
        }
        */
    }
}


bool adSieve::checkBuffer(char* queryBuffer) {

    int position = 12;
    std::string domain = "";

    //kürzt queryBuffer um den Header etc und macht einen richtigen Domain string für den blocklist vergleich
    while (queryBuffer[position] != 0) {        



        int blockLength = queryBuffer[position];

        for (int i = 0; i < blockLength; i++) {
            position++;
            domain += queryBuffer[position];

        }

        position++;

        if (queryBuffer[position] != 0) {
            domain += '.';
        }
    }

    size_t posDot = 0;

    //vergleicht die Blocklist und die angefragte Domain, schneidet auch subDomains weg
    if (!(hashTable.find(domain) != hashTable.end())) {     //vergleicht die Blocklist und die angefragte Domain, schneidet auch subDomains weg

        while (true) {

            posDot = domain.find('.');

            if (posDot == std::string::npos) {
                return false;
                
            }

            domain = domain.substr(posDot + 1);

            if (hashTable.find(domain) != hashTable.end()) {
                return true;
                
            }
        }
    }

    else { return true; }
}
