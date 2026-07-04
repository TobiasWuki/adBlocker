#include "adSieve.h"
#include "utils.h"
#include <iostream>
#include <fstream> //fileStream
#include <unordered_set> // Für die Hash-Tabelle
#include <cstdint>
#include <cctype>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif


adSieve::adSieve() {
    
     std::ifstream file(filePath);

    if (file.is_open() == false) {
        std::cout << "Fehler: Blacklist nicht gefunden" << std::endl;
        return;
    }

    std::string currentLine;

    while (std::getline(file, currentLine)) {

		if (currentLine.empty()) {			continue;  } //wenn leer überspringen
		
		size_t otherChars = currentLine.find_first_of("!#");
		
		if (otherChars != std::string::npos) {
		continue;			// wenn kommentar überspringen
        }
	
		
        size_t space = currentLine.find(' '); //size_t = riesiges 64 bit unsigned int
        // Semantik-Schutz: Nur splitten, wenn wirklich ein Leerzeichen da ist!
        if (space != std::string::npos) {
            std::string domain = currentLine.substr(space + 1);		//ip adresse ist immer mit space getrennt, daher wenn space ip adresse davor daher abschneiden

			for (int i = 0; i < domain.length(); i++) {
				if (std::isalnum(domain[i]) { //es können kommentare oder auch syntax dass es eine wildcard ist, davorstehen. daher jedes zeichen weg
					
					domain = currentLine.substr(i-1);
				}
			}	
            hashTable.insert(domain);
        }
			
        else {
            // Keine IP davor? Dann ist die ganze Zeile die Domain!
            hashTable.insert(currentLine);
        }
    }
}





void adSieve::startFilterEngine() {

    int outPort53Socket = 0;
    int outInternetSocket = 0;
    utils::postOffice::initSockets(outPort53Socket, outInternetSocket);

    while (true) {

        /*stack*/
        char queryBuffer[512];
        sockaddr_in ipClient{};
        /*tack ende*/
        int byteCount = utils::postOffice::receiveQuery(queryBuffer, ipClient, outPort53Socket, utils::postOffice::maxSize);

        /*      KEIN BUTTON MONTIERT
        
        if (pause) [[unlikely]] {

            utils::postOffice::forward(queryBuffer, utils::postOffice::UPSTREAM_DNS, byteCount, outInternetSocket);
            byteCount = utils::postOffice::receiveAnswer(queryBuffer, outInternetSocket, utils::postOffice::maxSize);
            utils::postOffice::send(queryBuffer, ipClient, outPort53Socket, byteCount);

            continue;
        }
        */

        if (checkBuffer(queryBuffer)) { //sowieso ein boolean, braucht kein vergleich 

            utils::postOffice::gaslightAppointeeStan(queryBuffer);
            utils::postOffice::send(queryBuffer, ipClient, outPort53Socket, byteCount);

            continue;

        }
        else {
            utils::postOffice::forward(queryBuffer, utils::postOffice::upstreamDNS, byteCount, outInternetSocket);
        }

        byteCount = utils::postOffice::receiveAnswer(queryBuffer, outInternetSocket, utils::postOffice::maxSize);

        utils::postOffice::send(queryBuffer, ipClient, outPort53Socket, byteCount);

    }
}


bool adSieve::checkBuffer(char* queryBuffer) {

    int position = 12;
    std::string domain = "";

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
	return hashTable.find(domain) != hashTable.end();
}
