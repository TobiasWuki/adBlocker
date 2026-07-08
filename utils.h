#pragma once
#include <iostream>
#include <string>
#include <cstdint>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif


namespace utils {

	struct NetworkAddr {
		std::string ip;
		unsigned short port;
	};

	namespace toEndians {
		static uint16_t toLittleEndian(uint16_t networkValue);
		static uint16_t toBigEndian(uint16_t pcValue);
	}

    namespace postOffice {

        // 1. Wir erstellen eine leere Box vom Typ des Betriebssystems
        inline std::string upstreamDNS = "1.1.1.1";
        inline constexpr int maxSize = 512;

        inline int receiveQuery(char* queryBuffer, sockaddr_in& ipClient, int outPort53Socket, int maxSize) {

            socklen_t sizeOf = sizeof(ipClient);
            int bytesReceivedQuery = recvfrom(outPort53Socket, queryBuffer, maxSize, 0, (sockaddr*)&ipClient, &sizeOf);
		    std::cout << "erhalten" << bytesReceivedQuery << std::endl;
            return bytesReceivedQuery;

        }

        inline bool send(char* gaslightMsg, sockaddr_in& ipClient, int outPort53Socket, int byteCount) {

            int bytesSent = sendto(outPort53Socket, gaslightMsg, byteCount, 0, (sockaddr*)&ipClient, sizeof(ipClient));

            bool worked = false;

            //if (byteCount == bytesSent) { worked = true; }

            return worked;

        }

        inline bool forward(char* queryBuffer, std::string UPSTREAM_DNS, int byteCount, int& outInternetSocket) {

            // 2. Erstelle das Adress-Schild für Port 53
            sockaddr_in toCloudFare;
            toCloudFare.sin_family = AF_INET;                           // IPv4 nutzen
            toCloudFare.sin_port = htons(53);                           // Auf allen Kanälen lauschen
            inet_pton(AF_INET, UPSTREAM_DNS.c_str(), &toCloudFare.sin_addr);

            bool workedForward = false;

            int bytesSent = sendto(outInternetSocket, queryBuffer, byteCount, 0, (sockaddr*)&toCloudFare, sizeof(toCloudFare));

            if (byteCount == bytesSent) { workedForward = true; }

            return workedForward;

        }

        inline int receiveAnswer(char* queryBuffer, int& outInternetSocket, int maxSize) {


            sockaddr_in fromDNS;
            socklen_t fromLength = sizeof(fromDNS); // Das Betriebssystem MUSS die Größe des Speichers kennen!

            // Hier passiert die Magie mit Zeigern (&) und Typecasts (sockaddr*)
            int bytesReceivedAnswer = recvfrom(outInternetSocket, queryBuffer, maxSize, 0, (sockaddr*)&fromDNS, &fromLength);

            return bytesReceivedAnswer;
            /*
            sockaddr_in fromDNS;

           int bytesReceivedAnswer = recvfrom(outInternetSocket, queryBuffer, maxSize, fromDNS);

            return bytesReceivedAnswer;
            */
        }

        inline void gaslightAppointeeStan(char* queryBuffer) {

            // Sicherer Cast auf unsigned char für saubere Bit-Arithmetik
            auto* bytes = reinterpret_cast<uint8_t*>(queryBuffer);

            // 1. Aus Query eine Response machen (QR-Bit auf 1 setzen)
            bytes[2] |= 0x84;

            // 2. Alten Fehlercode löschen und NXDOMAIN (3) setzen
            bytes[3] &= 0xF0;
            bytes[3] |= 0x03;

            //Anzahl der Anfragen auf null setzen
            //bytes[6] &= 0x00;
            //bytes[7] &= 0x00;


        }

        inline void initSockets(int& outPort53Socket, int& outInternetSocket) {

            // 1. Erschaffe die Eingangstür (Eingangs-Socket)
            outPort53Socket = socket(AF_INET, SOCK_DGRAM, 0);

            // 2. Erstelle das Adress-Schild für Port 53
            sockaddr_in localAddress;
            localAddress.sin_family = AF_INET;                           // IPv4 nutzen
            localAddress.sin_port = htons(53);                           // Auf allen Kanälen lauschen
            inet_pton(AF_INET, "0.0.0.0", &localAddress.sin_addr);
            // 3. Nagle das Schild an die Eingangstür (Binden)
            bind(outPort53Socket, (sockaddr*)&localAddress, sizeof(localAddress));


            // 4. Erschaffe die Ausgangstür für das Internet (Ausgangs-Socket)
            //    (Kein bind nötig, das OS verwaltet den Port beim Rausgehen selbst)
            outInternetSocket = socket(AF_INET, SOCK_DGRAM, 0);
        }
    
	}

};
