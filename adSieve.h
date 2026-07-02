#pragma once
#include <unordered_set>
#include <string>

class adSieve {

	private:
		std::unordered_set<std::string> hashTable;

		// Du brauchst hier vermutlich auch deinen filePath für den Konstruktor:
		std::string filePath = "blacklist.txt"; // Oder wie deine Datei heißt

	public:

		adSieve();
		void startFilterEngine();
		bool checkBuffer(char* queryBuffer);

};