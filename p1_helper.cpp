#include "p1_helper.h"
#include <fstream>
#include <sstream>

std::vector<Game> loadGamesFromFile(const std::string& filename) {
    std::vector<Game> games;
    std::ifstream file(filename);
    std::string line;

    // Skip header line
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string id_str, title, platform, genre, year_str, esrb, availability_str, copies_str;

        std::getline(ss, id_str, ';');
        std::getline(ss, title, ';');
        std::getline(ss, platform, ';');
        std::getline(ss, genre, ';');
        std::getline(ss, year_str, ';');
        std::getline(ss, esrb, ';');
        std::getline(ss, availability_str, ';');
        std::getline(ss, copies_str, ';');

        Game game;
        game.id = std::stoi(id_str);
        game.title = title;
        game.platform = platform;
        game.genre = genre;
        game.year = std::stoi(year_str);
        game.esrb = esrb;
        game.available = (availability_str == "True");
        game.copies = std::stoi(copies_str);

        games.push_back(game);
    }
    return games;
}
