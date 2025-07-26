#ifndef P1_HELPER_H
#define P1_HELPER_H

#include <vector>
#include <string>

struct Game {
    int id;
    std::string title;
    std::string platform;
    std::string genre;
    int year;
    std::string esrb;
    bool available;
    int copies;
};

std::vector<Game> loadGamesFromFile(const std::string& filename);

#endif // P1_HELPER_H
